"""
Hai đích đến (sinks) của luồng CDC Streaming:
1. PostgreSQL (Data Warehouse): Upsert (INSERT ON CONFLICT DO NOTHING) dựa trên log_id.
2. S3 (MinIO): Ghi Parquet batch theo offset.
"""
import os
import io
import s3fs
import pandas as pd
from psycopg2.extras import execute_values
from src.etl.load import build_dim_time, build_dim_ip, build_dim_port, build_dim_protocol, build_dim_label, FACT_COLS
from src.etl.transform import make_time_key


def _insert_batch_log(cur, batch_meta, rows_loaded):
    cur.execute(
        """INSERT INTO etl_batch_log
           (consumer_group, topic, kafka_partition, start_offset, end_offset,
            rows_in, rows_loaded, rows_rejected, latency_p50_ms, latency_p95_ms)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
        (
            batch_meta["consumer_group"],
            batch_meta["topic"],
            batch_meta["partition"],
            batch_meta["offset_start"],
            batch_meta["offset_end"],
            batch_meta["rows_in"],
            rows_loaded,
            batch_meta["rows_in"] - rows_loaded,
            batch_meta["latency_p50_ms"],
            batch_meta["latency_p95_ms"],
        ),
    )


class PostgresSink:
    def __init__(self, pg_conn, blacklists, logger):
        self.conn = pg_conn
        self.blacklists = blacklists
        self.logger = logger
        self.dim_cache = {
            "time_key": set(),
            "ip_address": set(),
            "port_number": set(),
            "protocol_number": set(),
            "label_raw": set()
        }
        with self.conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS network_alerts (
                    alert_id SERIAL PRIMARY KEY,
                    source_log_id VARCHAR(255) UNIQUE,
                    flow_start_ts TIMESTAMP,
                    src_ip VARCHAR(50),
                    dst_ip VARCHAR(50),
                    dst_port INT,
                    attack_type VARCHAR(50),
                    alert_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
        self.conn.commit()

    def _sync_dimension(self, table, col_name, df_dim, insert_cols):
        """Đẩy lên PostgreSQL nếu giá trị (col_name) chưa có trong DB (upsert)."""
        new_values = [row for _, row in df_dim.iterrows() if row[col_name] not in self.dim_cache[col_name]]
        if not new_values:
            return
        
        df_new = pd.DataFrame(new_values)
        with self.conn.cursor() as cur:
            # Tạo chuỗi ON CONFLICT phù hợp (Postgres hỗ trợ DO NOTHING)
            conflict_col = col_name if table != "dim_time" else "time_key"
            cols = ",".join(insert_cols)
            val_template = ",".join(["%s"] * len(insert_cols))
            
            sql = f"""
                INSERT INTO {table} ({cols}) 
                VALUES %s 
                ON CONFLICT ({conflict_col}) DO NOTHING
            """
            
            # Cần bỏ các key không dùng trong DB tự tăng (như ip_key, port_key, v.v...)
            # Tuy nhiên để tối ưu chúng ta dùng thủ thuật UPDATE khóa thay thế hoặc fetch lại từ DB sau.
            # Ở bản này, ta sẽ bỏ qua _key nếu DB tự tăng (SERIAL)
            filtered_cols = [
                c for c in insert_cols
                if not c.endswith("_key") or table in ("dim_time", "dim_protocol")
            ]
            filtered_sql = f"""
                INSERT INTO {table} ({",".join(filtered_cols)}) 
                VALUES %s 
                ON CONFLICT ({conflict_col}) DO NOTHING
            """
            
            rows = df_new[filtered_cols].values.tolist()
            execute_values(cur, filtered_sql, rows)
            
            for v in df_new[col_name]:
                self.dim_cache[col_name].add(v)
        self.conn.commit()

    def write_batch(self, df_clean, batch_meta):
        """Ghi batch sạch vào PostgreSQL (Idempotent)."""
        if df_clean.empty:
            return 0
            
        tcfg = {"business_start": 8, "business_end": 17} # Hardcode nhẹ cho streaming config
        
        # 1. Dựng Dimension cho lô hiện tại
        dim_time = build_dim_time(df_clean["flow_start_ts"], tcfg)
        dim_ip = build_dim_ip(set(df_clean["src_ip"]) | set(df_clean["dst_ip"]), self.blacklists)
        dim_port = build_dim_port(set(df_clean["dst_port"]))
        dim_protocol = build_dim_protocol(set(df_clean["protocol_number"]))
        dim_label = build_dim_label(df_clean[["label_raw", "attack_group", "is_attack"]])
        
        # 2. Đồng bộ các dimension lên PG (Upsert)
        self._sync_dimension("dim_time", "time_key", dim_time, ["time_key", "full_datetime", "date_value", "year_num", "month_num", "day_num", "day_name", "hour_num","minute_num", "time_period", "is_business_hours"])
        self._sync_dimension("dim_ip", "ip_address", dim_ip, ["ip_address", "is_internal","network_segment", "is_blacklisted", "blacklist_source"])
        self._sync_dimension("dim_protocol", "protocol_number", dim_protocol, ["protocol_key", "protocol_number", "protocol_name"])
        self._sync_dimension("dim_port", "port_number", dim_port, ["port_number", "service_name", "port_range"])
        self._sync_dimension("dim_label", "label_raw", dim_label, ["label_raw", "attack_group", "is_attack"])
        
        # 3. Lấy surrogate keys từ PG về cho Fact
        with self.conn.cursor() as cur:
            # Tra ngược (do ta dùng Serial nên DB sinh key)
            df_clean["time_key"] = make_time_key(df_clean["flow_start_ts"])
            cur.execute("SELECT ip_address, ip_key FROM dim_ip")
            ip_map = dict(cur.fetchall())
            df_clean["src_ip_key"] = df_clean["src_ip"].map(ip_map)
            df_clean["dst_ip_key"] = df_clean["dst_ip"].map(ip_map)
            
            cur.execute("SELECT port_number, port_key FROM dim_port")
            port_map = dict(cur.fetchall())
            df_clean["dst_port_key"] = df_clean["dst_port"].map(port_map)
            
            df_clean["protocol_key"] = df_clean["protocol_number"]
            
            cur.execute("SELECT label_raw, label_key FROM dim_label")
            label_map = dict(cur.fetchall())
            df_clean["label_key"] = df_clean["label_raw"].map(label_map)

        # 4. Upsert Fact Table với source_log_id
        # Sử dụng DO NOTHING để đảm bảo idempotent
        fact_cols = FACT_COLS + ["source_log_id"] # source_log_id là cờ UNIQUE
        sql = f"""
            INSERT INTO fact_flow ({','.join(fact_cols)}) 
            VALUES %s 
            ON CONFLICT (source_log_id) DO NOTHING
        """
        rows = df_clean[fact_cols].values.tolist()
        with self.conn.cursor() as cur:
            execute_values(cur, sql, rows)
            _insert_batch_log(cur, batch_meta, len(df_clean))
        self.conn.commit()
        return len(df_clean)
    def write_alerts(self, df_alerts):
        """Ghi các luồng bị phát hiện là tấn công vào bảng cảnh báo."""
        if df_alerts.empty:
            return 0

        with self.conn.cursor() as cur:
            sql = """
                INSERT INTO network_alerts (source_log_id, flow_start_ts, src_ip, dst_ip, dst_port, attack_type) 
                VALUES %s 
                ON CONFLICT (source_log_id) DO NOTHING
            """
            cols = ["source_log_id", "flow_start_ts", "src_ip", "dst_ip", "dst_port", "predicted_attack"]
            rows = df_alerts[cols].values.tolist()
            
            from psycopg2.extras import execute_values
            execute_values(cur, sql, rows)
            
        self.conn.commit()
        return len(df_alerts)

class ObjectStoreSink:
    def __init__(self, endpoint_url, access_key, secret_key, bucket="network-lake"):
        self.fs = s3fs.S3FileSystem(
            key=access_key, 
            secret=secret_key, 
            client_kwargs={'endpoint_url': endpoint_url}
        )
        self.bucket = bucket
        
    def write_batch(self, df_clean, batch_meta):
        if df_clean.empty:
            return
        
        event_date = str(df_clean["flow_start_ts"].dt.date.iloc[0])
        # Tên file mang tính Idempotent: ghi lại cùng lô sẽ ghi đè cùng object
        file_name = f"part-p{batch_meta['partition']}-o{batch_meta['offset_start']}-{batch_meta['offset_end']}.parquet"
        s3_path = f"{self.bucket}/clean/event_date={event_date}/{file_name}"
        
        with self.fs.open(s3_path, 'wb') as f:
            df_clean.to_parquet(f, index=False)