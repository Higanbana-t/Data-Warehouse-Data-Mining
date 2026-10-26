"""
ETL Streaming Consumer: Đọc CDC từ Kafka, gom lô, làm sạch, ghi kép vào PostgreSQL và S3.
"""
import os
import json
import time
import signal
import numpy as np
import pandas as pd
import psycopg2
# pyrefly: ignore[missing-import]
from confluent_kafka import Consumer, KafkaError

from src.etl.transform_core import MYSQL_TO_CORE, apply_core_cleaning
from src.etl.load import load_blacklists
from src.etl.sinks import PostgresSink, ObjectStoreSink
from src.utils.logger import get_logger
from src.mining.inference import StreamingInference

running = True
def handle_sigterm(*args):
    global running
    running = False

def main():
    signal.signal(signal.SIGINT, handle_sigterm)
    signal.signal(signal.SIGTERM, handle_sigterm)
    logger = get_logger("stream_consumer")
    
    # Khởi tạo kết nối DB & S3
    pg_conn = psycopg2.connect(
        host=os.getenv("PGHOST", "postgres"), port=os.getenv("PGPORT", "5432"),
        user=os.environ["PGUSER"], password=os.environ["PGPASSWORD"], dbname=os.environ["PGDATABASE"]
    )
    blacklists = load_blacklists(os.getenv("BLACKLIST_DIR", "data/raw/firehol"), logger)
    pg_sink = PostgresSink(pg_conn, blacklists, logger)
    s3_sink = ObjectStoreSink(
        endpoint_url=os.environ["S3_ENDPOINT_URL"],
        access_key=os.environ["S3_ACCESS_KEY"],
        secret_key=os.environ["S3_SECRET_KEY"]
    )

    # Khởi tạo mô hình suy luận 1 LẦN DUY NHẤT ngoài vòng lặp
    model_path = os.getenv("MODEL_PATH", "models/multiclass_rf_v1.joblib")
    logger.info("Nạp mô hình suy luận AI từ: %s", model_path)
    inferencer = StreamingInference(model_path=model_path)
    logger.info("Nạp mô hình AI thành công. Số đặc trưng: %d", len(inferencer.features))

    # Khởi tạo Kafka Consumer
    consumer = Consumer({
        'bootstrap.servers': os.getenv('KAFKA_BOOTSTRAP_SERVERS', 'kafka:9092'),
        'group.id': 'dwdm-etl-streaming-group',
        'auto.offset.reset': 'earliest',
        'enable.auto.commit': False
    })
    topic = "fw.firewall.raw_network_logs"
    consumer.subscribe([topic])
    
    batch = []
    batch_meta = {'offset_start': None, 'offset_end': None, 'partition': 0, 'latencies_ms': []}
    tcfg = {"business_start": 8, "business_end": 17, "date_min": "2017-07-01", "date_max": "2017-07-31", "afternoon_hours": [1, 2, 3, 4, 5, 6, 7]}
    last_flush_time = time.time()

    def flush_batch():
        nonlocal batch, batch_meta, last_flush_time
        if not batch:
            return
        
        df = pd.DataFrame(batch).rename(columns=MYSQL_TO_CORE)
        df_clean, stats = apply_core_cleaning(df, tcfg)
        
        alerts_count = 0
        if not df_clean.empty:
            # --- TÍCH HỢP AI PHÁT HIỆN TẤN CÔNG (dùng inferencer đã nạp sẵn) ---
            df_clean["predicted_attack"] = inferencer.predict(df_clean)
            
            # Lọc các dòng bị mô hình đánh giá là tấn công (khác Benign)
            df_alerts = df_clean[df_clean["predicted_attack"] != "Benign"].copy()
            if not df_alerts.empty:
                df_alerts["source_log_id"] = df_alerts["source_log_id"].astype(str)
                df_alerts = df_alerts.drop_duplicates(subset=["source_log_id"])
            # ------------------------------------------------------------------
            
            lats = batch_meta['latencies_ms']
            p50 = int(np.percentile(lats, 50)) if lats else 0
            p95 = int(np.percentile(lats, 95)) if lats else 0
            
            meta = {
                'consumer_group': 'dwdm-etl-streaming-group',
                'topic': topic,
                'partition': batch_meta['partition'],
                'offset_start': batch_meta['offset_start'],
                'offset_end': batch_meta['offset_end'],
                'rows_in': len(batch),
                'latency_p50_ms': p50,
                'latency_p95_ms': p95
            }
            
            # Ghi kép (Dual-write) + Ghi cảnh báo
            try:
                pg_sink.write_batch(df_clean, meta)
                s3_sink.write_batch(df_clean, meta)
                alerts_count = pg_sink.write_alerts(df_alerts)
                
                consumer.commit(asynchronous=False)
                logger.info(f"Lô {len(batch)} dòng | Sạch: {len(df_clean)} | Cảnh báo AI: {alerts_count} cuộc tấn công (P50: {p50}ms, P95: {p95}ms).")
            except Exception as e:
                logger.error(f"Lỗi ghi Sinks (Lô sẽ được giao lại): {e}", exc_info=True)
                pg_conn.rollback()
                return
        else:
            consumer.commit(asynchronous=False)
            logger.info(f"Lô {len(batch)} dòng | Sau làm sạch: 0 dòng hợp lệ.")
        
        batch.clear()
        batch_meta = {'offset_start': None, 'offset_end': None, 'partition': 0, 'latencies_ms': []}
        last_flush_time = time.time()

    logger.info("Bắt đầu đọc luồng từ Kafka...")
    while running:
        msg = consumer.poll(timeout=1.0)
        now = time.time()

        if msg is not None:
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    logger.error("Lỗi Kafka: %s", msg.error())
            else:
                try:
                    val = json.loads(msg.value().decode('utf-8'))
                    if not ('__op' in val and val['__op'] in ('d', 't')):
                        batch.append(val)
                        if batch_meta['offset_start'] is None:
                            batch_meta['offset_start'] = msg.offset()
                        batch_meta['offset_end'] = msg.offset()
                        batch_meta['partition'] = msg.partition()
                        
                        # Tính độ trễ CDC
                        t_src, t_deb = val.get('__source_ts_ms'), val.get('__ts_ms')
                        if t_src is not None and t_deb is not None:
                            batch_meta['latencies_ms'].append(max(0, int(t_deb - t_src)))
                except Exception as e:
                    logger.warning("Bỏ qua thông điệp hỏng: %s", e)

        # Micro-batching: Xử lý khi đủ 500 dòng HOẶC quá 3.0s nếu có dữ liệu đọng
        if len(batch) >= 500 or (len(batch) > 0 and (now - last_flush_time) >= 3.0):
            flush_batch()

    if batch:
        flush_batch()

    consumer.close()
    pg_conn.close()

if __name__ == "__main__":
    main()