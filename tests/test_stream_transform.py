import pandas as pd
import sys
import types

from src.etl.transform_core import MYSQL_TO_CORE, apply_core_cleaning
from src.etl.load import build_dim_time
from src.etl.transform import make_time_key


def test_fact_time_keys_match_minute_granularity_dimension():
    timestamps = pd.Series(
        pd.to_datetime(["2017-07-03 08:55:58", "2017-07-03 08:55:12", "2017-07-03 08:56:01"])
    )
    dim_time = build_dim_time(timestamps, {"business_start": 8, "business_end": 17})
    fact_time_keys = make_time_key(timestamps)

    assert fact_time_keys.tolist() == [201707030855, 201707030855, 201707030856]
    assert set(fact_time_keys).issubset(set(dim_time["time_key"]))


def test_cdc_record_maps_to_core_and_cleans():
    cdc_record = {
        "log_id": 1,
        "flow_id": "192.168.10.5-8.254.250.126-49188-80-6",
        "source_ip": "8.254.250.126",
        "source_port": 80,
        "destination_ip": "192.168.10.5",
        "destination_port": 49188,
        "protocol": 6,
        "event_time_raw": "03/07/2017 08:55:58",
        "flow_duration": 4.0,
        "total_fwd_packets": 2.0,
        "total_backward_packets": 0.0,
        "total_length_of_fwd_packets": 12.0,
        "total_length_of_bwd_packets": 0.0,
        "flow_bytes_per_s": 3_000_000.0,
        "flow_packets_per_s": 500_000.0,
        "average_packet_size": 9.0,
        "fin_flag_count": 0.0,
        "syn_flag_count": 0.0,
        "rst_flag_count": 0.0,
        "psh_flag_count": 0.0,
        "ack_flag_count": 1.0,
        "label": "BENIGN",
    }
    df = pd.DataFrame([cdc_record]).rename(columns=MYSQL_TO_CORE)
    tcfg = {
        "business_start": 8,
        "business_end": 17,
        "date_min": "2017-07-01",
        "date_max": "2017-07-31",
        "afternoon_hours": [1, 2, 3, 4, 5, 6, 7],
    }

    cleaned, _ = apply_core_cleaning(df, tcfg)

    assert len(cleaned) == 1
    assert cleaned.loc[0, "total_fwd_packets"] == 2
    assert cleaned.loc[0, "total_bwd_packets"] == 0
    assert cleaned.loc[0, "total_packets"] == 2
    assert cleaned.loc[0, "total_bytes"] == 12
    assert cleaned.loc[0, "avg_packet_size"] == 9
    assert cleaned.loc[0, "source_log_id"] == 1


def test_protocol_dimension_insert_includes_assigned_primary_key(monkeypatch):
    monkeypatch.setitem(sys.modules, "s3fs", types.ModuleType("s3fs"))
    from src.etl import sinks
    from src.etl.load import build_dim_protocol

    class Cursor:
        def execute(self, sql):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    class Connection:
        def __init__(self):
            self.committed = False

        def cursor(self):
            return Cursor()

        def commit(self):
            self.committed = True

    conn = Connection()
    inserted = {}

    def capture_insert(cursor, sql, rows):
        inserted["sql"] = sql
        inserted["rows"] = rows

    monkeypatch.setattr(sinks, "execute_values", capture_insert)
    sink = sinks.PostgresSink(conn, {}, None)
    protocol_dim = build_dim_protocol({6})

    sink._sync_dimension(
        "dim_protocol",
        "protocol_number",
        protocol_dim,
        ["protocol_key", "protocol_number", "protocol_name"],
    )

    assert "INSERT INTO dim_protocol (protocol_key,protocol_number,protocol_name)" in inserted["sql"]
    assert inserted["rows"] == [[6, 6, "TCP"]]
    assert conn.committed


def test_batch_log_insert_matches_schema_columns(monkeypatch):
    monkeypatch.setitem(sys.modules, "s3fs", types.ModuleType("s3fs"))
    from src.etl.sinks import _insert_batch_log

    class Cursor:
        def execute(self, sql, params):
            self.sql = sql
            self.params = params

    cursor = Cursor()
    _insert_batch_log(
        cursor,
        {
            "consumer_group": "dwdm-etl-streaming-group",
            "topic": "fw.firewall.raw_network_logs",
            "partition": 0,
            "offset_start": 100,
            "offset_end": 599,
            "rows_in": 500,
            "latency_p50_ms": 250,
            "latency_p95_ms": 900,
        },
        rows_loaded=480,
    )

    assert (
        "(consumer_group, topic, kafka_partition, start_offset, end_offset,"
        " rows_in, rows_loaded, rows_rejected, latency_p50_ms, latency_p95_ms)"
        in " ".join(cursor.sql.split())
    )
    assert cursor.params == (
        "dwdm-etl-streaming-group",
        "fw.firewall.raw_network_logs",
        0,
        100,
        599,
        500,
        480,
        20,
        250,
        900,
    )


def test_empty_alert_batch_still_creates_alert_table(monkeypatch):
    monkeypatch.setitem(sys.modules, "s3fs", types.ModuleType("s3fs"))
    from src.etl.sinks import PostgresSink

    class Cursor:
        def __init__(self):
            self.statements = []

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def execute(self, sql):
            self.statements.append(sql)

    class Connection:
        def __init__(self):
            self.cur = Cursor()
            self.committed = False

        def cursor(self):
            return self.cur

        def commit(self):
            self.committed = True

    conn = Connection()
    sink = PostgresSink(conn, {}, None)

    assert sink.write_alerts(pd.DataFrame()) == 0
    assert "CREATE TABLE IF NOT EXISTS network_alerts" in conn.cur.statements[0]
    assert conn.committed
