"""
Lõi làm sạch dữ liệu dùng chung cho cả Batch (transform.py) và Streaming (stream_consumer.py).
"""
import pandas as pd
import numpy as np

# Import lại các hằng số và hàm tiện ích từ transform.py
from src.etl.transform import (
    KEY_COLS, INT_KEY_COLS, MEASURE_REQUIRED, FLAG_COLS, RATE_COLS,
    canonical_ip, parse_timestamps, normalize_label, attack_group_of
)

MYSQL_TO_CORE = {
    "source_ip": "src_ip",
    "destination_ip": "dst_ip",
    "event_time_raw": "ts_raw",
    "protocol": "protocol_number",
    "source_port": "src_port",
    "destination_port": "dst_port",
    "label": "label_raw",
    "log_id": "source_log_id",
    "flow_duration": "flow_duration_us",
    "total_fwd_packets": "total_fwd_packets",
    "total_backward_packets": "total_bwd_packets",
    "total_length_of_fwd_packets": "total_fwd_bytes",
    "total_length_of_bwd_packets": "total_bwd_bytes",
    "average_packet_size": "avg_packet_size",
}


def apply_core_cleaning(df, tcfg, extra_cols=None):
    """Làm sạch DataFrame đã được đổi tên cột về chuẩn (src_ip, dst_ip, ts_raw, ...)."""
    extra_cols = extra_cols or []
    stats = {}
    
    # 1. Dòng thiếu khóa
    n = len(df)
    df = df.dropna(subset=KEY_COLS)
    stats["drop_null_key"] = n - len(df)

    # 2. Ép kiểu số
    n = len(df)
    for c in INT_KEY_COLS + MEASURE_REQUIRED + FLAG_COLS + RATE_COLS:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    df[RATE_COLS] = df[RATE_COLS].replace([np.inf, -np.inf], np.nan)
    df = df.dropna(subset=INT_KEY_COLS)
    stats["drop_bad_numeric_key"] = n - len(df)

    # 3. Chuẩn hóa IP
    n = len(df)
    uniq = pd.unique(pd.concat([df["src_ip"], df["dst_ip"]]).astype(str))
    ip_map = {u: canonical_ip(u) for u in uniq}
    df["src_ip"] = df["src_ip"].astype(str).map(ip_map)
    df["dst_ip"] = df["dst_ip"].astype(str).map(ip_map)
    df = df.dropna(subset=["src_ip", "dst_ip"])
    stats["drop_invalid_ip"] = n - len(df)

    # 4. Timestamp
    n = len(df)
    df["flow_start_ts"], pm_count = parse_timestamps(df["ts_raw"], tcfg["afternoon_hours"])
    df = df.dropna(subset=["flow_start_ts"])
    stats["drop_bad_timestamp"] = n - len(df)
    stats["ts_pm_adjusted"] = pm_count

    n = len(df)
    lo, hi = pd.Timestamp(tcfg["date_min"]), pd.Timestamp(tcfg["date_max"]) + pd.Timedelta(days=1)
    df = df[(df["flow_start_ts"] >= lo) & (df["flow_start_ts"] < hi)]
    stats["drop_out_of_range_date"] = n - len(df)
    h = df["flow_start_ts"].dt.hour
    stats["rows_outside_8_18"] = int(((h < tcfg["business_start"]) | (h > tcfg["business_end"])).sum())

    # 5. Số đo thiếu/âm
    n = len(df)
    bad = df[MEASURE_REQUIRED].isna().any(axis=1) | (df[MEASURE_REQUIRED] < 0).any(axis=1)
    df = df[~bad]
    stats["drop_negative_or_missing_measure"] = n - len(df)

    # 6. Ép kiểu cuối
    for c in INT_KEY_COLS:
        df[c] = df[c].astype("int64")
    for c in ["total_fwd_packets", "total_bwd_packets"]:
        df[c] = df[c].astype("int64")
    for c in ["flow_duration_us", "total_fwd_bytes", "total_bwd_bytes"]:
        df[c] = df[c].astype("int64")
    for c in FLAG_COLS:
        df[c] = df[c].fillna(0).clip(0, 32767).astype("int64")
    df["total_packets"] = df["total_fwd_packets"] + df["total_bwd_packets"]
    df["total_bytes"] = df["total_fwd_bytes"] + df["total_bwd_bytes"]
    df["flow_id"] = df["flow_id"].fillna("").astype(str).str.strip()

    # 7. Nhãn
    df["label_raw"] = normalize_label(df["label_raw"])
    groups = {l: attack_group_of(l) for l in df["label_raw"].unique()}
    df["attack_group"] = df["label_raw"].map(groups)
    df["is_attack"] = df["attack_group"] != "Benign"

    # 8. Bỏ trùng lặp hoàn toàn
    n = len(df)
    df = df.drop_duplicates(subset=[c for c in df.columns if c != "ts_raw" and c not in extra_cols])
    stats["drop_duplicates"] = n - len(df)

    df = df.drop(columns=["ts_raw"]).sort_values("flow_start_ts", kind="stable").reset_index(drop=True)
    return df, stats