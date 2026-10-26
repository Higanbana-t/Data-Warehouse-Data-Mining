# làm sạch, chuẩn hóa IP/Timestamp, gộp nhãn.
#tách dữ liệu thô ra thành 4 bảng Dimension và 1 bảng Fact, đồng thời chuẩn hóa thời gian và IP.
"""TRANSFORM: làm sạch và chuẩn hóa dữ liệu flow (IP, Timestamp, số đo, nhãn)."""
import ipaddress
import re

import numpy as np
import pandas as pd

RAW_TO_CLEAN = {
    "Flow ID": "flow_id", "Source IP": "src_ip", "Source Port": "src_port",
    "Destination IP": "dst_ip", "Destination Port": "dst_port", "Protocol": "protocol_number",
    "Timestamp": "ts_raw", "Flow Duration": "flow_duration_us",
    "Total Fwd Packets": "total_fwd_packets", "Total Backward Packets": "total_bwd_packets",
    "Total Length of Fwd Packets": "total_fwd_bytes", "Total Length of Bwd Packets": "total_bwd_bytes",
    "Flow Bytes/s": "flow_bytes_per_s", "Flow Packets/s": "flow_packets_per_s",
    "Average Packet Size": "avg_packet_size",
    "FIN Flag Count": "fin_flag_count", "SYN Flag Count": "syn_flag_count", "RST Flag Count": "rst_flag_count",
    "PSH Flag Count": "psh_flag_count", "ACK Flag Count": "ack_flag_count", "Label": "label_raw",
}
KEY_COLS = ["src_ip", "dst_ip", "ts_raw", "protocol_number", "src_port", "dst_port", "label_raw"]
MEASURE_REQUIRED = ["flow_duration_us", "total_fwd_packets", "total_bwd_packets", "total_fwd_bytes", "total_bwd_bytes"]
FLAG_COLS = ["fin_flag_count", "syn_flag_count", "rst_flag_count", "psh_flag_count", "ack_flag_count"]
RATE_COLS = ["flow_bytes_per_s", "flow_packets_per_s", "avg_packet_size"]
INT_KEY_COLS = ["src_port", "dst_port", "protocol_number"]


# ---------------------------------------------------------------- hàm tiện ích
def feature_name(name):
    """Chuẩn hóa tên cột đặc trưng để dùng an toàn trong DataFrame và Parquet."""
    value = str(name).strip().lower().replace("/", "_per_")
    return re.sub(r"_+", "_", re.sub(r"[^a-z0-9]+", "_", value)).strip("_")


def normalize_label(s):
    """Thay mọi ký tự không in được (vd byte 0x96 trong 'Web Attack ? Brute Force') bằng dấu '-'."""
    return s.astype(str).str.replace(r"[^\x20-\x7E]+", "-", regex=True).str.strip()


def attack_group_of(label):
    """Gộp nhãn gốc thành nhóm: Benign / DDoS / PortScan / WebAttack / Botnet / Other."""
    l = label.strip().lower()
    if l == "benign":
        return "Benign"
    if l == "ddos":
        return "DDoS"
    if l == "portscan":
        return "PortScan"
    if l.startswith("web attack"):
        return "WebAttack"
    if l == "bot":
        return "Botnet"
    return "Other"  # DoS Hulk/GoldenEye/slowloris/Slowhttptest, FTP/SSH-Patator, Infiltration, Heartbleed


def canonical_ip(ip):
    """Chuẩn hóa chuỗi IP (IPv4/IPv6); trả None nếu không hợp lệ."""
    try:
        return ipaddress.ip_address(str(ip).strip()).compressed
    except ValueError:
        return None


def parse_timestamps(series, afternoon_hours):
    """Chuyển 'd/m/yyyy h:mm' thành datetime.

    Định dạng là NGÀY/THÁNG (dữ liệu chỉ có tháng 7/2017 nên '3/7/2017' là 3 tháng 7).
    Không có AM/PM: giờ nằm trong afternoon_hours được cộng 12 giờ.
    """
    s = series.astype(str).str.strip()
    ts = pd.to_datetime(s, format="%d/%m/%Y %H:%M", errors="coerce")
    miss = ts.isna()
    if miss.any():  # dự phòng cho dòng có thêm giây
        ts[miss] = pd.to_datetime(s[miss], format="%d/%m/%Y %H:%M:%S", errors="coerce")
    pm = ts.dt.hour.isin(list(afternoon_hours))
    ts = ts.where(~pm, ts + pd.Timedelta(hours=12))
    return ts, int(pm.sum())


def make_time_key(ts):
    """Khóa dim_time dạng yyyymmddHHMM (BIGINT), tính bằng số học cho nhanh."""
    return (ts.dt.year.astype("int64") * 100_000_000 + ts.dt.month.astype("int64") * 1_000_000
            + ts.dt.day.astype("int64") * 10_000 + ts.dt.hour.astype("int64") * 100
            + ts.dt.minute.astype("int64"))


# ---------------------------------------------------------------- hàm chính
def clean_flows(raw, cfg, source_file=""):
    """Làm sạch 1 file (dùng cho Batch ETL). Trả về (DataFrame sạch, dict thống kê số dòng bị loại ở từng bước)."""
    tcfg = cfg["time"]
    stats = {"file": source_file, "rows_read": len(raw)}

    df = raw.rename(columns=RAW_TO_CLEAN)[list(RAW_TO_CLEAN.values())].copy()
    extra_cols = []
    if cfg.get("etl", {}).get("keep_all_features", True):
        used_names = set(RAW_TO_CLEAN.values())
        raw_to_clean = set(RAW_TO_CLEAN)
        for col in raw.columns:
            if col in raw_to_clean:
                continue
            name = feature_name(col)
            duplicate_base = re.sub(r"\.\d+$", "", str(col).strip())
            if name in used_names or feature_name(duplicate_base) in used_names:
                continue
            values = pd.to_numeric(raw[col], errors="coerce").replace([np.inf,-np.inf], np.nan)
            df[name] = values.to_numpy(dtype="float32")
            extra_cols.append(name)
            used_names.add(name)

    from src.etl.transform_core import apply_core_cleaning
    df, core_stats = apply_core_cleaning(df, tcfg, extra_cols=extra_cols)
    stats.update(core_stats)
    
    df["source_file"] = source_file
    stats["rows_out"] = len(df)
    return df, stats

def sample_flows(df, cfg):
    """(Tùy chọn) lấy mẫu: giữ benign_frac của Benign, tối đa max_rows_per_label dòng cho mỗi nhãn tấn công."""
    s = cfg["sampling"]
    parts = []
    for _, g in df.groupby("label_raw"):
        if g["attack_group"].iloc[0] == "Benign":
            g = g.sample(frac=s["benign_frac"], random_state=s["random_state"])
        elif len(g) > s["max_rows_per_label"]:
            g = g.sample(n=s["max_rows_per_label"], random_state=s["random_state"])
        parts.append(g)
    out = pd.concat(parts) if parts else df
    return out.sort_values("flow_start_ts", kind="stable").reset_index(drop=True)