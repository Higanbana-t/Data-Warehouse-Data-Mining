# đọc CSV theo chunk
"""EXTRACT: tìm và đọc các file CSV gốc của CICIDS2017 (bản GeneratedLabelledFlows)."""
from pathlib import Path

import pandas as pd

# Các cột gốc cần dùng (tên đã bỏ khoảng trắng đầu/cuối). Các cột còn lại (~65 đặc trưng)
# không nạp vào kho; nếu cần cho mô hình thì đọc lại trực tiếp từ file gốc ở giai đoạn Data Mining.
NEEDED_COLUMNS = [
    "Flow ID", "Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Timestamp",
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Flow Bytes/s", "Flow Packets/s", "Average Packet Size",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
    "Label",
]


def list_raw_files(raw_dir):
    files = sorted(Path(raw_dir).rglob("*.csv"))
    if not files:
        raise FileNotFoundError(
            f"Không tìm thấy file .csv nào trong '{raw_dir}'. "
            "Hãy giải nén GeneratedLabelledFlows.zip vào thư mục này.")
    return files


def read_raw_file(path, keep_all=True):
    """Đọc 1 file CSV gốc và giữ TẤT CẢ các cột để phục vụ Data Mining."""
    df = pd.read_csv(path, encoding="latin-1", low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    missing = [c for c in NEEDED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(
            f"{Path(path).name} thiếu cột: {missing}. Cần bản GeneratedLabelledFlows.")
    return df