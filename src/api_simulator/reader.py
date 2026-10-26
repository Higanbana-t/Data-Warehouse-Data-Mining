"""Đọc các file CSV GeneratedLabelledFlows theo đúng thứ tự thời gian và chuyển sang tên cột của bảng MySQL."""
import json
import os
from pathlib import Path

import numpy as np
import pandas as pd

from src.api_simulator.make_ddl import INT_COLS, TEXT_COLS

TEXT_NAMES = {name for name, _ in TEXT_COLS.values()}   # flow_id, source_ip, destination_ip, event_time_raw, label
INT_NAMES = set(INT_COLS.values())                       # source_port, destination_port, protocol
DAYS = ("monday", "tuesday", "wednesday", "thursday", "friday")


def file_order_key(name):
    """Thứ tự phát lại: thứ Hai -> thứ Sáu; trong ngày: sáng trước chiều; chiều thứ Sáu: PortScan trước DDoS.
    (Sắp theo tên file thông thường sẽ cho 'Friday' lên trước 'Monday'.)"""
    n = name.lower()
    day = next((i for i, d in enumerate(DAYS) if n.startswith(d)), 9)
    part = 1 if "afternoon" in n else 0
    sub = 1 if "ddos" in n else 0
    return (day, part, sub, n)


def list_csv_files(directory):
    files = sorted(Path(directory).rglob("*.csv"), key=lambda p: file_order_key(p.name))
    if not files:
        raise FileNotFoundError(f"Không tìm thấy file .csv nào trong '{directory}'.")
    return files


def load_column_map(path=None):
    """{tên cột MySQL: tên cột gốc trong CSV}, sinh bởi make_ddl.py."""
    path = path or os.getenv("COLUMN_MAP_PATH", "sql/mysql/raw_network_logs_columns.json")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def read_file(path, column_map):
    """Đọc 1 file CSV, trả về DataFrame có tên cột MySQL (+ source_file).
    Infinity/NaN trở thành giá trị thiếu (MySQL kiểu DOUBLE không lưu được); cổng/giao thức là số nguyên."""
    raw = pd.read_csv(path, encoding="latin-1", low_memory=False)  # latin-1: nhãn Web Attack chứa byte lạ
    raw.columns = [c.strip() for c in raw.columns]                 # tên cột gốc có khoảng trắng đầu
    missing = [o for o in column_map.values() if o not in raw.columns]
    if missing:
        raise ValueError(f"{Path(path).name} thiếu cột {missing[:5]}. Cần bản GeneratedLabelledFlows (có IP/Timestamp/Protocol).")
    out = pd.DataFrame({my: raw[orig] for my, orig in column_map.items()})
    for c in out.columns:
        if c in TEXT_NAMES:
            out[c] = out[c].astype(object).where(out[c].notna(), None)
            out[c] = out[c].map(lambda v: v.strip() if isinstance(v, str) else v)
        else:
            out[c] = pd.to_numeric(out[c], errors="coerce").replace([np.inf, -np.inf], np.nan)
            if c in INT_NAMES:
                out[c] = out[c].astype("Int64")
    out["source_file"] = Path(path).name
    return out


def load_replay_frame(directory, column_map, max_rows=None):
    """Nạp toàn bộ các file (theo đúng thứ tự phát lại) vào một DataFrame; dùng cho tập mẫu vài trăm nghìn dòng."""
    parts, total = [], 0
    for f in list_csv_files(directory):
        df = read_file(f, column_map)
        parts.append(df)
        total += len(df)
        if max_rows and total >= max_rows:
            break
    out = pd.concat(parts, ignore_index=True)
    return out.iloc[:max_rows].copy() if max_rows else out


def to_records(df):
    """DataFrame -> list[dict] an toàn cho JSON: giá trị thiếu thành None, số nguyên là int của Python."""
    obj = df.astype(object)
    obj = obj.where(pd.notna(obj), None)
    return obj.to_dict("records")
