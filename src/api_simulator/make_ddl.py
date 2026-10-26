"""
Sinh DDL bảng `raw_network_logs` (MySQL) và file ánh xạ tên cột từ dòng tiêu đề của CSV gốc (GeneratedLabelledFlows).

    python -m src.api_simulator.make_ddl --csv data/raw/cicids2017/Monday-WorkingHours.pcap_ISCX.csv

Ghi ra:
    sql/mysql/02_raw_network_logs.sql          # DDL, được mount vào MySQL khi khởi tạo lần đầu
    sql/mysql/raw_network_logs_columns.json    # {tên cột MySQL: tên cột gốc trong CSV}, dùng chung cho
                                               # Simulator (CSV -> MySQL) và consumer (MySQL -> làm sạch)

Quy tắc:
  - tên cột MySQL = snake_case của tên gốc (cùng quy tắc feature_name của ETL);
  - Timestamp -> event_time_raw (chuỗi gốc, ví dụ '7/7/2017 1:00'), Label -> label;
  - đặc trưng số = DOUBLE (không dùng DECIMAL: Debezium mã hóa DECIMAL thành chuỗi nhị phân khó đọc);
  - cột 'Fwd Header Length' xuất hiện 2 lần trong CSV: chỉ giữ bản đầu;
  - thêm log_id (khóa tự tăng, làm khóa idempotent ở kho dữ liệu), source_file, ingested_at (thời điểm ghi thật).
"""
import argparse
import csv
import json
import re
from pathlib import Path

TEXT_COLS = {"Flow ID": ("flow_id", "VARCHAR(150)"), "Source IP": ("source_ip", "VARCHAR(64)"),
             "Destination IP": ("destination_ip", "VARCHAR(64)"), "Timestamp": ("event_time_raw", "VARCHAR(32)"),
             "Label": ("label", "VARCHAR(64)")}
INT_COLS = {"Source Port": "source_port", "Destination Port": "destination_port", "Protocol": "protocol"}


def snake(col):
    s = col.strip().lower().replace("/", "_per_")
    return re.sub(r"[^a-z0-9]+", "_", s).strip("_")


def build(header):
    cols, seen_raw = [], set()
    for raw in (h.strip() for h in header):
        if raw in seen_raw:  # cột lặp tên (Fwd Header Length)
            continue
        seen_raw.add(raw)
        if raw in TEXT_COLS:
            name, typ = TEXT_COLS[raw]
        elif raw in INT_COLS:
            name, typ = INT_COLS[raw], "INT"
        else:
            name, typ = snake(raw), "DOUBLE"
        cols.append((name, typ, raw))
    names = [c[0] for c in cols]
    if len(set(names)) != len(names):
        raise ValueError("Tên cột MySQL bị trùng sau khi chuẩn hóa: " + str([n for n in names if names.count(n) > 1]))
    return cols


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--csv", required=True, help="một file CSV gốc (chỉ cần dòng tiêu đề)")
    ap.add_argument("--out-dir", default="sql/mysql")
    args = ap.parse_args()
    with open(args.csv, newline="", encoding="latin-1") as f:
        header = next(csv.reader(f))
    cols = build(header)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    lines = ["CREATE DATABASE IF NOT EXISTS firewall;", "USE firewall;", "",
             "DROP TABLE IF EXISTS raw_network_logs;",
             "CREATE TABLE raw_network_logs (",
             "    log_id         BIGINT AUTO_INCREMENT PRIMARY KEY,   -- khóa idempotent ở kho dữ liệu"]
    lines += [f"    {n:<34}{t}," for n, t, _ in cols]
    lines += ["    source_file    VARCHAR(100),",
              "    ingested_at    TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)   -- thời điểm ghi thật (đo độ trễ)",
              ") ENGINE=InnoDB;", "",
              "-- Con trỏ của Collector: last_seq là seq cuối cùng của Firewall API đã được ghi vào raw_network_logs.",
              "-- Được cập nhật TRONG CÙNG GIAO DỊCH với việc ghi dữ liệu nên không mất, không trùng khi Collector chết giữa chừng.",
              "-- Bảng này KHÔNG nằm trong table.include.list của Debezium nên không phát sinh sự kiện CDC.",
              "CREATE TABLE IF NOT EXISTS collector_state (",
              "    source      VARCHAR(100) PRIMARY KEY,",
              "    last_seq    BIGINT NOT NULL DEFAULT 0,",
              "    updated_at  TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3)",
              ") ENGINE=InnoDB;",
              "",
              "-- Tài khoản 'simulator' (do Collector dùng) chỉ có INSERT/SELECT trên raw_network_logs; được thêm UPDATE",
              "-- ở bảng con trỏ. Tài khoản được tạo bởi docker/mysql/init/01_users.sh (chạy trước file này).",
              "GRANT UPDATE ON firewall.collector_state TO 'simulator'@'%';", ""]
    (out / "02_raw_network_logs.sql").write_text(
        "-- Sinh tự động bởi src/api_simulator/make_ddl.py, KHÔNG sửa tay. Không tạo chỉ mục phụ (tăng tốc INSERT).\n"
        + "\n".join(lines), encoding="utf-8")
    (out / "raw_network_logs_columns.json").write_text(
        json.dumps({n: raw for n, _, raw in cols}, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"Đã ghi {len(cols)} cột nguồn (+ log_id, source_file, ingested_at) vào {out}/")


if __name__ == "__main__":
    main()
