# gọi lần lượt extract → transform → load
"""
Chạy toàn bộ pipeline ETL: extract -> transform -> (Parquet sạch) -> load vào PostgreSQL.

Chạy từ THƯ MỤC GỐC dự án:
    python -m src.etl.run_etl --create-schema          # lần đầu: tạo bảng rồi chạy cả pipeline
    python -m src.etl.run_etl                          # chạy lại toàn bộ (TRUNCATE rồi nạp lại)
    python -m src.etl.run_etl --transform-only         # chỉ làm sạch, ghi Parquet + etl_summary.csv
    python -m src.etl.run_etl --load-only              # chỉ nạp từ Parquet đã có
    python -m src.etl.run_etl --limit-files 1          # chạy thử với 1 file đầu tiên

Kết nối DB qua biến môi trường PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD (hoặc file .env).
"""
import argparse
import sys
from pathlib import Path

import pandas as pd

from src.etl.extract import list_raw_files, read_raw_file
from src.etl.load import load_warehouse, reconcile
from src.etl.transform import clean_flows, sample_flows
from src.utils.config import get_connection, load_config
from src.utils.logger import get_logger

log = get_logger("etl")


def run_transform(cfg, limit_files=None):
    files = list_raw_files(cfg["paths"]["raw_dir"])
    if limit_files:
        files = files[:limit_files]
    clean_dir = Path(cfg["paths"]["clean_dir"])
    clean_dir.mkdir(parents=True, exist_ok=True)
    for old in clean_dir.glob("*.parquet"):  # xóa kết quả cũ để không lẫn file của lần chạy trước
        old.unlink()

    all_stats = []
    for path in files:
        log.info("Đọc %s", path.name)
        raw = read_raw_file(path)
        df, stats = clean_flows(raw, cfg, source_file=path.name)
        if cfg["sampling"]["enabled"]:
            df = sample_flows(df, cfg)
            stats["rows_out"] = len(df)
            stats["sampled"] = True
        out = clean_dir / f"{path.stem}.parquet"
        df.to_parquet(out, index=False)
        all_stats.append(stats)
        dropped = stats["rows_read"] - stats["rows_out"]
        log.info("  %s: đọc %d -> sạch %d (loại %d: null=%d, ip=%d, ts=%d, ngoài khoảng ngày=%d, số đo=%d, trùng=%d)",
                 path.name, stats["rows_read"], stats["rows_out"], dropped, stats["drop_null_key"],
                 stats["drop_invalid_ip"], stats["drop_bad_timestamp"], stats["drop_out_of_range_date"],
                 stats["drop_negative_or_missing_measure"], stats["drop_duplicates"])
        if stats["rows_out"] and stats["rows_outside_8_18"] / stats["rows_out"] > 0.01:
            log.warning("  %s: %.1f%% dòng nằm ngoài 08:00-17:59 sau khi chuyển AM/PM -> kiểm tra lại quy tắc "
                        "'afternoon_hours' trong config.yaml", path.name,
                        100 * stats["rows_outside_8_18"] / stats["rows_out"])

    summary = pd.DataFrame(all_stats)
    tables = Path(cfg["paths"]["tables_dir"])
    tables.mkdir(parents=True, exist_ok=True)
    summary.to_csv(tables / "etl_summary.csv", index=False, encoding="utf-8-sig")
    log.info("TỔNG: đọc %d dòng -> sạch %d dòng. Thống kê: %s", summary["rows_read"].sum(), summary["rows_out"].sum(),
             tables / "etl_summary.csv")
    return int(summary["rows_out"].sum())


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--raw-dir", help="ghi đè paths.raw_dir")
    ap.add_argument("--create-schema", action="store_true", help="chạy sql/01_create_schema.sql trước khi nạp")
    ap.add_argument("--transform-only", action="store_true")
    ap.add_argument("--load-only", action="store_true")
    ap.add_argument("--limit-files", type=int, help="chỉ xử lý N file đầu tiên (chạy thử)")
    args = ap.parse_args()
    if args.transform_only and args.load_only:
        sys.exit("Không dùng đồng thời --transform-only và --load-only.")

    cfg = load_config(args.config)
    if args.raw_dir:
        cfg["paths"]["raw_dir"] = args.raw_dir

    expected = None
    if not args.load_only:
        expected = run_transform(cfg, args.limit_files)
    if args.transform_only:
        return

    if expected is None:  # --load-only: đếm số dòng từ Parquet
        expected = sum(len(pd.read_parquet(f, columns=["flow_id"]))
                       for f in Path(cfg["paths"]["clean_dir"]).glob("*.parquet"))
    conn = get_connection()
    try:
        if args.create_schema:
            schema = Path(cfg["paths"]["schema_sql"]).read_text(encoding="utf-8")
            with conn, conn.cursor() as cur:
                cur.execute(schema)
            log.info("Đã tạo schema từ %s", cfg["paths"]["schema_sql"])
        load_warehouse(conn, cfg, log)
        ok = reconcile(conn, expected, log)
    finally:
        conn.close()
    if not ok:
        sys.exit(1)
    log.info("HOÀN THÀNH. Bước tiếp theo: psql -f sql/04_views.sql rồi python -m src.olap.run_queries")


if __name__ == "__main__":
    main()