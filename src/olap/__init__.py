"""
Chạy toàn bộ truy vấn OLAP trong sql/03_olap_queries.sql và xuất kết quả ra CSV.

Chạy từ thư mục gốc dự án:
    python -m src.olap.run_queries                  # chạy tất cả
    python -m src.olap.run_queries --only qc_ q4_   # chỉ chạy truy vấn có tên bắt đầu bằng qc_ hoặc q4_
    python -m src.olap.run_queries --list           # liệt kê tên các truy vấn

Kết nối PostgreSQL qua biến môi trường chuẩn: PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD
(hoặc nạp từ file .env bằng python-dotenv nếu bạn đã cài).
"""
import argparse
import csv
import re
import sys
from pathlib import Path

import psycopg2

try:  # tùy chọn: nạp .env nếu có
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

SQL_FILE = Path("sql/03_olap_queries.sql")
OUT_DIR = Path("reports/tables")
MARKER = re.compile(r"^--\s*name:\s*(\S+)\s*$", re.MULTILINE)


def parse_queries(text):
    """Tách file SQL thành {tên: câu_lệnh} dựa trên các dòng '-- name: ...'."""
    matches = list(MARKER.finditer(text))
    queries = {}
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        queries[m.group(1)] = text[m.end():end].strip()
    return queries


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sql", type=Path, default=SQL_FILE, help="đường dẫn file SQL")
    ap.add_argument("--out", type=Path, default=OUT_DIR, help="thư mục xuất CSV")
    ap.add_argument("--only", nargs="*", help="chỉ chạy truy vấn có tên bắt đầu bằng các tiền tố này")
    ap.add_argument("--list", action="store_true", help="chỉ liệt kê tên truy vấn")
    ap.add_argument("--preview", type=int, default=5, help="số dòng hiển thị xem trước (mặc định 5)")
    args = ap.parse_args()

    queries = parse_queries(args.sql.read_text(encoding="utf-8"))
    if args.only:
        queries = {k: v for k, v in queries.items() if k.startswith(tuple(args.only))}
    if args.list:
        print("\n".join(queries))
        return
    if not queries:
        sys.exit("Không tìm thấy truy vấn nào khớp.")

    args.out.mkdir(parents=True, exist_ok=True)
    failed = []
    conn = psycopg2.connect("")  # đọc cấu hình từ biến môi trường PG*
    conn.autocommit = True
    with conn, conn.cursor() as cur:
        for name, sql in queries.items():
            try:
                cur.execute(sql)
                cols = [c.name for c in cur.description]
                rows = cur.fetchall()
            except Exception as e:  # một truy vấn lỗi không làm dừng các truy vấn còn lại
                failed.append(name)
                print(f"[LOI] {name}: {str(e).strip().splitlines()[0]}")
                continue
            path = args.out / f"{name}.csv"
            with path.open("w", newline="", encoding="utf-8-sig") as f:  # utf-8-sig để Excel mở đúng tiếng Việt
                w = csv.writer(f)
                w.writerow(cols)
                w.writerows(rows)
            print(f"[OK ] {name:34s} {len(rows):>6} dòng -> {path}")
            for r in rows[: args.preview]:
                print("      ", r)
    print(f"\nHoàn thành: {len(queries) - len(failed)}/{len(queries)} truy vấn thành công.")
    if failed:
        sys.exit(f"Truy vấn lỗi: {', '.join(failed)}")


if __name__ == "__main__":
    main()