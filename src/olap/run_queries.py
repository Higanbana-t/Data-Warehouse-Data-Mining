"""
Chạy truy vấn OLAP trong sql/03_olap_queries.sql và xuất CSV.
Lệnh: python -m src.olap.run_queries
"""
import os
import argparse
import csv
import re
import sys
from pathlib import Path
import psycopg2
from dotenv import load_dotenv

load_dotenv()

SQL_FILE = Path("sql/03_olap_queries.sql")
OUT_DIR = Path("reports/tables")
MARKER = re.compile(r"^--\s*name:\s*(\S+)\s*$", re.MULTILINE)

def parse_queries(text):
    matches = list(MARKER.finditer(text))
    queries = {}
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        queries[m.group(1)] = text[m.end():end].strip()
    return queries

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sql", type=Path, default=SQL_FILE)
    ap.add_argument("--out", type=Path, default=OUT_DIR)
    args = ap.parse_args()

    queries = parse_queries(args.sql.read_text(encoding="utf-8"))
    args.out.mkdir(parents=True, exist_ok=True)
    failed = []
    
    try:
        conn = psycopg2.connect(
            host=os.getenv("PGHOST"), port=os.getenv("PGPORT"),
            database=os.getenv("PGDATABASE"), user=os.getenv("PGUSER"),
            password=os.getenv("PGPASSWORD")
        )
        conn.autocommit = True
    except Exception as e:
        sys.exit(f"Lỗi kết nối CSDL PostgreSQL: {e}")

    with conn, conn.cursor() as cur:
        for name, sql in queries.items():
            try:
                cur.execute(sql)
                cols = [c.name for c in cur.description]
                rows = cur.fetchall()
            except Exception as e:
                failed.append(name)
                print(f"[LỖI] {name}: {str(e).strip().splitlines()[0]}")
                continue
            
            path = args.out / f"{name}.csv"
            with path.open("w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f)
                w.writerow(cols)
                w.writerows(rows)
            print(f"[OK ] {name:34s} {len(rows):>6} dòng -> {path}")

    print(f"\nHoàn thành: {len(queries) - len(failed)}/{len(queries)} truy vấn thành công.")

if __name__ == "__main__":
    main()