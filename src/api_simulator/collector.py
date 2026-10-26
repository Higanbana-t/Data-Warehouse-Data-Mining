"""
Collector: gọi Firewall API theo chu kỳ rồi INSERT vào bảng raw_network_logs của MySQL.

    python -m src.api_simulator.collector                  # chạy đến khi API báo hết dữ liệu
    python -m src.api_simulator.collector --follow         # chờ mãi, kể cả khi API chưa có dữ liệu mới
    python -m src.api_simulator.collector --max-rows 5000  # dừng sau khi ghi 5.000 dòng (kiểm thử)

Biến môi trường: API_URL, API_KEY, MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE,
                 POLL_INTERVAL_SECONDS, BATCH_LIMIT, SOURCE_NAME, COLUMN_MAP_PATH

Không mất, không trùng: con trỏ (seq cuối đã ghi) nằm trong bảng collector_state và được cập nhật TRONG CÙNG GIAO DỊCH
với việc ghi lô dữ liệu. Nếu Collector chết giữa chừng, giao dịch bị hủy và lần chạy sau tiếp tục đúng chỗ.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

import pymysql

from src.api_simulator import reader


class ApiError(Exception):
    def __init__(self, status, message="", retry_after=None):
        super().__init__(f"HTTP {status}: {message}")
        self.status, self.retry_after = status, retry_after


class StateConflict(Exception):
    """Con trỏ trong MySQL đã bị tiến trình khác thay đổi (có hai Collector chạy cùng lúc)."""


def log(msg):
    print(f"[collector] {msg}", flush=True)


def fetch(api_url, api_key, after, limit, timeout=15):
    req = urllib.request.Request(f"{api_url.rstrip('/')}/v1/logs?after={after}&limit={limit}",
                                 headers={"X-API-Key": api_key})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        ra = e.headers.get("Retry-After")
        raise ApiError(e.code, e.read().decode()[:200], float(ra) if ra else None) from e


def connect_mysql(retries=40, delay=3):
    for attempt in range(retries):
        try:
            return pymysql.connect(host=os.getenv("MYSQL_HOST", "mysql"), port=int(os.getenv("MYSQL_PORT", "3306")),
                                   user=os.getenv("MYSQL_USER", "simulator"), password=os.environ["MYSQL_PASSWORD"],
                                   database=os.getenv("MYSQL_DATABASE", "firewall"), charset="utf8mb4", autocommit=False)
        except pymysql.err.OperationalError as e:
            if attempt == retries - 1:
                raise
            log(f"chờ MySQL... ({str(e)[:80]})")
            time.sleep(delay)


def read_cursor(conn, source):
    with conn.cursor() as cur:
        cur.execute("INSERT IGNORE INTO collector_state (source, last_seq) VALUES (%s, 0)", (source,))
        cur.execute("SELECT last_seq FROM collector_state WHERE source = %s", (source,))
        seq = cur.fetchone()[0]
    conn.commit()
    return int(seq)


def insert_batch(conn, source, old_seq, new_seq, records, columns):
    """Ghi lô và cập nhật con trỏ trong MỘT giao dịch. Con trỏ chỉ được dời nếu vẫn đang ở old_seq."""
    sql = (f"INSERT INTO raw_network_logs ({', '.join(columns)}) VALUES ({', '.join(['%s'] * len(columns))})")
    rows = [[rec.get(c) for c in columns] for rec in records]
    try:
        with conn.cursor() as cur:
            cur.executemany(sql, rows)
            cur.execute("UPDATE collector_state SET last_seq = %s WHERE source = %s AND last_seq = %s",
                        (new_seq, source, old_seq))
            if cur.rowcount != 1:
                raise StateConflict(f"con trỏ không còn là {old_seq}: có Collector khác đang chạy?")
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--follow", action="store_true", help="không dừng khi API báo hết dữ liệu")
    ap.add_argument("--max-rows", type=int, default=0, help="dừng sau khi ghi tối đa N dòng (0 = không giới hạn)")
    ap.add_argument("--give-up-after", type=float, default=300, help="thoát sau N giây API không trả lời (0 = chờ mãi)")
    args = ap.parse_args()

    api_url, api_key = os.environ["API_URL"], os.environ["API_KEY"]
    poll = float(os.getenv("POLL_INTERVAL_SECONDS", "0.5"))
    limit = int(os.getenv("BATCH_LIMIT", "500"))
    source = os.getenv("SOURCE_NAME", "firewall-api")
    columns = list(reader.load_column_map()) + ["source_file"]

    conn = connect_mysql()
    seq = read_cursor(conn, source)
    log(f"bắt đầu từ seq={seq}; API={api_url}; mỗi lô tối đa {limit} dòng; nghỉ {poll}s giữa các lần gọi")
    total, t_start, last_log, down_since, backoff = 0, time.time(), time.time(), None, 1.0
    while True:
        try:
            page = fetch(api_url, api_key, seq, limit)
            down_since, backoff = None, 1.0
        except ApiError as e:
            if e.status in (401, 403):
                sys.exit(f"[collector] LỖI: API từ chối khóa (HTTP {e.status}). Kiểm tra API_KEY.")
            wait = e.retry_after or backoff
            log(f"{e}; thử lại sau {wait:.0f}s")
            time.sleep(wait)
            backoff = min(backoff * 2, 10)
            continue
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
            down_since = down_since or time.time()
            if args.give_up_after and time.time() - down_since > args.give_up_after:
                sys.exit(f"[collector] LỖI: API không trả lời suốt {args.give_up_after:.0f}s ({e})")
            log(f"chờ API... ({type(e).__name__}); thử lại sau {backoff:.0f}s")
            time.sleep(backoff)
            backoff = min(backoff * 2, 10)
            continue

        recs = page["records"]
        if recs:
            new_seq = recs[-1]["seq"]
            insert_batch(conn, source, seq, new_seq, recs, columns)
            seq, total = new_seq, total + len(recs)
        if time.time() - last_log >= 5:
            rate = total / max(time.time() - t_start, 1e-9)
            log(f"đã ghi {total:,} dòng ({rate:,.0f} dòng/s); seq={seq:,}; API đã phát {page['released']:,}/{page['total']:,}")
            last_log = time.time()
        if args.max_rows and total >= args.max_rows:
            log(f"đạt --max-rows={args.max_rows}; dừng ở seq={seq}")
            break
        if page["end"] and not args.follow:
            log(f"API đã hết dữ liệu; tổng đã ghi {total:,} dòng, seq cuối = {seq:,}")
            break
        time.sleep(poll)  # mô phỏng độ trễ giữa các lần lấy dữ liệu
    conn.close()


if __name__ == "__main__":
    main()
