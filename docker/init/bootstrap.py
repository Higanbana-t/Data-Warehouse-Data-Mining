"""
Khởi tạo một lần (dịch vụ `init`): (1) tạo bucket S3, (2) đăng ký Debezium connector. Chạy lại nhiều lần không lỗi.

Biến môi trường: CONNECT_URL, CONNECTOR_NAME, CONNECTOR_CONFIG_PATH, DEBEZIUM_USER, DEBEZIUM_PASSWORD,
                 S3_ENDPOINT_URL, S3_ACCESS_KEY, S3_SECRET_KEY, S3_BUCKET
Dùng thư viện chuẩn cho phần gọi REST của Connect; dùng boto3 cho S3 (không cần công cụ `mc` của MinIO).
"""
import json
import os
import string
import sys
import time
import urllib.error
import urllib.request

WAIT_SECONDS = int(os.getenv("BOOTSTRAP_WAIT_SECONDS", "180"))


def log(msg):
    print(f"[bootstrap] {msg}", flush=True)


def retry(what, fn, timeout=WAIT_SECONDS, delay=3):
    """Gọi fn() cho đến khi thành công hoặc hết thời gian; trả về kết quả của fn."""
    deadline, last = time.time() + timeout, None
    while True:
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 - mọi lỗi kết nối đều cần thử lại
            last = e
            if time.time() > deadline:
                sys.exit(f"[bootstrap] LỖI: hết {timeout}s chờ {what}. Lỗi cuối: {last}")
            log(f"chờ {what}... ({type(e).__name__}: {str(e)[:120]})")
            time.sleep(delay)


# ---------------------------------------------------------------- S3
def ensure_bucket():
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError

    s3 = boto3.client("s3", endpoint_url=os.environ["S3_ENDPOINT_URL"],
                      aws_access_key_id=os.environ["S3_ACCESS_KEY"], aws_secret_access_key=os.environ["S3_SECRET_KEY"],
                      region_name="us-east-1", config=Config(s3={"addressing_style": "path"},
                                                             connect_timeout=5, read_timeout=10, retries={"max_attempts": 1}))
    retry("dịch vụ S3", lambda: s3.list_buckets())
    bucket = os.environ.get("S3_BUCKET", "network-lake")
    try:
        s3.head_bucket(Bucket=bucket)
        log(f"bucket '{bucket}' đã tồn tại")
    except ClientError:
        s3.create_bucket(Bucket=bucket)
        log(f"đã tạo bucket '{bucket}'")


# ---------------------------------------------------------------- Debezium
def http(method, url, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status, json.loads(r.read().decode() or "null")


def register_connector():
    base = os.environ["CONNECT_URL"].rstrip("/")
    name = os.environ.get("CONNECTOR_NAME", "fw-mysql-connector")
    with open(os.environ["CONNECTOR_CONFIG_PATH"], encoding="utf-8") as f:
        try:
            text = string.Template(f.read()).substitute(os.environ)
        except KeyError as e:
            sys.exit(f"[bootstrap] LỖI: thiếu biến môi trường {e} (kiểm tra file .env và phần environment của dịch vụ init)")
    config = json.loads(text)

    info = retry("Kafka Connect (REST)", lambda: http("GET", base + "/")[1])
    log(f"Connect sẵn sàng: phiên bản {info.get('version')}")
    try:  # PUT .../config tạo mới hoặc cập nhật: chạy lại nhiều lần không lỗi
        status, _ = http("PUT", f"{base}/connectors/{name}/config", config)
    except urllib.error.HTTPError as e:
        sys.exit(f"[bootstrap] LỖI khi đăng ký connector (HTTP {e.code}): {e.read().decode()[:1500]}")
    log(f"đã gửi cấu hình connector '{name}' (HTTP {status})")

    def running():
        st = http("GET", f"{base}/connectors/{name}/status")[1]
        states = [st["connector"]["state"]] + [t["state"] for t in st.get("tasks", [])]
        if "FAILED" in states:
            trace = next((t.get("trace", "") for t in st.get("tasks", []) if t["state"] == "FAILED"),
                         st["connector"].get("trace", ""))
            sys.exit(f"[bootstrap] Connector FAILED:\n{trace[:2000]}")
        if states[0] != "RUNNING" or not st.get("tasks") or any(s != "RUNNING" for s in states):
            raise RuntimeError(f"trạng thái hiện tại: {states}")
        return states

    states = retry("connector chuyển sang RUNNING", running, timeout=90)
    log(f"connector '{name}' đang chạy: {states}")


if __name__ == "__main__":
    ensure_bucket()
    register_connector()
    log("HOÀN THÀNH")
