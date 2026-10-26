"""Kiểm thử Firewall API, reader, tạo mẫu phát lại và Collector (không cần MySQL/Docker). Chạy: python -m pytest tests -v"""
import csv
import importlib.util
import json
from pathlib import Path

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from src.api_simulator import api, collector, make_replay_sample, reader
from src.api_simulator.make_ddl import build

_spec = importlib.util.spec_from_file_location("fx", Path(__file__).with_name("make_fixture_csv.py"))
fx = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fx)
HEADER = fx.HEADER.split(",")
NAMES = [h.strip() for h in HEADER]
COLUMN_MAP = {name: raw for name, _, raw in build(HEADER)}
KEY = "khoa-thu-nghiem"


def make_row(over=None):
    """Dòng mẫu thật của CICIDS2017; `over` là {tên cột gốc: giá trị} cần ghi đè."""
    r = fx.TEMPLATE.split(",")
    for k, v in (over or {}).items():
        r[NAMES.index(k)] = v
    return r


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="latin-1") as f:
        w = csv.writer(f)
        w.writerow(HEADER)
        w.writerows(rows)


def labelled(label, n, start=0, **over):
    return [make_row({"Label": label, "Source Port": str(1000 + start + i), **over}) for i in range(n)]


# ------------------------------------------------------------------ reader
def test_file_order_is_chronological():
    names = ["Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", "Monday-WorkingHours.pcap_ISCX.csv",
             "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
             "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv", "Wednesday-workingHours.pcap_ISCX.csv",
             "Tuesday-WorkingHours.pcap_ISCX.csv", "Friday-WorkingHours-Morning.pcap_ISCX.csv"]
    got = [n.split("-")[0] + ("-" + n.split("-")[2] if "Friday" in n or "Thursday" in n else "") for n in sorted(names, key=reader.file_order_key)]
    assert sorted(names, key=reader.file_order_key)[0].startswith("Monday")
    assert [n.split(".")[0] for n in sorted(names, key=reader.file_order_key)][-2:] == [
        "Friday-WorkingHours-Afternoon-PortScan", "Friday-WorkingHours-Afternoon-DDos"]
    assert len(got) == 8


def test_read_file_maps_names_and_cleans_values(tmp_path):
    rows = [make_row({"Flow Bytes/s": "Infinity", "Label": "Web Attack \x96 Brute Force"}),
            make_row({"Flow Packets/s": "NaN", "Source Port": "35396"})]
    write_csv(tmp_path / "Monday-WorkingHours.csv", rows)
    df = reader.read_file(tmp_path / "Monday-WorkingHours.csv", COLUMN_MAP)
    assert list(df.columns) == list(COLUMN_MAP) + ["source_file"]
    assert pd.isna(df.loc[0, "flow_bytes_per_s"]) and pd.isna(df.loc[1, "flow_packets_per_s"])   # Infinity/NaN -> thiếu
    assert str(df["source_port"].dtype) == "Int64" and df.loc[1, "source_port"] == 35396
    assert df.loc[0, "label"] == "Web Attack \x96 Brute Force"        # nhãn giữ nguyên, ETL sẽ chuẩn hóa
    assert df.loc[0, "source_file"] == "Monday-WorkingHours.csv"
    json.dumps(reader.to_records(df), allow_nan=False)                # không còn NaN/Infinity trong JSON


def test_read_file_rejects_machinelearningcsv(tmp_path):
    p = tmp_path / "x.csv"
    p.write_text("Destination Port,Flow Duration,Label\n80,1,BENIGN\n", encoding="latin-1")
    with pytest.raises(ValueError, match="GeneratedLabelledFlows"):
        reader.read_file(p, COLUMN_MAP)


# ------------------------------------------------------------------ API
@pytest.fixture
def clock():
    t = {"now": 100.0}
    fn = lambda: t["now"]  # noqa: E731
    fn.t = t
    return fn


def make_client(tmp_path, clock, n=10, rate=10, max_rps=1000):
    write_csv(tmp_path / "Monday-WorkingHours.csv", labelled("BENIGN", n))
    df = reader.load_replay_frame(tmp_path, COLUMN_MAP)
    app = api.create_app(api.ReplayStore(df, rate, clock=clock), KEY, max_rps=max_rps)
    return TestClient(app), {"X-API-Key": KEY}


def test_auth_required_but_health_is_open(tmp_path, clock):
    c, h = make_client(tmp_path, clock)
    assert c.get("/health").json() == {"status": "ok"}
    assert c.get("/v1/logs").status_code == 401
    assert c.get("/v1/logs", headers={"X-API-Key": "sai"}).status_code == 401
    assert c.get("/v1/logs", headers=h).status_code == 200


def test_replay_clock_releases_rows_over_time(tmp_path, clock):
    c, h = make_client(tmp_path, clock, n=10, rate=10)
    r = c.get("/v1/logs?after=0", headers=h).json()
    assert r["count"] == 0 and r["end"] is False                       # đồng hồ vừa khởi động
    clock.t["now"] += 0.5
    r = c.get("/v1/logs?after=0", headers=h).json()
    assert [x["seq"] for x in r["records"]] == [1, 2, 3, 4, 5] and r["next_after"] == 5
    clock.t["now"] += 10
    r = c.get("/v1/logs?after=5", headers=h).json()
    assert [x["seq"] for x in r["records"]] == [6, 7, 8, 9, 10] and r["end"] is True


def test_pagination_has_no_gaps_or_duplicates(tmp_path, clock):
    c, h = make_client(tmp_path, clock, n=10, rate=0)
    seen, after = [], 0
    while True:
        r = c.get(f"/v1/logs?after={after}&limit=3", headers=h).json()
        seen += [x["seq"] for x in r["records"]]
        after = r["next_after"]
        if r["end"]:
            break
    assert seen == list(range(1, 11))
    assert c.get("/v1/logs?after=10", headers=h).json()["count"] == 0   # sau seq cuối: rỗng, không lỗi


def test_record_has_all_columns_and_json_safe_values(tmp_path, clock):
    c, h = make_client(tmp_path, clock, n=2, rate=0)
    rec = c.get("/v1/logs", headers=h).json()["records"][0]
    assert set(COLUMN_MAP) | {"seq", "source_file"} == set(rec)
    assert isinstance(rec["source_port"], int) and rec["source_ip"] == "192.168.10.12"


def test_limit_is_validated(tmp_path, clock):
    c, h = make_client(tmp_path, clock, rate=0)
    assert c.get("/v1/logs?limit=0", headers=h).status_code == 422
    assert c.get(f"/v1/logs?limit={api.MAX_LIMIT + 1}", headers=h).status_code == 422
    assert c.get("/v1/logs?after=-1", headers=h).status_code == 422


def test_rate_limit_returns_429_with_retry_after(tmp_path, clock):
    c, h = make_client(tmp_path, clock, rate=0, max_rps=2)
    codes = [c.get("/v1/stats", headers=h).status_code for _ in range(3)]
    assert codes == [200, 200, 429]
    assert c.get("/v1/stats", headers=h).headers.get("retry-after") == "1"


def test_stats(tmp_path, clock):
    c, h = make_client(tmp_path, clock, n=10, rate=10)
    assert c.get("/v1/stats", headers=h).json()["replay_started"] is False
    c.get("/v1/logs", headers=h)
    clock.t["now"] += 0.35
    s = c.get("/v1/stats", headers=h).json()
    assert s["total"] == 10 and s["released"] == 3 and s["replay_started"] is True


# ------------------------------------------------------------------ tạo mẫu phát lại
def test_replay_sample_quotas_order_and_rare_labels(tmp_path):
    rows1 = labelled("BENIGN", 100) + labelled("Bot", 5, start=1000)
    rows2 = labelled("BENIGN", 100, start=2000) + labelled("DDoS", 50, start=3000) + labelled("Heartbleed", 2, start=4000)
    write_csv(tmp_path / "Friday-WorkingHours-Morning.csv", rows1)
    write_csv(tmp_path / "Friday-WorkingHours-Afternoon-DDos.csv", rows2)
    out, header = make_replay_sample.build_sample(tmp_path, benign_quota=20, plan={"bot": None, "heartbleed": None, "ddos": 10})
    lab = next(c for c in out.columns if c.strip() == "Label")
    port = next(c for c in out.columns if c.strip() == "Source Port")
    labels = out[lab].map(make_replay_sample.norm).value_counts().to_dict()
    assert labels["bot"] == 5 and labels["heartbleed"] == 2           # nhãn hiếm: lấy hết
    assert labels["ddos"] == 10                                         # nhãn lớn: đúng hạn ngạch
    assert 15 <= labels["benign"] <= 20                                 # Benign: lấy cách đều
    assert out.loc[out[lab] == "DDoS", port].astype(int).tolist() == list(range(4000, 4010))  # đoạn LIÊN TỤC từ đầu đợt
    assert out[lab].iloc[0] == "BENIGN" and out[lab].iloc[-1] == "Heartbleed"                 # giữ thứ tự file
    assert [h.strip() for h in header] == NAMES


# ------------------------------------------------------------------ collector (không cần MySQL thật)
class FakeCursor:
    def __init__(self, rowcount):
        self.rowcount, self.log = rowcount, []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def executemany(self, sql, rows):
        self.log.append(("many", len(rows)))

    def execute(self, sql, params=None):
        self.log.append(("exec", sql.split()[0]))


class FakeConn:
    def __init__(self, rowcount):
        self.cur, self.committed, self.rolled_back = FakeCursor(rowcount), False, False

    def cursor(self):
        return self.cur

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True


def test_insert_batch_commits_when_cursor_matches():
    conn = FakeConn(rowcount=1)
    collector.insert_batch(conn, "s", 0, 2, [{"a": 1, "seq": 1}, {"a": 2, "seq": 2}], ["a"])
    assert conn.committed and not conn.rolled_back and ("many", 2) in conn.cur.log


def test_insert_batch_rolls_back_on_cursor_conflict():
    conn = FakeConn(rowcount=0)
    with pytest.raises(collector.StateConflict):
        collector.insert_batch(conn, "s", 0, 2, [{"a": 1}], ["a"])
    assert conn.rolled_back and not conn.committed
