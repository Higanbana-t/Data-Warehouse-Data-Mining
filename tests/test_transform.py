"""Kiểm thử các hàm làm sạch. Chạy từ thư mục gốc dự án:  python -m pytest tests -v"""
import pandas as pd
import pytest

from src.etl.transform import (attack_group_of, canonical_ip, clean_flows, make_time_key, normalize_label,
                               parse_timestamps)
from src.utils.config import load_config

AFTERNOON = [1, 2, 3, 4, 5, 6, 7]


@pytest.fixture
def cfg():
    return {"time": {"afternoon_hours": AFTERNOON, "business_start": 8, "business_end": 17,
                     "date_min": "2017-07-03", "date_max": "2017-07-07"},
            "sampling": {"enabled": False}}


def raw_row(**over):
    """Dòng thật đầu tiên người dùng cung cấp (SSH, BENIGN), cột đã strip tên."""
    row = {"Flow ID": "192.168.10.12-192.168.10.50-35396-22-6", "Source IP": "192.168.10.12", "Source Port": 35396,
           "Destination IP": "192.168.10.50", "Destination Port": 22, "Protocol": 6, "Timestamp": "7/7/2017 1:00",
           "Flow Duration": 1266342, "Total Fwd Packets": 41, "Total Backward Packets": 44,
           "Total Length of Fwd Packets": 2664, "Total Length of Bwd Packets": 6954,
           "Flow Bytes/s": 7595.10464, "Flow Packets/s": 67.12246771, "Average Packet Size": 113.1529412,
           "FIN Flag Count": 0, "SYN Flag Count": 0, "RST Flag Count": 0, "PSH Flag Count": 1,
           "ACK Flag Count": 0, "Label": "BENIGN"}
    row.update(over)
    return row


def test_timestamp_afternoon_and_morning():
    ts, pm = parse_timestamps(pd.Series(["7/7/2017 1:00", "3/7/2017 8:55", "7/7/2017 12:30", "6/7/2017 11:59"]), AFTERNOON)
    assert list(ts.dt.strftime("%Y-%m-%d %H:%M")) == ["2017-07-07 13:00", "2017-07-03 08:55",
                                                      "2017-07-07 12:30", "2017-07-06 11:59"]
    assert pm == 1


def test_timestamp_is_day_first():
    ts, _ = parse_timestamps(pd.Series(["3/7/2017 9:00"]), AFTERNOON)
    assert ts.iloc[0].month == 7 and ts.iloc[0].day == 3  # 3 tháng 7, KHÔNG phải 7 tháng 3


def test_timestamp_garbage_becomes_nat():
    ts, _ = parse_timestamps(pd.Series(["abc", "99/99/2017 1:00"]), AFTERNOON)
    assert ts.isna().all()


def test_make_time_key():
    ts = pd.Series(pd.to_datetime(["2017-07-07 13:05"]))
    assert make_time_key(ts).iloc[0] == 201707071305


def test_normalize_label_fixes_bad_dash():
    s = pd.Series(["Web Attack \x96 Brute Force", "BENIGN", "Web Attack \ufffd XSS"])
    assert list(normalize_label(s)) == ["Web Attack - Brute Force", "BENIGN", "Web Attack - XSS"]


@pytest.mark.parametrize("label,group", [
    ("BENIGN", "Benign"), ("DDoS", "DDoS"), ("PortScan", "PortScan"), ("Bot", "Botnet"),
    ("Web Attack - Sql Injection", "WebAttack"), ("DoS Hulk", "Other"), ("FTP-Patator", "Other"),
    ("Infiltration", "Other"), ("Heartbleed", "Other")])
def test_attack_group(label, group):
    assert attack_group_of(label) == group


def test_canonical_ip():
    assert canonical_ip(" 192.168.10.12 ") == "192.168.10.12"
    assert canonical_ip("fe80:0:0:0:250:56ff:fe8e:2cd8") == "fe80::250:56ff:fe8e:2cd8"
    assert canonical_ip("abc") is None and canonical_ip("300.1.1.1") is None


def test_clean_good_row(cfg):
    df, st = clean_flows(pd.DataFrame([raw_row()]), cfg, "x.csv")
    assert st["rows_out"] == 1 and st["rows_read"] == 1
    r = df.iloc[0]
    assert str(r.flow_start_ts) == "2017-07-07 13:00:00"
    assert r.total_bytes == 2664 + 6954 and r.total_packets == 85
    assert r.attack_group == "Benign" and not r.is_attack and r.protocol_number == 6


def test_clean_drops_bad_rows(cfg):
    rows = [raw_row(),
            raw_row(**{"Source IP": "abc"}),                      # IP sai
            raw_row(**{"Timestamp": "9/9/2017 1:00"}),            # ngoài khoảng ngày
            raw_row(**{"Flow Duration": -5}),                     # thời lượng âm
            raw_row(**{"Label": None}),                           # thiếu nhãn
            raw_row(),                                            # trùng hoàn toàn
            raw_row(**{"Flow Bytes/s": float("inf")})]            # Infinity: GIỮ dòng, đổi thành NULL
    df, st = clean_flows(pd.DataFrame(rows), cfg, "x.csv")
    assert st["drop_invalid_ip"] == 1 and st["drop_out_of_range_date"] == 1
    assert st["drop_negative_or_missing_measure"] == 1 and st["drop_null_key"] == 1
    assert st["drop_duplicates"] == 1
    assert st["rows_out"] == 2
    assert df["flow_bytes_per_s"].isna().sum() == 1


# ---------------------------------------------------------------- đặc trưng bổ sung cho Data Mining
def test_feature_name_on_real_header():
    from src.etl.transform import RAW_TO_CLEAN, feature_name
    assert feature_name("Flow IAT Mean") == "flow_iat_mean"
    assert feature_name("Fwd Packets/s") == "fwd_packets_per_s"
    assert feature_name("Bwd Avg Bytes/Bulk") == "bwd_avg_bytes_per_bulk"
    assert feature_name("Init_Win_bytes_forward") == "init_win_bytes_forward"
    assert feature_name("Down/Up Ratio") == "down_per_up_ratio"
    # tên đặc trưng không được trùng với 21 cột chính
    extras = ["Fwd Packet Length Max", "Avg Fwd Segment Size", "Packet Length Mean", "Subflow Fwd Bytes", "Idle Max"]
    assert not {feature_name(c) for c in extras} & set(RAW_TO_CLEAN.values())


def test_clean_keeps_extra_features_and_same_rows(cfg):
    rows = [raw_row(**{"Flow IAT Mean": 7595.1, "Fwd Header Length": 1328, "Fwd Header Length.1": 1328}),
            raw_row(**{"Flow IAT Mean": float("inf"), "Fwd Header Length": 1, "Fwd Header Length.1": 1,
                       "Source Port": 1}),
            raw_row(**{"Flow IAT Mean": 7595.1, "Fwd Header Length": 1328, "Fwd Header Length.1": 1328})]  # trùng dòng 1
    with_extra, _ = clean_flows(pd.DataFrame(rows), cfg, "x.csv")
    base_only, _ = clean_flows(pd.DataFrame(rows)[[c for c in rows[0] if c not in
                                                   ("Flow IAT Mean", "Fwd Header Length", "Fwd Header Length.1")]],
                               cfg, "x.csv")
    assert len(with_extra) == len(base_only) == 2          # tập dòng KHÔNG phụ thuộc vào việc giữ đặc trưng
    assert "flow_iat_mean" in with_extra.columns and "fwd_header_length" in with_extra.columns
    assert "fwd_header_length_1" not in with_extra.columns  # cột lặp bị bỏ
    assert with_extra["flow_iat_mean"].isna().sum() == 1    # Infinity -> NaN
    assert str(with_extra["flow_iat_mean"].dtype) == "float32"