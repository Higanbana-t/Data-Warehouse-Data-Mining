"""Kiểm thử các hàm Data Mining (dữ liệu tổng hợp nhỏ, không cần Parquet). Chạy: python -m pytest tests -v"""
import numpy as np
import pandas as pd
import pytest

from src.mining import evaluate as ev
from src.mining import features as ft
from src.mining.business_questions import (build_ip_profiles, botlike_distance, choose_k_and_cluster, loo_eval,
                                           scale_profiles)
from src.utils.logger import get_logger

log = get_logger("test")


@pytest.fixture
def cfg():
    return {"mining": {"random_state": 0, "split_mode": "stratified", "test_size": 0.3, "test_max_rows": None,
                       "train_benign_cap": 100, "train_cap_per_label": 30, "corr_threshold": 0.98}}


def toy_df(n_benign=400, n_dos=60, n_rare=10):
    rng = np.random.default_rng(1)
    labels = ["BENIGN"] * n_benign + ["DoS Hulk"] * n_dos + ["Heartbleed"] * n_rare
    n = len(labels)
    ts = pd.Timestamp("2017-07-05 09:00") + pd.to_timedelta(rng.integers(0, 480, n), unit="m")
    a = rng.normal(size=n)
    return pd.DataFrame({"label_raw": labels, "attack_group": ["Benign" if l == "BENIGN" else "Other" for l in labels],
                         "flow_start_ts": ts, "f1": a, "f2": a * 2 + 1e-6 * rng.normal(size=n),   # tương quan ~1 với f1
                         "f3": rng.normal(size=n), "f_const": 1.0})


def test_split_stratified_keeps_every_label(cfg):
    tr, te = ft.split_dataset(toy_df(), cfg, log)
    assert set(tr["label_raw"]) == set(te["label_raw"]) == {"BENIGN", "DoS Hulk", "Heartbleed"}
    assert len(tr) + len(te) == 470


def test_split_stratified_label_with_single_row_goes_to_train(cfg):
    df = pd.concat([toy_df(), toy_df().iloc[:1].assign(label_raw="Rare1", attack_group="Other")])
    tr, te = ft.split_dataset(df, cfg, log)
    assert "Rare1" in set(tr["label_raw"]) and "Rare1" not in set(te["label_raw"])


def test_split_time_block_test_is_later_than_train(cfg):
    cfg["mining"]["split_mode"] = "time_block"
    tr, te = ft.split_dataset(toy_df(), cfg, log)
    for label in set(tr["label_raw"]):
        assert tr.loc[tr.label_raw == label, "flow_start_ts"].max() <= te.loc[te.label_raw == label, "flow_start_ts"].min()


def test_balance_train_caps_labels(cfg):
    out = ft.balance_train(toy_df(), cfg)
    c = out["label_raw"].value_counts()
    assert c["BENIGN"] == 100 and c["DoS Hulk"] == 30 and c["Heartbleed"] == 10  # lớp nhỏ giữ nguyên


def test_select_features_drops_constant_and_correlated(cfg):
    keep, info = ft.select_features(toy_df(), ["f1", "f2", "f3", "f_const"], cfg, log)
    assert "f_const" in info["dropped_constant"] and "f_const" not in keep
    assert set(keep) == {"f1", "f3"} and "f2" in info["dropped_correlated"]


def test_candidate_features_excludes_meta_and_ports(tmp_path):
    import pyarrow as pa
    import pyarrow.parquet as pq
    cols = {f"x{i}": [1.0] for i in range(25)}
    cols.update({"src_ip": ["1.1.1.1"], "label_raw": ["BENIGN"], "src_port": [5], "dst_port": [80], "flow_id": ["a"]})
    pq.write_table(pa.table(cols), tmp_path / "a.parquet")
    cfg = {"paths": {"clean_dir": str(tmp_path)}, "mining": {"exclude_features": ["src_port"]}}
    feats = ft.candidate_features(cfg)
    assert "dst_port" in feats and "src_port" not in feats and "src_ip" not in feats and "flow_id" not in feats
    assert "dst_port" not in ft.candidate_features(cfg, drop=["dst_port"])


def test_candidate_features_fails_when_no_features(tmp_path):
    import pyarrow as pa
    import pyarrow.parquet as pq
    pq.write_table(pa.table({"flow_duration_us": [1], "label_raw": ["BENIGN"]}), tmp_path / "a.parquet")
    with pytest.raises(ValueError, match="keep_all_features"):
        ft.candidate_features({"paths": {"clean_dir": str(tmp_path)}, "mining": {}})


def test_binary_metrics():
    y = np.array([0, 0, 0, 0, 1, 1, 1, 1])
    p = np.array([0, 0, 0, 1, 1, 1, 1, 0])
    m = ev.binary_metrics(y, p, np.array([.1, .2, .1, .6, .9, .8, .7, .4]))
    assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (3, 1, 1, 3)
    assert m["precision_attack"] == pytest.approx(0.75) and m["recall_attack"] == pytest.approx(0.75)
    assert m["fpr"] == pytest.approx(0.25) and m["roc_auc"] > 0.9


def test_binary_metrics_single_class_does_not_crash():
    m = ev.binary_metrics(np.zeros(5, dtype=int), np.zeros(5, dtype=int), np.zeros(5))
    assert np.isnan(m["roc_auc"]) and m["fpr"] == 0


def ip_flows():
    rows = []
    for ip, n, port_n, grp in [("10.0.0.1", 60, 1, "Benign"), ("10.0.0.2", 80, 3, "Botnet"), ("10.0.0.3", 5, 1, "Benign")]:
        for i in range(n):
            rows.append({"src_ip": ip, "dst_ip": f"9.9.9.{i % 4}", "dst_port": 80 + i % port_n, "protocol_number": 6,
                         "flow_duration_us": 1000 + i, "total_bytes": 500, "flow_packets_per_s": 10.0,
                         "syn_flag_count": int(i % 2 == 0), "rst_flag_count": 0, "attack_group": grp})
    return pd.DataFrame(rows)


def test_build_ip_profiles():
    prof = build_ip_profiles(ip_flows(), min_flows=50)
    assert set(prof["src_ip"]) == {"10.0.0.1", "10.0.0.2"}  # 10.0.0.3 chỉ có 5 flow nên bị loại
    r = prof.set_index("src_ip").loc["10.0.0.2"]
    assert r["n_flows"] == 80 and r["n_dst_ip"] == 4 and r["n_dst_port"] == 3
    assert r["bot_flows"] == 80 and r["attack_share"] == 1.0 and r["syn_ratio"] == pytest.approx(0.5)


def test_botlike_distance_and_loo():
    rng = np.random.default_rng(0)
    Z = np.vstack([rng.normal(0, 1, (200, 3)), rng.normal(8, 0.2, (4, 3))])  # 4 IP botnet tụ lại, xa phần còn lại
    mask = np.r_[np.zeros(200, bool), np.ones(4, bool)]
    d = botlike_distance(Z, mask)
    assert d[mask].max() < d[~mask].min()
    loo = loo_eval(Z, mask)
    assert len(loo) == 4 and (loo["rank"] <= 4).all() and loo["percentile"].max() < 0.05
    assert loo_eval(Z, np.r_[np.ones(2, bool), np.zeros(202, bool)]) is None  # < 3 IP botnet -> không đánh giá


def test_cluster_choice_finds_two_blobs():
    rng = np.random.default_rng(0)
    Z = np.vstack([rng.normal(0, 0.3, (100, 2)), rng.normal(6, 0.3, (100, 2))])
    labels, k, sil = choose_k_and_cluster(Z, 2, 5, 0)
    assert k == 2 and len(set(labels[:100])) == 1 and set(labels[:100]) != set(labels[100:])


def test_scale_profiles_shape():
    prof = build_ip_profiles(ip_flows(), min_flows=50)
    assert scale_profiles(prof).shape == (2, 9)