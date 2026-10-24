"""
Trả lời câu hỏi nghiệp vụ 1 và 2 bằng khai phá dữ liệu.

    python -m src.mining.business_questions               # chạy cả q1 và q2
    python -m src.mining.business_questions --only q1

Q1: Đặc trưng nào phân biệt rõ nhất traffic hợp lệ (kể cả lúc lưu lượng tăng cao) và tấn công DDoS?
    -> xếp hạng đặc trưng bằng 3 cách: độ tách biệt từng đặc trưng (AUC), permutation importance của Random Forest,
       và cây quyết định nông (độ sâu 3) cho luật dễ đọc. Chạy với 2 phạm vi Benign: 'all' (mọi traffic hợp lệ)
       và 'busy' (chỉ traffic hợp lệ trong các phút có lưu lượng cao nhất).
Q2: IP nào có hành vi giống botnet nhất?
    -> lập hồ sơ hành vi theo IP nguồn (KHÔNG dùng nhãn), phân cụm KMeans, xếp hạng theo khoảng cách tới hồ sơ trung
       bình của các IP đã biết là botnet; kiểm chứng bằng leave-one-out. Nhãn chỉ dùng để diễn giải và đánh giá.
"""
import argparse
import json
import os

from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import f1_score, roc_auc_score, silhouette_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier, export_text

from src.mining import features as ft
from src.utils.config import load_config
from src.utils.logger import get_logger

log = get_logger("bq")# Tắt threadpoolctl để tránh lỗi đọc đường dẫn tiếng Việt trên Windows
os.environ["SCIPY_USE_MKL"] = "FF"

# =============================================================== Q1
def busy_minutes(cfg, quantile):
    """Tập các phút có số flow >= phân vị `quantile` (phút lưu lượng cao)."""
    ts = pd.concat([pd.read_parquet(f, columns=["flow_start_ts"])["flow_start_ts"] for f in ft.clean_files(cfg)])
    counts = ts.dt.floor("min").value_counts()
    thr = counts.quantile(quantile)
    return set(counts[counts >= thr].index), float(thr)


def load_q1_samples(cfg, feats, busy, per_file):
    rs = cfg["mining"]["random_state"]
    ben_all, ben_busy, ddos = [], [], []
    for f in ft.clean_files(cfg):
        d = pd.read_parquet(f, columns=feats + ["attack_group", "flow_start_ts"],
                            filters=[("attack_group", "in", ["Benign", "DDoS"])])
        if d.empty:
            continue
        d[feats] = d[feats].astype("float32")
        is_ben, is_busy = d["attack_group"] == "Benign", d["flow_start_ts"].dt.floor("min").isin(busy)
        for lst, mask in ((ben_all, is_ben), (ben_busy, is_ben & is_busy), (ddos, ~is_ben)):
            part = d[mask]
            if len(part):
                lst.append(part.sample(n=min(len(part), per_file), random_state=rs))
    cat = lambda lst: pd.concat(lst, ignore_index=True) if lst else pd.DataFrame(columns=feats)
    return cat(ben_all), cat(ben_busy), cat(ddos)


def make_scope(benign, ddos, per_class, rs):
    b = benign.sample(n=min(len(benign), per_class), random_state=rs)
    d = ddos.sample(n=min(len(ddos), per_class), random_state=rs)
    out = pd.concat([b, d], ignore_index=True)
    out["y"] = np.r_[np.zeros(len(b), dtype=int), np.ones(len(d), dtype=int)]
    return out


def rank_features(df, feats, cfg):
    """df có cột y (0 = Benign, 1 = DDoS). Trả về (bảng xếp hạng, luật cây nông, chỉ số mô hình)."""
    rs = cfg["mining"]["random_state"]
    X, y = df[feats], df["y"].to_numpy()
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, stratify=y, random_state=rs)
    keep, _ = ft.select_features(Xtr, feats, cfg, log)
    med = Xtr[keep].median()
    Xtr_i, Xte_i = Xtr[keep].fillna(med), Xte[keep].fillna(med)

    # 1) độ tách biệt từng đặc trưng (AUC đơn biến) và trung vị từng lớp
    rows = []
    Xall = X[keep].fillna(med)
    for c in keep:
        v = Xall[c]
        auc = roc_auc_score(y, v) if v.nunique() > 1 else 0.5
        mb, md = float(v[y == 0].median()), float(v[y == 1].median())
        rows.append({"feature": c, "univariate_auc": auc, "separability": max(auc, 1 - auc),
                     "direction": "DDoS cao hơn" if md > mb else "DDoS thấp hơn" if md < mb else "như nhau",
                     "median_benign": mb, "median_ddos": md})
    rk = pd.DataFrame(rows)

    # 2) Random Forest + permutation importance trên tập test
    rf = RandomForestClassifier(n_estimators=100, max_depth=12, min_samples_leaf=3, class_weight="balanced",
                                n_jobs=-1, random_state=rs).fit(Xtr_i, ytr)
    pred = rf.predict(Xte_i)
    sub = np.random.default_rng(rs).choice(len(Xte_i), size=min(10_000, len(Xte_i)), replace=False)
    pi = permutation_importance(rf, Xte_i.iloc[sub], yte[sub], scoring="f1", n_repeats=3, random_state=rs, n_jobs=-1)
    rk["perm_importance_mean"], rk["perm_importance_std"] = pi.importances_mean, pi.importances_std
    rk["rf_impurity_importance"] = rf.feature_importances_
    rk = rk.sort_values("perm_importance_mean", ascending=False).reset_index(drop=True)
    rk.insert(0, "rank", np.arange(1, len(rk) + 1))

    # 3) cây quyết định nông -> luật dễ đọc
    dt = DecisionTreeClassifier(max_depth=3, min_samples_leaf=20, class_weight="balanced", random_state=rs).fit(Xtr_i, ytr)
    rules = export_text(dt, feature_names=list(keep))
    metrics = {"rf_f1": float(f1_score(yte, pred)),
               "rf_auc": float(roc_auc_score(yte, rf.predict_proba(Xte_i)[:, 1])),
               "tree3_f1": float(f1_score(yte, dt.predict(Xte_i))), "n_benign": int((y == 0).sum()),
               "n_ddos": int((y == 1).sum()), "n_features_used": len(keep)}
    return rk, rules, metrics


def plot_top_features(df, rk, path, top=6):
    names = rk["feature"].head(top).tolist()
    d = df.sample(n=min(len(df), 20_000), random_state=0)
    fig, axes = plt.subplots(2, 3, figsize=(11, 6))
    for ax, name in zip(axes.ravel(), names):
        ax.boxplot([d.loc[d.y == 0, name].dropna(), d.loc[d.y == 1, name].dropna()], showfliers=False,
                   tick_labels=["Benign", "DDoS"])
        ax.set_yscale("symlog")
        ax.set_title(name, fontsize=9)
    fig.suptitle("Phân bố các đặc trưng quan trọng nhất: Benign và DDoS")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def run_q1(cfg, drop=()):
    q = cfg["mining"]["q1"]
    sfx = ("_no_" + "_".join(drop)) if drop else ""
    tables, figs = Path(cfg["paths"]["tables_dir"]), Path(cfg["paths"]["figures_dir"])
    tables.mkdir(parents=True, exist_ok=True)
    figs.mkdir(parents=True, exist_ok=True)
    feats = ft.candidate_features(cfg, drop=drop)
    busy, thr = busy_minutes(cfg, q["busy_quantile"])
    log.info("Q1: %d phút 'bận' (>= %.0f flow/phút, phân vị %.2f)", len(busy), thr, q["busy_quantile"])
    ben_all, ben_busy, ddos = load_q1_samples(cfg, feats, busy, per_file=max(q["per_class"], 60_000))
    if len(ddos) < 100:
        raise ValueError("Có quá ít flow DDoS trong dữ liệu để phân tích Q1.")
    summary = {"busy_minute_threshold_flows": thr, "n_busy_minutes": len(busy)}
    for scope, benign in (("all", ben_all), ("busy", ben_busy)):
        if len(benign) < 200:
            log.warning("Q1 [%s]: chỉ có %d flow Benign, bỏ qua phạm vi này.", scope, len(benign))
            continue
        df = make_scope(benign, ddos, q["per_class"], cfg["mining"]["random_state"])
        log.info("Q1 [%s]: %d Benign + %d DDoS", scope, int((df.y == 0).sum()), int((df.y == 1).sum()))
        rk, rules, met = rank_features(df, feats, cfg)
        rk.to_csv(tables / f"q1_feature_ranking_{scope}{sfx}.csv", index=False, encoding="utf-8-sig")
        (tables / f"q1_tree_rules_{scope}{sfx}.txt").write_text(
            f"Cây quyết định độ sâu 3 (Benign=0, DDoS=1), phạm vi Benign: {scope}\n"
            f"F1 trên tập test: {met['tree3_f1']:.4f}\n\n{rules}", encoding="utf-8")
        plot_top_features(df, rk, figs / f"q1_top_features_{scope}{sfx}.png")
        summary[scope] = met
        log.info("  RF F1=%.4f | top 5 (permutation): %s", met["rf_f1"], ", ".join(rk["feature"].head(5)))
    (tables / f"q1_summary{sfx}.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")


# =============================================================== Q2
PROFILE_COLS = ["n_flows", "n_dst_ip", "n_dst_port", "mean_duration_us", "mean_bytes", "median_pps",
                "syn_ratio", "rst_ratio", "tcp_share"]
LOG_COLS = ["n_flows", "n_dst_ip", "n_dst_port", "mean_duration_us", "mean_bytes", "median_pps"]


def build_ip_profiles(df, min_flows):
    """Hồ sơ hành vi theo IP nguồn. Cột nhãn (attack_flows, bot_flows) chỉ để diễn giải, không dùng để phân cụm."""
    d = df.assign(_syn=(df["syn_flag_count"] > 0), _rst=(df["rst_flag_count"] > 0),
                  _tcp=(df["protocol_number"] == 6), _atk=(df["attack_group"] != "Benign"),
                  _bot=(df["attack_group"] == "Botnet"))
    g = d.groupby("src_ip", observed=True)
    prof = pd.DataFrame({"n_flows": g.size(), "n_dst_ip": g["dst_ip"].nunique(), "n_dst_port": g["dst_port"].nunique(),
                         "mean_duration_us": g["flow_duration_us"].mean(), "mean_bytes": g["total_bytes"].mean(),
                         "median_pps": g["flow_packets_per_s"].median(), "syn_ratio": g["_syn"].mean(),
                         "rst_ratio": g["_rst"].mean(), "tcp_share": g["_tcp"].mean(),
                         "attack_flows": g["_atk"].sum(), "bot_flows": g["_bot"].sum()})
    prof = prof[prof["n_flows"] >= min_flows].copy()
    prof["median_pps"] = prof["median_pps"].fillna(prof["median_pps"].median())
    prof["attack_share"] = prof["attack_flows"] / prof["n_flows"]
    prof.index = prof.index.astype(str)
    return prof.rename_axis("src_ip").reset_index()


def scale_profiles(prof):
    X = prof[PROFILE_COLS].copy()
    X[LOG_COLS] = np.log1p(X[LOG_COLS].clip(lower=0))
    return StandardScaler().fit_transform(X)


def choose_k_and_cluster(Z, k_min, k_max, rs):
    n = len(Z)
    k_max = min(k_max, n - 1)
    if k_max < k_min:
        return np.zeros(n, dtype=int), 1, pd.DataFrame()
    idx = np.random.default_rng(rs).choice(n, size=min(5000, n), replace=False)
    res = []
    for k in range(k_min, k_max + 1):
        km = KMeans(n_clusters=k, n_init=10, random_state=rs).fit(Z[idx])
        res.append({"k": k, "silhouette": silhouette_score(Z[idx], km.labels_)})
    sil = pd.DataFrame(res)
    best = int(sil.loc[sil["silhouette"].idxmax(), "k"])
    return KMeans(n_clusters=best, n_init=10, random_state=rs).fit_predict(Z), best, sil


def botlike_distance(Z, bot_mask):
    """Khoảng cách tới hồ sơ trung bình của các IP botnet đã biết (nhỏ = giống botnet hơn)."""
    return np.linalg.norm(Z - Z[bot_mask].mean(axis=0), axis=1)


def loo_eval(Z, bot_mask):
    """Giấu từng IP botnet đi, dùng các IP botnet còn lại làm hồ sơ tham chiếu, xem IP bị giấu xếp hạng thứ mấy."""
    bots = np.flatnonzero(bot_mask)
    if len(bots) < 3:
        return None
    rows = []
    for b in bots:
        ref = bots[bots != b]
        cand = np.setdiff1d(np.arange(len(Z)), ref)  # mọi IP trừ các IP tham chiếu (gồm cả IP bị giấu)
        d = np.linalg.norm(Z[cand] - Z[ref].mean(axis=0), axis=1)
        rank = int((d < d[np.where(cand == b)[0][0]]).sum()) + 1
        rows.append({"held_out_index": int(b), "rank": rank, "n_candidates": len(cand), "percentile": rank / len(cand)})
    return pd.DataFrame(rows)


def run_q2(cfg):
    q = cfg["mining"]["q2"]
    rs = cfg["mining"]["random_state"]
    tables, figs = Path(cfg["paths"]["tables_dir"]), Path(cfg["paths"]["figures_dir"])
    tables.mkdir(parents=True, exist_ok=True)
    figs.mkdir(parents=True, exist_ok=True)
    cols = ["src_ip", "dst_ip", "dst_port", "protocol_number", "flow_duration_us", "total_bytes",
            "flow_packets_per_s", "syn_flag_count", "rst_flag_count", "attack_group"]
    df = pd.concat([pd.read_parquet(f, columns=cols) for f in ft.clean_files(cfg)], ignore_index=True)
    log.info("Q2: %d flow, lập hồ sơ theo IP nguồn (>= %d flow)...", len(df), q["min_flows"])
    prof = build_ip_profiles(df, q["min_flows"])
    del df
    if len(prof) < 10:
        raise ValueError(f"Chỉ có {len(prof)} IP đủ điều kiện; hạ mining.q2.min_flows trong config.yaml.")
    Z = scale_profiles(prof)
    prof["cluster"], k, sil = choose_k_and_cluster(Z, q["k_min"], q["k_max"], rs)
    bot_mask = (prof["bot_flows"] > 0).to_numpy()
    log.info("Q2: %d IP, k=%d cụm, %d IP có flow nhãn Botnet", len(prof), k, int(bot_mask.sum()))

    summary = {"n_ips": len(prof), "k": k, "n_known_bot_ips": int(bot_mask.sum())}
    prof["is_known_bot"] = bot_mask
    if bot_mask.any():
        prof["dist_to_bot_profile"] = botlike_distance(Z, bot_mask)
        prof["botlike_rank"] = prof["dist_to_bot_profile"].rank(method="min").astype(int)
        loo = loo_eval(Z, bot_mask)
        if loo is not None:
            loo.insert(0, "src_ip", prof["src_ip"].to_numpy()[loo["held_out_index"]])
            loo.drop(columns="held_out_index").to_csv(tables / "q2_loo_eval.csv", index=False, encoding="utf-8-sig")
            summary.update({"loo_median_percentile": float(loo["percentile"].median()),
                            "loo_in_top10pct": int((loo["percentile"] <= 0.10).sum()), "loo_n": len(loo),
                            "random_baseline_percentile": 0.5})
            log.info("Q2 leave-one-out: phân vị xếp hạng trung vị = %.3f (ngẫu nhiên ~0.5); %d/%d IP nằm top 10%%",
                     summary["loo_median_percentile"], summary["loo_in_top10pct"], summary["loo_n"])
        else:
            log.warning("Q2: chỉ có %d IP botnet (<3) nên bỏ qua kiểm chứng leave-one-out.", int(bot_mask.sum()))
    else:
        log.warning("Q2: không có flow nhãn Botnet; chỉ lập hồ sơ và phân cụm.")

    prof.sort_values("botlike_rank" if "botlike_rank" in prof else "n_flows",
                     ascending=("botlike_rank" in prof)).to_csv(tables / "q2_ip_profiles.csv", index=False,
                                                                encoding="utf-8-sig")
    if "botlike_rank" in prof:
        prof.nsmallest(50, "botlike_rank").to_csv(tables / "q2_botlike_ranking.csv", index=False, encoding="utf-8-sig")
    cl = (prof.groupby("cluster").agg(n_ips=("src_ip", "size"), flows=("n_flows", "sum"),
                                      attack_flows=("attack_flows", "sum"), bot_flows=("bot_flows", "sum"),
                                      **{f"mean_{c}": (c, "mean") for c in PROFILE_COLS if c != "n_flows"})
          .reset_index())
    cl["attack_share"] = cl["attack_flows"] / cl["flows"]
    cl.to_csv(tables / "q2_cluster_summary.csv", index=False, encoding="utf-8-sig")
    if len(sil):
        sil.to_csv(tables / "q2_silhouette.csv", index=False, encoding="utf-8-sig")

    xy = PCA(n_components=2, random_state=rs).fit_transform(Z)
    fig, ax = plt.subplots(figsize=(7, 5.5))
    sc = ax.scatter(xy[:, 0], xy[:, 1], c=prof["cluster"], cmap="tab10", s=10, alpha=0.6)
    if bot_mask.any():
        ax.scatter(xy[bot_mask, 0], xy[bot_mask, 1], marker="*", s=220, c="red", edgecolor="black", label="IP có flow Botnet")
        ax.legend()
    ax.set_title(f"Hồ sơ hành vi theo IP nguồn (KMeans k={k}, chiếu PCA)")
    ax.set_xlabel("PC1")
    ax.set_ylabel("PC2")
    fig.colorbar(sc, label="Cụm")
    fig.tight_layout()
    fig.savefig(figs / "q2_ip_clusters.png", dpi=150)
    plt.close(fig)
    (tables / "q2_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--only", nargs="*", choices=["q1", "q2"], default=["q1", "q2"])
    ap.add_argument("--drop-features", nargs="*", default=[], help="Q1: loại thêm đặc trưng, vd: dst_port protocol_number")
    args = ap.parse_args()
    cfg = load_config(args.config)
    if "q1" in args.only:
        run_q1(cfg, drop=args.drop_features)
    if "q2" in args.only:
        run_q2(cfg)
    log.info("HOÀN THÀNH.")


if __name__ == "__main__":
    main()