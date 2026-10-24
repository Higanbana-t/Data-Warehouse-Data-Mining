"""
Huấn luyện và so sánh các mô hình phân loại traffic mạng.

Chạy từ THƯ MỤC GỐC dự án (sau khi ETL đã tạo Parquet sạch):
    python -m src.mining.train                              # cả 2 bài toán, cả 3 mô hình
    python -m src.mining.train --task binary --models dt rf # chỉ nhị phân, bỏ SVM
    python -m src.mining.train --split-mode time_block      # chia theo thời gian (khắt khe hơn)
    python -m src.mining.train --drop-features dst_port     # thử nghiệm bỏ cổng đích
    python -m src.mining.train --max-rows 300000            # chạy thử nhanh / máy yếu

Bài toán:
    binary     : Benign (0) hay Attack (1)
    multiclass : nhóm tấn công (attack_group: Benign/DDoS/PortScan/WebAttack/Botnet/Other)
Kết quả: models/*.joblib, reports/tables/*.csv, reports/figures/*.png
"""
import argparse
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC, LinearSVC
from sklearn.tree import DecisionTreeClassifier

from src.mining import evaluate as ev
from src.mining import features as ft
from src.utils.config import load_config
from src.utils.logger import get_logger

log = get_logger("mining")
MODEL_NAMES = {"dt": "DecisionTree", "rf": "RandomForest", "svm": "SVM"}


def build_pipeline(name, cfg):
    mc, rs = cfg["mining"]["models"], cfg["mining"]["random_state"]
    imputer = ("imputer", SimpleImputer(strategy="median", keep_empty_features=True))
    if name == "dt":
        p = mc["dt"]
        est = DecisionTreeClassifier(max_depth=p["max_depth"], min_samples_leaf=p["min_samples_leaf"],
                                     class_weight="balanced", random_state=rs)
        return Pipeline([imputer, ("model", est)])
    if name == "rf":
        p = mc["rf"]
        est = RandomForestClassifier(n_estimators=p["n_estimators"], max_depth=p["max_depth"],
                                     min_samples_leaf=p["min_samples_leaf"], class_weight="balanced_subsample",
                                     n_jobs=-1, random_state=rs)
        return Pipeline([imputer, ("model", est)])
    if name == "svm":  # SVM cần chuẩn hóa thang đo
        p = mc["svm"]
        if p["kernel"] == "rbf":
            est = SVC(kernel="rbf", C=p["C"], class_weight="balanced", cache_size=1000, random_state=rs)
        else:
            est = LinearSVC(C=p["C"], class_weight="balanced", dual=False, max_iter=5000, random_state=rs)
        return Pipeline([imputer, ("scaler", StandardScaler()), ("model", est)])
    raise ValueError(name)


def importance_of(pipe, feats):
    est = pipe.named_steps["model"]
    if hasattr(est, "feature_importances_"):
        return pd.Series(est.feature_importances_, index=feats)
    if hasattr(est, "coef_"):  # SVM tuyến tính: trung bình |hệ số| trên đặc trưng đã chuẩn hóa
        return pd.Series(np.abs(est.coef_).mean(axis=0), index=feats)
    return None


def score_of(pipe, X):
    est = pipe.named_steps["model"]
    if hasattr(est, "predict_proba"):
        return pipe.predict_proba(X)[:, 1]
    return pipe.decision_function(X)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--task", choices=["binary", "multiclass", "both"], default="both")
    ap.add_argument("--models", nargs="+", choices=list(MODEL_NAMES), default=list(MODEL_NAMES))
    ap.add_argument("--split-mode", choices=["stratified", "time_block"])
    ap.add_argument("--drop-features", nargs="*", default=[], help="loại thêm các đặc trưng, vd: dst_port")
    ap.add_argument("--max-rows", type=int, help="giới hạn tổng số dòng đọc (chạy thử / máy yếu)")
    ap.add_argument("--tag", help="hậu tố tên file kết quả (mặc định tự suy ra từ các tùy chọn)")
    args = ap.parse_args()

    cfg = load_config(args.config)
    if args.split_mode:
        cfg["mining"]["split_mode"] = args.split_mode
    m = cfg["mining"]
    tag = args.tag if args.tag is not None else "_".join(
        ([] if m["split_mode"] == "stratified" else ["timeblock"]) +
        (["no_" + "_".join(args.drop_features)] if args.drop_features else []))
    sfx = f"_{tag}" if tag else ""
    tables, figs, models_dir = (Path(cfg["paths"][k]) for k in ("tables_dir", "figures_dir", "models_dir"))
    for d in (tables, figs, models_dir):
        d.mkdir(parents=True, exist_ok=True)

    # ---- 1. dữ liệu
    feats0 = ft.candidate_features(cfg, drop=args.drop_features)
    log.info("Đọc dữ liệu sạch (%d đặc trưng ứng viên)...", len(feats0))
    df = ft.load_dataset(cfg, feats0, log, args.max_rows)
    log.info("Tổng %d dòng. Chia %s (test_size=%.2f)", len(df), m["split_mode"], m["test_size"])
    train, test = ft.split_dataset(df, cfg, log)
    del df
    train_full_n = len(train)
    train = ft.balance_train(train, cfg)
    log.info("Train: %d -> %d dòng sau khi giảm mẫu | Test: %d dòng (phân bố tự nhiên)", train_full_n, len(train), len(test))
    feats, finfo = ft.select_features(train, feats0, cfg, log)

    split_summary = (pd.concat([train["label_raw"].value_counts().rename("n_train"),
                                test["label_raw"].value_counts().rename("n_test")], axis=1)
                     .fillna(0).astype(int).rename_axis("label_raw").reset_index())
    split_summary.to_csv(tables / f"split_summary{sfx}.csv", index=False, encoding="utf-8-sig")
    Xtr, Xte = train[feats], test[feats]

    # ---- 2. huấn luyện từng bài toán x mô hình
    tasks = ["binary", "multiclass"] if args.task == "both" else [args.task]
    for task in tasks:
        if task == "binary":
            ytr, yte, classes, disp = train["is_attack"].to_numpy(), test["is_attack"].to_numpy(), [0, 1], ["Benign", "Attack"]
        else:
            tgt = m["multiclass_target"]
            ytr, yte = train[tgt].to_numpy(), test[tgt].to_numpy()
            classes = disp = sorted(set(ytr) | set(yte))
        rows = []
        for name in args.models:
            pipe = build_pipeline(name, cfg)
            sub_idx = None
            if name == "svm":  # SVM chậm với dữ liệu lớn: huấn luyện trên tập con
                n_rows = m["models"]["svm"]["rbf_train_rows" if m["models"]["svm"]["kernel"] == "rbf" else "train_rows"]
                sub = ft.cap_per_label(train, n_rows, m["random_state"])
                Xfit, yfit = sub[feats], (sub["is_attack"].to_numpy() if task == "binary" else sub[m["multiclass_target"]].to_numpy())
            else:
                Xfit, yfit = Xtr, ytr
            log.info("[%s | %s] huấn luyện trên %d dòng...", task, MODEL_NAMES[name], len(Xfit))
            t0 = time.perf_counter()
            pipe.fit(Xfit, yfit)
            t_fit = time.perf_counter() - t0
            t0 = time.perf_counter()
            pred = pipe.predict(Xte)
            t_pred = time.perf_counter() - t0
            met = (ev.binary_metrics(yte, pred, score_of(pipe, Xte)) if task == "binary"
                   else ev.multiclass_metrics(yte, pred))
            met.update({"model": MODEL_NAMES[name], "task": task, "n_train": len(Xfit), "n_test": len(Xte),
                        "train_seconds": round(t_fit, 1), "predict_seconds": round(t_pred, 1)})
            rows.append(met)
            key = f"{task}_{name}{sfx}"
            ev.per_class_report(yte, pred, classes).assign(class_name=lambda d: d["class"].map(
                dict(zip(map(str, classes), disp))).fillna(d["class"])).to_csv(
                tables / f"classification_report_{key}.csv", index=False, encoding="utf-8-sig")
            ev.plot_confusion(yte, pred, classes, f"{MODEL_NAMES[name]} - {task}", figs / f"confusion_{key}.png") \
                if task == "multiclass" else ev.plot_confusion(
                np.where(yte == 1, "Attack", "Benign"), np.where(pred == 1, "Attack", "Benign"),
                ["Benign", "Attack"], f"{MODEL_NAMES[name]} - binary", figs / f"confusion_{key}.png")
            imp = importance_of(pipe, feats)
            if imp is not None:
                imp.sort_values(ascending=False).rename("importance").rename_axis("feature").reset_index().to_csv(
                    tables / f"feature_importance_{key}.csv", index=False, encoding="utf-8-sig")
                ev.plot_importance(imp, f"Top đặc trưng - {MODEL_NAMES[name]} ({task})", figs / f"importance_{key}.png")
            joblib.dump({"pipeline": pipe, "features": feats, "classes": classes, "task": task,
                         "split_mode": m["split_mode"]}, models_dir / f"{key}_v1.joblib")
            log.info("  -> %s", ", ".join(f"{k}={float(v):.4f}" for k, v in met.items()
                                       if k in ("accuracy", "f1_attack", "recall_attack", "fpr", "roc_auc",
                                                "macro_f1", "weighted_f1")))
        cmp_df = pd.DataFrame(rows)
        lead = ["model", "task"]
        cmp_df = cmp_df[lead + [c for c in cmp_df.columns if c not in lead]]
        cmp_df.to_csv(tables / f"model_comparison_{task}{sfx}.csv", index=False, encoding="utf-8-sig")
        shown = ["f1_attack", "recall_attack", "precision_attack", "roc_auc"] if task == "binary" \
            else ["macro_f1", "weighted_f1", "accuracy"]
        ev.plot_model_comparison(cmp_df, shown, f"So sánh mô hình - {task} ({m['split_mode']})",
                                 figs / f"model_comparison_{task}{sfx}.png")

    (tables / f"mining_run_info{sfx}.json").write_text(json.dumps({
        "split_mode": m["split_mode"], "test_size": m["test_size"], "random_state": m["random_state"],
        "n_train_before_balance": train_full_n, "n_train_used": len(train), "n_test": len(test),
        "n_features": len(feats), "drop_features": args.drop_features, "feature_info": finfo,
        "sklearn": sklearn.__version__, "pandas": pd.__version__}, ensure_ascii=False, indent=2), encoding="utf-8")
    log.info("HOÀN THÀNH. Kết quả trong %s và %s", tables, figs)


if __name__ == "__main__":
    main()