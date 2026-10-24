"""Chuẩn bị dữ liệu cho Data Mining: đọc Parquet sạch, chọn đặc trưng, chia train/test, giảm mẫu tập train."""
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
from sklearn.model_selection import train_test_split

# Cột định danh/nhãn: KHÔNG bao giờ dùng làm đặc trưng (tránh để mô hình "học thuộc" IP, thời điểm hay nhãn)
META_COLS = {"flow_id", "src_ip", "dst_ip", "flow_start_ts", "label_raw", "attack_group", "is_attack", "source_file"}


def clean_files(cfg):
    files = sorted(Path(cfg["paths"]["clean_dir"]).glob("*.parquet"))
    if not files:
        raise FileNotFoundError(f"Không có file Parquet trong {cfg['paths']['clean_dir']}; hãy chạy ETL trước.")
    return files


def candidate_features(cfg, drop=()):
    """Các cột số trong Parquet (trừ cột định danh/nhãn và cột bị loại trong cấu hình)."""
    excl = META_COLS | set(cfg["mining"].get("exclude_features", [])) | set(drop)
    schema = pq.read_schema(clean_files(cfg)[0])
    feats = [f.name for f in schema
             if f.name not in excl and (pa.types.is_integer(f.type) or pa.types.is_floating(f.type))]
    if len(feats) < 20:
        raise ValueError(f"Chỉ có {len(feats)} cột số trong Parquet. Hãy đặt etl.keep_all_features: true trong "
                         "config.yaml rồi chạy lại: python -m src.etl.run_etl --transform-only")
    return feats


def _sample_each_label(df, frac, rs, label_col="label_raw"):
    """Lấy mẫu theo tỷ lệ frac trong từng nhãn, luôn giữ ít nhất 1 dòng mỗi nhãn."""
    parts = []
    for _, g in df.groupby(label_col, sort=False):
        n = min(len(g), max(1, int(round(len(g) * frac))))
        parts.append(g.sample(n=n, random_state=rs))
    return pd.concat(parts)


def load_dataset(cfg, feats, log, max_rows=None):
    files = clean_files(cfg)
    cols = list(feats) + ["label_raw", "attack_group", "flow_start_ts"]
    parts = []
    for f in files:
        d = pd.read_parquet(f, columns=cols)
        d[feats] = d[feats].astype("float32")
        parts.append(d)
        log.info("  đọc %s: %d dòng", f.name, len(d))
    df = pd.concat(parts, ignore_index=True)
    df["is_attack"] = (df["attack_group"] != "Benign").astype("int8")
    if max_rows and len(df) > max_rows:
        df = _sample_each_label(df, max_rows / len(df), cfg["mining"]["random_state"]).reset_index(drop=True)
        log.warning("Giới hạn --max-rows: chỉ dùng %d dòng (lấy mẫu phân tầng theo nhãn).", len(df))
    return df


def split_dataset(df, cfg, log):
    """Chia train/test. Tập test giữ phân bố tự nhiên (chỉ giới hạn kích thước)."""
    m = cfg["mining"]
    rs, mode = m["random_state"], m["split_mode"]
    if mode == "time_block":
        tr, te = [], []
        for _, g in df.groupby("label_raw", sort=False):
            g = g.sort_values("flow_start_ts", kind="stable")
            k = int(round(len(g) * (1 - m["test_size"])))
            k = len(g) if len(g) < 2 else min(max(k, 1), len(g) - 1)
            tr.append(g.iloc[:k])
            te.append(g.iloc[k:])
        train, test = pd.concat(tr), pd.concat(te)
    elif mode == "stratified":
        counts = df["label_raw"].value_counts()
        tiny = df["label_raw"].isin(counts[counts < 2].index)  # nhãn chỉ có 1 dòng: đưa hết vào train
        train, test = train_test_split(df[~tiny], test_size=m["test_size"], stratify=df.loc[~tiny, "label_raw"],
                                       random_state=rs)
        train = pd.concat([train, df[tiny]])
    else:
        raise ValueError(f"split_mode không hợp lệ: {mode}")
    cap = m.get("test_max_rows")
    if cap and len(test) > cap:
        test = _sample_each_label(test, cap / len(test), rs)
        log.info("Tập test giới hạn còn %d dòng (phân tầng theo nhãn).", len(test))
    return train.reset_index(drop=True), test.reset_index(drop=True)


def balance_train(train, cfg):
    """Giảm mẫu tập train: Benign tối đa train_benign_cap, mỗi nhãn tấn công tối đa train_cap_per_label."""
    m = cfg["mining"]
    parts = []
    for _, g in train.groupby("label_raw", sort=False):
        cap = m["train_benign_cap"] if g["attack_group"].iloc[0] == "Benign" else m["train_cap_per_label"]
        parts.append(g.sample(n=cap, random_state=m["random_state"]) if len(g) > cap else g)
    return pd.concat(parts).sample(frac=1, random_state=m["random_state"]).reset_index(drop=True)


def cap_per_label(df, n_total, rs, label_col="label_raw"):
    """Tập con nhỏ hơn (cho SVM): chia đều n_total cho các nhãn; nhãn ít dòng hơn thì lấy hết."""
    per = max(1, n_total // df[label_col].nunique())
    parts = [g.sample(n=per, random_state=rs) if len(g) > per else g for _, g in df.groupby(label_col, sort=False)]
    return pd.concat(parts).sample(frac=1, random_state=rs).reset_index(drop=True)


def select_features(train, feats, cfg, log):
    """Bỏ đặc trưng hằng số và đặc trưng có tương quan quá cao (|r| > corr_threshold) trên tập train."""
    rs = cfg["mining"]["random_state"]
    sample = train[feats].sample(n=min(100_000, len(train)), random_state=rs)
    nun = sample.nunique(dropna=True)
    const = [c for c in feats if nun[c] <= 1]
    keep = [c for c in feats if c not in const]
    corr = sample[keep].corr().abs()
    upper = corr.where(np.triu(np.ones(corr.shape, dtype=bool), k=1))
    thr = cfg["mining"]["corr_threshold"]
    dropped_corr = {c: upper.index[upper[c] > thr].tolist() for c in upper.columns if (upper[c] > thr).any()}
    keep = [c for c in keep if c not in dropped_corr]
    log.info("Đặc trưng: %d ban đầu -> bỏ %d hằng số, %d tương quan cao -> giữ %d",
             len(feats), len(const), len(dropped_corr), len(keep))
    return keep, {"features": keep, "dropped_constant": const, "dropped_correlated": dropped_corr}