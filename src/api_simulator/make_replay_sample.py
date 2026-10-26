"""
Tạo tập mẫu phát lại ~100.000 dòng (đủ mọi nhãn) từ các file CSV GeneratedLabelledFlows gốc.

    python -m src.api_simulator.make_replay_sample --raw-dir data/raw/cicids2017 --out data/replay/replay_sample.csv

Quy tắc (xem mục 14.13.7 của báo cáo):
  - nhãn hiếm: lấy TOÀN BỘ (Heartbleed, SQL Injection, Infiltration, XSS, Brute Force, Bot);
  - nhãn trung bình / lớn: lấy một ĐOẠN LIÊN TỤC từ đầu đoạn tấn công (đúng số dòng đã định);
  - Benign: lấy trải đều (cách đều) để số dòng đạt chỉ tiêu.
  Giữ nguyên thứ tự file và thứ tự dòng, nên các đợt tấn công vẫn liền nhau. File ra có cùng header với file gốc.

Mẫu có ~một nửa là tấn công: CHỈ để demo luồng streaming, không dùng để đánh giá mô hình.
"""
import argparse
import csv
import re
from pathlib import Path

import pandas as pd

from src.api_simulator.reader import list_csv_files

# nhãn (đã chuẩn hóa, viết thường) -> số dòng tối đa (None = lấy hết)
PLAN = {"heartbleed": None, "web attack - sql injection": None, "infiltration": None, "web attack - xss": None,
        "web attack - brute force": None, "bot": None,
        "ftp-patator": 3000, "ssh-patator": 3000, "dos slowloris": 3000, "dos slowhttptest": 3000, "dos goldeneye": 5000,
        "dos hulk": 10000, "portscan": 10000, "ddos": 10000}
BENIGN_QUOTA = 48_807


def norm(label):
    """Thay mọi ký tự ngoài ASCII in được (byte lạ trong nhãn Web Attack) bằng '-' và đưa về chữ thường."""
    return re.sub(r"[^\x20-\x7E]+", "-", str(label)).strip().lower()


def read_labels(path):
    df = pd.read_csv(path, encoding="latin-1", low_memory=False, usecols=lambda c: c.strip() == "Label")
    return df.iloc[:, 0].map(norm)


def build_sample(raw_dir, benign_quota=BENIGN_QUOTA, plan=PLAN):
    files = list_csv_files(raw_dir)
    labels = {f: read_labels(f) for f in files}                       # lượt 1: đếm nhãn
    n_benign = sum(int((s == "benign").sum()) for s in labels.values())
    step = max(1, -(-n_benign // benign_quota)) if n_benign else 1    # lấy 1 dòng Benign sau mỗi `step` dòng
    with open(files[0], newline="", encoding="latin-1") as fh:
        header = next(csv.reader(fh))                                  # header NGUYÊN BẢN (giữ cả cột lặp tên)
    taken, benign_seen, parts = {}, 0, []
    for f in files:                                                    # lượt 2: chọn dòng
        df = pd.read_csv(f, encoding="latin-1", low_memory=False)
        lab, keep = labels[f].reset_index(drop=True), []
        for i, l in enumerate(lab):
            if l == "benign":
                if benign_seen % step == 0:
                    keep.append(i)
                benign_seen += 1
            elif l in plan:
                quota = plan[l]
                if quota is None or taken.get(l, 0) < quota:
                    taken[l] = taken.get(l, 0) + 1
                    keep.append(i)
        parts.append(df.iloc[keep])
    out = pd.concat(parts, ignore_index=True)
    out.columns = header          # pandas đổi cột lặp tên thành "Fwd Header Length.1"; trả lại đúng tên gốc
    return out, header


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--raw-dir", default="data/raw/cicids2017")
    ap.add_argument("--out", default="data/replay/replay_sample.csv")
    args = ap.parse_args()
    out, header = build_sample(args.raw_dir)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(args.out, index=False, encoding="latin-1")
    counts = out[[c for c in out.columns if c.strip() == "Label"][0]].map(norm).value_counts()
    print(f"Đã ghi {len(out):,} dòng vào {args.out}")
    print(counts.to_string())


if __name__ == "__main__":
    main()
