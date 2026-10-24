# Network Traffic Analysis & Anomaly Detection

Dự án bài tập lớn môn Data Warehouse & Data Mining.
=============================================================================
                  SƠ ĐỒ LUỒNG XỬ LÝ DỮ LIỆU (DATA PIPELINE)
=============================================================================

[1. NGUỒN DỮ LIỆU THÔ - RAW DATA]
   ├── 📄 Dữ liệu mạng: 8 files CSV (CIC-IDS-2017) -> ~3.1 triệu dòng
   └── 📄 Tình báo đe dọa: firehol_level1.netset (Blacklist)
          │
          ▼
[2. ĐƯỜNG ỐNG ETL - PYTHON PIPELINE]
   ├── 🟢 EXTRACT (Trích xuất)
   │     └── Đọc dữ liệu thô theo từng lô nhỏ (Chunking) để tránh tràn RAM.
   │
   ├── 🟡 TRANSFORM & ENRICH (Nhào nặn & Làm giàu)
   │     ├── Chọn 21 thuộc tính quan trọng nhất (Feature Selection).
   │     ├── Xử lý nhiễu: Bỏ giá trị NULL, sửa lỗi định dạng giờ AM/PM.
   │     ├── Chuẩn hóa: Gom nhóm nhãn tấn công (WebAttack, DDoS...).
   │     ├── Làm giàu: Quét IP với Blacklist -> Gán cờ is_blacklisted = TRUE/FALSE.
   │     └── 💾 LƯU TRUNG GIAN: Xuất ra các file siêu nén (.parquet).
   │
   └── 🔴 LOAD (Nạp dữ liệu)
         ├── Áp dụng Lũy đẳng (Idempotent): Tự động TRUNCATE bảng cũ.
         └── Dùng lệnh COPY FROM STDIN bơm tốc độ cao vào kho.
          │
          ▼
[3. KHO DỮ LIỆU - DATA WAREHOUSE (POSTGRESQL)]
   └── ⭐ LƯỢC ĐỒ HÌNH SAO (STAR SCHEMA)
         ├── 🗄️ Bảng trung tâm: fact_flow (Chứa độ đo: bytes, packets, duration...)
         └── 🗂️ Các bảng chiều (Dimensions) xung quanh:
               ├── dim_time (Giờ, Ngày, Tháng)
               ├── dim_ip (IP Nguồn, IP Đích, Trạng thái Blacklist)
               ├── dim_port (Cổng đích, Dịch vụ HTTP/SSH...)
               ├── dim_protocol (TCP, UDP, ICMP)
               └── dim_label (Trạng thái tấn công, Nhóm tấn công)
          │
          ▼
[4. TẦNG ỨNG DỤNG & PHÂN TÍCH (JUPYTER NOTEBOOKS)]
   ├── 📊 Giai đoạn 1: Phân tích Đa chiều (03_olap.ipynb)
   │     └── Áp dụng SQL & Pandas để Slice, Dice, Roll-up, Drill-down.
   │
   └── 🧠 Giai đoạn 2: Khai phá dữ liệu (04_data_mining.ipynb) -> [Bước tiếp theo]
         ├── Đọc thẳng dữ liệu sạch từ file .parquet.
         └── Huấn luyện mô hình Machine Learning (Phân loại tấn công).