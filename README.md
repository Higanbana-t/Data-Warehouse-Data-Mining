# SOC Cybershield: Phân Tích Lưu Lượng Mạng & Phát Hiện Bất Thường (AI Anomaly Detection)

> **Báo cáo đồ án môn học**: Kho Dữ Liệu & Khai Phá Dữ Liệu (Data Warehouse & Data Mining - DWDM)  
> **Kiến trúc**: CDC Streaming ETL • Star Schema Data Warehouse • S3 Data Lake • Machine Learning Real-time Inference • FastAPI Backend • SOC Operations Dashboard

---

## 1. Sơ Đồ Kiến Trúc Hệ Thống (End-to-End Architecture)

Hệ thống được thiết kế theo mô hình **Streaming Data Pipeline & Dual-write Architecture** chuẩn doanh nghiệp:

```
[ CICIDS2017 Replay CSV ]
           │
           ▼
   [ firewall-api:8000 ]  <───  [ collector ]
                                     │ (INSERT)
                                     ▼
                           [ MySQL 8.4 OLTP ] (raw_network_logs)
                                     │ (Binlog)
                                     ▼
                         [ Debezium 3.7 Connect ]
                                     │ (CDC JSON)
                                     ▼
                        [ Apache Kafka (KRaft) ] (Topic: fw.firewall.raw_network_logs)
                                     │
                                     ▼
                      [ dwdm-etl-consumer (Python) ]
                         ├── 1. Làm sạch & Chuẩn hóa (transform_core)
                         ├── 2. Tra cứu IP Blacklist (FireHOL Level 1 & 2)
                         ├── 3. Suy luận AI thời gian thực (multiclass_rf_v1.joblib)
                         ├── 4. Dual-write Sinks:
                         │      ├── MinIO S3 Data Lake (Parquet theo event_date)
                         │      └── PostgreSQL Star Schema DW (fact_flow, dim_*, etl_batch_log)
                         └── 5. Ghi nhận cảnh báo tấn công (network_alerts)
                                     │
                     ┌───────────────┴───────────────┐
                     ▼                               ▼
       [ PostgreSQL 16 (network_dw) ]     [ MinIO S3 (network-lake) ]
                     │
                     ▼
         [ backend-api (FastAPI:8050) ]
                     │
                     ▼
      [ SOC Cybershield Web Dashboard ] (http://localhost:8050/)
```

---

## 2. Bảng Phân Bổ Cổng Dịch Vụ (Service Ports)

| Dịch Vụ | Container | Cổng Host | Cổng Container | Mô Tả & Đường Dẫn |
|---|---|---|---|---|
| **SOC Dashboard** | `dwdm-backend-api` | **8050** | 8050 | Giao diện điều hành an ninh mạng: `http://localhost:8050/` |
| **Backend API (Docs)** | `dwdm-backend-api` | **8050** | 8050 | Tài liệu Swagger UI: `http://localhost:8050/docs` |
| **Firewall API (Sim)** | `dwdm-firewall-api` | **8000** | 8000 | API phát lại log firewall: `http://localhost:8000/docs` |
| **PostgreSQL DW** | `dwdm-postgres` | **5433** | 5432 | Star Schema Data Warehouse (`network_dw`) |
| **MySQL OLTP** | `dwdm-mysql` | **3307** | 3306 | CSDL nguồn mô phỏng log firewall (`firewall`) |
| **Kafka Connect** | `dwdm-connect` | **8083** | 8083 | Debezium REST API kiểm tra connector status |
| **Kafka Broker** | `dwdm-kafka` | *Internal* | 9092 | Message Broker KRaft (mạng nội bộ Docker) |
| **MinIO S3 API** | `dwdm-minio` | **19000** | 9000 | S3 Storage API lưu trữ Parquet Data Lake |
| **MinIO Console** | `dwdm-minio` | **19001** | 9001 | Web UI quản trị MinIO: `http://localhost:19001/` |

---

## 3. Hướng Dẫn Vận Hành Nhanh (Quick Start)

### 3.1. Cấu hình môi trường
Tạo file `.env` từ file mẫu `.env.example` (đã được thiết lập sẵn trong workspace):
```bash
cp .env.example .env
```

### 3.2. Khởi chạy toàn bộ hệ thống
Chạy lệnh duy nhất để khởi động toàn bộ 8 services hạ tầng, streaming consumer, backend API và dashboard:
```bash
# Khởi động hạ tầng cơ sở dữ liệu và message broker
docker compose up -d mysql postgres kafka connect minio

# Đăng ký Debezium CDC Connector và tạo S3 bucket
docker compose up init

# Khởi chạy ứng dụng (Firewall API, ETL Consumer, Backend API & Dashboard)
docker compose --profile app up -d firewall-api etl-consumer backend-api
```

Kiểm tra trạng thái toàn bộ containers:
```bash
docker compose ps
```

---

## 4. Kịch Bản Nghiệm Thu & Bảo Vệ Đồ Án (Step-by-Step Defense Guide)

Dưới đây là các lệnh chạy terminal để demo trực tiếp từng tính năng trước hội đồng chấm thi:

### Bước 1: Kiểm tra trạng thái ETL Streaming Consumer & Nạp Mô Hình AI
Kiểm tra log của consumer xác nhận nạp Blacklist FireHOL và Mô hình Random Forest 48 đặc trưng:
```bash
docker logs --tail 25 dwdm-etl-consumer
```
*Kỳ vọng:* Xuất hiện log `Nạp mô hình AI thành công. Số đặc trưng: 48` và `Bắt đầu đọc luồng từ Kafka...`.

---

### Bước 2: Bơm dữ liệu giả lập từ Collector (Phát hiện tấn công)
Bơm 1.000 luồng lưu lượng mạng qua collector:
```bash
docker compose --profile app run --rm collector python -m src.api_simulator.collector --max-rows 1000
```
Theo dõi consumer nhận luồng từ Kafka, làm sạch, dự đoán AI và ghi vào kho:
```bash
docker logs --tail 20 dwdm-etl-consumer
```
*Kỳ vọng:* Hiển thị log micro-batch xử lý dạng:
`Lô 500 dòng | Sạch: 500 | Cảnh báo AI: 495 cuộc tấn công (P50: 167ms, P95: 186ms).`

---

### Bước 3: Nghiệm thu CSDL Data Warehouse (PostgreSQL)
Truy vấn trực tiếp số lượng bản ghi trong Data Warehouse:
```bash
python -c "
import psycopg2
conn = psycopg2.connect(host='localhost', port=5433, user='dw_admin', password='doi_mat_khau_postgres', dbname='network_dw')
cur = conn.cursor()
cur.execute('SELECT COUNT(*) FROM fact_flow;')
print('Tổng số flow trong fact_flow:', cur.fetchone()[0])
cur.execute('SELECT COUNT(*) FROM network_alerts;')
print('Tổng số cảnh báo trong network_alerts:', cur.fetchone()[0])
cur.execute('SELECT attack_type, COUNT(*) FROM network_alerts GROUP BY attack_type ORDER BY COUNT(*) DESC;')
print('Phân bố tấn công phát hiện được:')
for r in cur.fetchall():
    print(f'  - {r[0]}: {r[1]}')
cur.close(); conn.close()
"
```
*Kỳ vọng:* Có đầy đủ các loại hình tấn công được AI phân loại: `DDoS`, `PortScan`, `Other` (Patator/DoS), `Botnet`, `WebAttack`.

---

### Bước 4: Nghiệm thu MinIO S3 Data Lake (Parquet Files)
Kiểm tra các phân vùng Parquet đã được ghi lên MinIO:
```bash
docker exec dwdm-etl-consumer python -c "
import boto3
s3 = boto3.client('s3', endpoint_url='http://minio:9000', aws_access_key_id='lakeadmin', aws_secret_access_key='doi_mat_khau_s3_dai')
res = s3.list_objects_v2(Bucket='network-lake', Prefix='clean/')
print('Tổng số file Parquet trên S3 Lake:', res.get('KeyCount', 0))
print('Danh sách file mẫu:')
for obj in res.get('Contents', [])[:3]:
    print('  -', obj['Key'])
"
```

---

### Bước 5: Kiểm tra các RESTful Endpoints của Backend API (FastAPI)
Kiểm tra phản hồi JSON chuẩn (HTTP 200) của cả 5 endpoints:

1. **Health Check**:
   ```bash
   curl http://localhost:8050/health
   ```
2. **Overview KPI & Streaming Latency**:
   ```bash
   curl http://localhost:8050/stats/overview
   ```
3. **Phân bố các loại hình tấn công**:
   ```bash
   curl http://localhost:8050/analytics/attack-distribution
   ```
4. **Top IP độc hại & Top cổng mục tiêu**:
   ```bash
   curl http://localhost:8050/analytics/top-talkers
   ```
5. **Feed cảnh báo thời gian thực (lọc theo DDoS)**:
   ```bash
   curl "http://localhost:8050/alerts/recent?limit=5&attack_type=DDoS"
   ```

---

### Bước 6: Trực quan hóa trên SOC Cybershield Dashboard
Mở trình duyệt web và truy cập địa chỉ:
👉 **[http://localhost:8050/](http://localhost:8050/)**

Các tính năng nổi bật trên giao diện:
- **Thẻ KPI thời gian thực**: Tổng luồng mạng, tổng cảnh báo AI, tỉ lệ tấn công (%), độ trễ micro-batch P50 / P95 (ms).
- **Biểu đồ Donut**: Phân bố tỷ lệ các loại hình tấn công (DDoS, PortScan, WebAttack, Botnet, Other).
- **Biểu đồ Đường (Timeline)**: Xu hướng lưu lượng tấn công theo mốc thời gian ghi nhận.
- **Biểu đồ Cột**: Top các cổng dịch vụ bị nhắm tới nhiều nhất (HTTP - 80, FTP - 21, HTTPS - 443, SSH - 22...).
- **Bảng Real-time Alert Feed**: Hiển thị chi tiết từng phiên tấn công với màu huy hiệu neon, có dropdown lọc tức thì theo loại tấn công.
- **Bảng Top IP Nguồn**: Xếp hạng các IP phát tán tấn công nhiều nhất kèm cờ đối soát Blacklist FireHOL Level 1 & 2.
- **Tự động làm mới (Auto-refresh)**: Cập nhật dữ liệu tự động mỗi 3 giây với nút Pause/Resume và trạng thái Radar Pulse.

---

## 5. Cấu Trúc Mã Nguồn Dự Án

```
network-anomaly-dwdm/
├── docker/                    # Dockerfile & cấu hình Debezium, MySQL, Init
├── models/                    # Mô hình AI đã train (.joblib)
│   ├── multiclass_rf_v1.joblib
│   └── binary_rf_v1.joblib
├── sql/                       # DDL Star Schema PostgreSQL & Raw MySQL
│   ├── 01_create_schema.sql
│   ├── 03_olap_queries.sql
│   └── 04_views.sql
├── dashboard/                 # Giao diện SOC Cybershield (HTML, Vanilla CSS, JS)
│   ├── index.html
│   ├── styles.css
│   └── app.js
├── src/
│   ├── api_service/           # FastAPI Backend Service (main.py, db.py)
│   ├── api_simulator/         # Firewall API Replay & Collector
│   ├── etl/                   # Pipeline Streaming & Sinks (Dual-write)
│   │   ├── stream_consumer.py # Kafka Consumer + AI Inference + Sinks
│   │   ├── sinks.py           # PostgresSink (UPSERT, alerts) & ObjectStoreSink (Parquet)
│   │   └── transform_core.py  # Lõi làm sạch, chuẩn hóa, blacklist check
│   ├── mining/                # Khai phá dữ liệu & Suy luận AI
│   │   ├── inference.py       # Class StreamingInference (load pipeline, features)
│   │   └── train.py           # Script huấn luyện Random Forest / Decision Tree
│   └── utils/                 # Cấu hình & Logger
├── docker-compose.yml         # File điều phối toàn bộ hệ thống
├── config.yaml                # Cấu hình dự án
└── README.md                  # Hướng dẫn chi tiết
```