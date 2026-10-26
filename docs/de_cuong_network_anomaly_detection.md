# BÁO CÁO ĐỀ CƯƠNG BÀI TẬP LỚN
## Môn: Data Warehouse & Data Mining

---

## 1. Tên đề tài

**Phân tích Lưu lượng Mạng và Phát hiện Bất thường**
*(Network Traffic Analysis & Anomaly Detection)*

---

## 2. Mô tả đề tài

### 2.1. Bối cảnh và lý do chọn đề tài
Trong bối cảnh các cuộc tấn công mạng ngày càng tinh vi (DDoS, Port Scan, Web Attack, Botnet...), việc giám sát lưu lượng mạng và phát hiện sớm các hành vi bất thường là nhu cầu cấp thiết đối với mọi tổ chức. Đề tài xây dựng một hệ thống thử nghiệm mô phỏng góc nhìn của một quản trị viên hạ tầng mạng, gồm ba thành phần: xử lý dữ liệu (ETL), kho dữ liệu (Data Warehouse) và mô hình khai phá dữ liệu (Data Mining) để hỗ trợ phát hiện tấn công.

### 2.2. Mục tiêu
- Xây dựng pipeline ETL để đọc, làm sạch và chuẩn hóa dữ liệu luồng traffic mạng.
- Thiết kế kho dữ liệu đa chiều (star schema) lưu trữ lịch sử giao tiếp mạng và danh sách IP rủi ro.
- Áp dụng thuật toán học máy để phân loại traffic hợp lệ (Benign) và các loại tấn công (DDoS, Port Scan, Web Attack).
- Trực quan hóa kết quả giám sát băng thông, giao thức và các IP có rủi ro cao.

### 2.3. Các tính năng chính của đề tài

| # | Tính năng | Mô tả |
|---|---|---|
| 1 | **Trích xuất và làm sạch dữ liệu (ETL)** | Đọc dữ liệu luồng traffic mạng (dạng flow-based CSV, đóng vai trò log đã được thiết bị mạng ghi lại), loại bỏ dòng lỗi/trùng lặp, chuẩn hóa định dạng IP và Timestamp, mã hóa các trường phân loại (protocol, flag...) |
| 2 | **Tích hợp và lưu trữ dữ liệu (Data Warehousing)** | Thiết kế kho dữ liệu đa chiều (Star Schema): Fact table lưu lịch sử giao tiếp mạng (mỗi dòng là 1 phiên kết nối), kèm Dimension: thời gian, giao thức, cổng dịch vụ, thiết bị/IP, và danh sách IP rủi ro (đối chiếu với 1 blacklist IP công khai) |
| 3 | **Khai phá dữ liệu (Data Mining)** | Xây dựng mô hình phân loại (Decision Tree, Random Forest, SVM) để tự động phân loại một luồng kết nối là hợp lệ (Benign) hay tấn công, và nếu là tấn công thì thuộc loại nào (DDoS, Port Scan, Web Attack) |
| 4 | **Trực quan hóa báo cáo (Dashboarding)** | Biểu đồ thống kê lưu lượng theo giao thức/khung giờ, xếp hạng các IP có hành vi bất thường nhiều nhất trong tập dữ liệu, hiệu suất mô hình phân loại |

---

## 3. Nguồn dữ liệu

| Nguồn | Mô tả | Link |
|---|---|---|
| **CICIDS2017** (nguồn chính) | Bộ dữ liệu chuẩn ~2,8 triệu bản ghi flow-based, có nhãn Benign/DDoS/PortScan/Web Attack/Botnet. **Phải dùng file `GeneratedLabelledFlows.zip`** (có đủ Flow ID, Source IP, Source Port, Destination IP, Protocol, Timestamp). Không dùng `MachineLearningCSV.zip` và các bản "cleaned" trên Kaggle vì đã bị lược bỏ các cột này | Trang chính thức: https://www.unb.ca/cic/datasets/ids-2017.html (bấm nút "Download this dataset" → điền form ngắn, không cần mật khẩu → chọn thư mục CSVs → `GeneratedLabelledFlows.zip`) |
| **Danh sách IP rủi ro/blacklist công khai** (nguồn bổ sung) | Dùng làm dimension "IP rủi ro" — không cần dịch vụ Threat Intelligence trả phí. Tải `firehol_level1.netset` vào `data/raw/blacklist/`. **Lưu ý:** file này gồm cả dải IP nội bộ (list `fullbogons`: 10/8, 172.16/12, 192.168/16) nên ETL chỉ kiểm tra IP công cộng; ngoài ra danh sách hiện tại (2026) không phản ánh đúng tình trạng IP năm 2017 | https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset (trang gốc: https://iplists.firehol.org/) |

**⚠️ Xác nhận: bản Kaggle `chethuhn/network-intrusion-dataset` KHÔNG dùng được cho đề tài này.** Bản đó là dạng `MachineLearningCSV` (chỉ giữ đặc trưng số để huấn luyện), đã thiếu các cột `Flow ID`, `Source IP`, `Source Port`, `Destination IP`, `Protocol` và `Timestamp` — tức là thiếu gần hết các cột cần cho `dim_ip`, `dim_time`, `dim_protocol`. Các bản "cleaned/preprocessed" khác trên Kaggle cũng thường cùng tình trạng, nên **chỉ chấp nhận file đã kiểm tra có đủ 6 cột trên**.

**Cách lấy đúng dữ liệu (theo thứ tự ưu tiên):**
1. **Nguồn chính thức (UNB/CIC):** vào trang https://www.unb.ca/cic/datasets/ids-2017.html → "Download this dataset" → điền form (họ tên, email, tổ chức, quốc gia; không cần mật khẩu) → tải `GeneratedLabelledFlows.zip` (~271 MB, gồm 8 file CSV theo từng buổi). Trang chính thức mô tả file này gồm các flow được gán nhãn theo timestamp, IP nguồn/đích, cổng, giao thức và loại tấn công. Nếu form báo "Server error" thì thử lại sau vài giờ hoặc dùng trình duyệt khác/trình quản lý tải (IDM).
2. **Bản sao dự phòng (bên thứ ba, chưa kiểm chứng):** một số repo GitHub/Kaggle có đăng lại `GeneratedLabelledFlows.zip` (ví dụ repo `rokibulroni/CIC-IDS-2017-Dataset` ghi dung lượng 271 MB). Nếu dùng, **bắt buộc mở file kiểm tra đủ 6 cột trên và số dòng ~2,8 triệu** trước khi làm tiếp. Repo `mahendradata/cicids2017-ml` có notebook tham khảo cách tải và tiền xử lý `GeneratedLabelledFlows`.
3. **Phương án B nếu không tải được:** dùng **UNSW-NB15 — 4 file CSV gốc** (`UNSW-NB15_1.csv` … `_4.csv`) có `srcip`, `sport`, `dstip`, `dsport`, `proto`, `stime`, `ltime`, `attack_cat`, `label` (khác với cặp file train/test chuẩn vốn đã bỏ IP và timestamp). Lưu ý nhãn của UNSW-NB15 khác (Fuzzers, DoS, Exploits, Reconnaissance, Generic...; không có DDoS, PortScan, Botnet riêng) nên câu hỏi 1, 2, 4 phải diễn đạt lại theo nhãn `Reconnaissance`/`DoS`.

**Lưu ý về địa chỉ IP trong CICIDS2017 (theo mô tả chính thức):** máy tấn công Kali dùng IP `205.174.165.73`, nhưng lưu lượng đi qua firewall có NAT (`205.174.165.80` → `172.16.0.1` → `192.168.10.50`), nên **trong nhiều flow tấn công, IP nguồn được ghi là `172.16.0.1` (firewall) chứ không phải IP thật của kẻ tấn công**. Cần kiểm tra thực tế trong dữ liệu và ghi rõ trong báo cáo khi trả lời câu hỏi 2 và 4. Tất cả IP này thuộc môi trường lab nên gần như chắc chắn **không có trong blacklist thực tế (FireHOL)**; các IP ngoài mạng trong lưu lượng Benign (web, DNS...) mới có khả năng trùng.

**Ghi chú:** đề tài dùng dữ liệu benchmark có sẵn thay vì log thu thập trực tiếp từ thiết bị mạng thật — dữ liệu này đóng vai trò "log đã được chuẩn hóa sẵn" để thực hành ETL (parse, làm sạch, chuẩn hóa) mà không cần dựng hạ tầng mạng thật.

---

## 4. Công cụ sử dụng

| Nhóm | Công cụ | Mục đích |
|---|---|---|
| Ngôn ngữ lập trình | Python | Xử lý dữ liệu, xây dựng mô hình |
| Xử lý dữ liệu | pandas, numpy | ETL: đọc, làm sạch, chuẩn hóa IP/Timestamp |
| Học máy | scikit-learn | Decision Tree, Random Forest, SVM, đánh giá mô hình |
| Kho dữ liệu | PostgreSQL / MySQL hoặc SQL Server | Lưu trữ star schema, truy vấn OLAP |
| Trực quan hóa | Power BI hoặc matplotlib/seaborn/Plotly | Dashboard giám sát traffic và IP rủi ro |
| Môi trường phát triển | Jupyter Notebook / VS Code | Viết và chạy thử nghiệm |

---

## 5. Câu hỏi nghiệp vụ (Business Questions)

Hệ thống sau khi hoàn thiện sẽ giúp người quản trị hạ tầng mạng trả lời các câu hỏi sau:

1. **Đặc trưng nào** (kích thước gói tin, thời gian duy trì phiên, số lượng cờ SYN...) giúp phân biệt rõ nhất giữa traffic tăng đột biến hợp lệ và một cuộc tấn công DDoS?
2. Trong tập dữ liệu, **IP/thiết bị nào có hành vi giống botnet nhất** (số lượng kết nối bất thường cao nhất, lặp lại nhiều lần)?
3. **Giao thức mạng nào** (TCP, UDP, ICMP) có dấu hiệu tiêu thụ băng thông bất thường vào một số khung giờ trong ngày, so với mức bình thường của chính giao thức đó?
4. Trong tập dữ liệu, **nhóm IP nào thực hiện quét cổng (port scan) nhiều nhất**, và các IP này có trùng với danh sách blacklist công khai (FireHOL) hay không?

*(Lưu ý: câu 3 được diễn đạt lại theo "khung giờ trong ngày" thay vì "ngoài giờ hành chính" vì CICIDS2017 chỉ ghi lưu lượng trong giờ làm việc (khoảng 9h-17h mỗi ngày), nên gần như không có dữ liệu ngoài giờ; hãy chạy truy vấn `qc_time_range` để xác nhận trên dữ liệu thật. Câu 2 và câu 4 được diễn đạt lại ở dạng "mô tả/xếp hạng dựa trên dữ liệu đã có" thay vì "dự đoán xác suất thời gian thực" hoặc "trong 30 ngày qua" — vì dữ liệu benchmark là một snapshot cố định, không phải luồng dữ liệu cập nhật liên tục.)*

---

## 6. Phạm vi và giới hạn của đề tài
- Đề tài sử dụng dữ liệu benchmark có sẵn (không thu thập traffic thực tế từ thiết bị mạng thật), kết quả mang tính chất thử nghiệm/mô phỏng, phù hợp mục đích học tập.
- Dữ liệu là một snapshot cố định (ghi trong vài ngày cụ thể), nên các phân tích về "hành vi rủi ro" hoặc "quét cổng" chỉ phản ánh trong phạm vi tập dữ liệu, không phải giám sát thời gian thực liên tục.
- Danh sách IP rủi ro dùng nguồn blacklist công khai (FireHOL) mang tính minh họa, không phải dịch vụ Threat Intelligence thương mại đầy đủ.

---

## 7. Lộ trình thực hiện chi tiết (10 tuần)

### Tổng quan

| Giai đoạn | Tuần | Nội dung chính | Sản phẩm bàn giao |
|---|---|---|---|
| 1. Chuẩn bị & khảo sát dữ liệu | 1-2 | Cài môi trường, tải dữ liệu, khám phá dữ liệu | Notebook EDA, quyết định phạm vi dữ liệu |
| 2. ETL | 3-4 | Làm sạch, chuẩn hóa IP/Timestamp, lấy mẫu | Script ETL, bộ dữ liệu sạch |
| 3. Data Warehouse | 5-6 | Thiết kế star schema, nạp dữ liệu, truy vấn OLAP | Sơ đồ schema, script SQL, kết quả truy vấn |
| 4. Data Mining | 7-8 | Huấn luyện và đánh giá mô hình phân loại | Notebook mô hình, bảng so sánh |
| 5. Dashboard & trả lời câu hỏi | 9 | Trực quan hóa, tổng hợp đáp án 4 câu hỏi | Dashboard, bảng kết luận |
| 6. Báo cáo & bảo vệ | 10 | Viết báo cáo, làm slide, dự phòng | Báo cáo, slide, mã nguồn |

---

### Giai đoạn 1 — Chuẩn bị & khảo sát dữ liệu (Tuần 1-2)

**Tuần 1: Chuẩn bị**
- Cài đặt: Python 3.10+, Jupyter/VS Code, PostgreSQL (hoặc MySQL/SQL Server), thư viện `pandas numpy scikit-learn matplotlib seaborn sqlalchemy psycopg2`.
- Tải CICIDS2017 **`GeneratedLabelledFlows.zip`** từ trang chính thức UNB (xem mục 3; không dùng `MachineLearningCSV` hay bản Kaggle đã lược cột). Tải thêm danh sách blacklist từ FireHOL.
- Mở thử 1 file, **kiểm tra có đủ 6 cột: `Flow ID`, `Source IP`, `Source Port`, `Destination IP`, `Protocol`, `Timestamp` (cùng cột `Label`)**. Thiếu bất kỳ cột nào → không dùng file đó; chuyển sang nguồn dự phòng hoặc Phương án B ở mục 3.
- Tạo cấu trúc thư mục dự án: `data/raw`, `data/clean`, `notebooks`, `sql`, `report`; quản lý mã nguồn bằng Git.

**Tuần 2: Khám phá dữ liệu (EDA)**
- Dữ liệu gồm 8 file CSV theo từng buổi (thứ Hai đến thứ Sáu), tổng ~2,8 triệu dòng. Nắm sơ lược phân bố nhãn theo ngày:
  - Thứ Hai: chỉ traffic bình thường
  - Thứ Ba: FTP-Patator, SSH-Patator
  - Thứ Tư: các kiểu DoS, Heartbleed
  - Thứ Năm: Web Attack, Infiltration
  - Thứ Sáu: Botnet, **PortScan**, **DDoS**
- Thống kê: số dòng mỗi nhãn, giá trị thiếu/vô cùng (Infinity), dòng trùng, kiểu dữ liệu từng cột, phân bố giao thức.
- **Quyết định phạm vi:** đề tài chỉ cần nhóm nhãn Benign / DDoS / PortScan / Web Attack (+ Botnet cho câu hỏi 2). Gom các nhãn khác vào nhóm "Other" hoặc loại bỏ để giảm độ phức tạp.
- **Chiến lược lấy mẫu (đã điều chỉnh):** mặc định **nạp toàn bộ ~2,8 triệu dòng vào kho** để kết quả OLAP chính xác (PostgreSQL xử lý được trên laptop nếu có index). ETL đọc từng file một và chỉ lấy 21 cột cần dùng nên không tràn RAM. Chỉ khi máy quá yếu mới bật `sampling.enabled: true` trong `config.yaml` (giữ một phần Benign, giới hạn số dòng mỗi nhãn tấn công) và phải ghi rõ trong báo cáo rằng các số đếm là trên mẫu. Việc lấy mẫu để huấn luyện mô hình thuộc giai đoạn Data Mining, làm riêng từ dữ liệu đã nạp.

✅ *Mốc hoàn thành:* notebook EDA + 1 trang ghi quyết định phạm vi dữ liệu.

---

### Giai đoạn 2 — ETL (Tuần 3-4)

**Tuần 3: Làm sạch**
- Chuẩn hóa tên cột (bỏ khoảng trắng đầu/cuối, thống nhất chữ thường, dùng dấu gạch dưới).
- Xử lý `Infinity`/`NaN` (ở các cột như Flow Bytes/s), xóa dòng trùng lặp, xóa cột hằng số (không mang thông tin).
- Chuẩn hóa **IP**: kiểm tra định dạng hợp lệ (module `ipaddress` của Python), thêm cột `is_internal` (IP nội bộ 192.168.x.x/172.16.x.x/10.x.x.x hay IP ngoài mạng).
- Chuẩn hóa **Timestamp**: dữ liệu mẫu thật cho thấy định dạng `d/m/yyyy h:mm` (ví dụ `7/7/2017 1:00`), **chỉ có độ phân giải phút** và không có AM/PM. Vì dữ liệu chỉ có tháng 7/2017 nên `3/7/2017` là ngày 3 tháng 7 (ngày đứng trước tháng). Dữ liệu được ghi trong giờ làm việc nên **giờ 1-7 được hiểu là buổi chiều (+12 giờ), giờ 8-12 giữ nguyên** (một số file có thể bắt đầu từ khoảng 8h sáng). Đây là suy luận, cần kiểm chứng: sau khi chạy ETL, cột `rows_outside_8_18` trong `etl_summary.csv` phải gần 0, và giờ các đợt tấn công nên khớp với danh sách giờ tấn công trên trang chính thức. Ghi rõ giả định này trong báo cáo.
- Gộp nhãn: tạo cột `attack_group` (Benign, DDoS, PortScan, WebAttack, Botnet, Other).

**Tuần 4: Hoàn thiện pipeline**
- Đóng gói các bước trên thành 1 script/notebook chạy lại được từ đầu đến cuối (`python -m src.etl.run_etl`, chạy từ thư mục gốc dự án), có ghi log số dòng trước/sau mỗi bước.
- Xuất dữ liệu sạch ra `data/clean/` (định dạng Parquet hoặc CSV).
- Chuẩn bị bảng blacklist: đọc file FireHOL, chuyển thành bảng (ip/cidr, nguồn danh sách).

✅ *Mốc hoàn thành:* script ETL chạy được + file dữ liệu sạch + bảng thống kê "trước/sau làm sạch".

---

### Giai đoạn 3 — Data Warehouse (Tuần 5-6)

**Tuần 5: Thiết kế & tạo schema**

Mô hình Star Schema đề xuất:

| Bảng | Loại | Cột chính |
|---|---|---|
| `fact_flow` | Fact | flow_id, time_key, src_ip_key, dst_ip_key, protocol_key, port_key, label_key; các số đo: flow_duration, total_fwd_packets, total_bwd_packets, flow_bytes, syn_flag_count, avg_packet_size... |
| `dim_time` | Dimension | time_key, datetime, ngày, giờ, thứ, `is_business_hours` (giờ hành chính hay không) |
| `dim_ip` | Dimension | ip_key, ip_address, is_internal, `is_blacklisted`, nguồn blacklist |
| `dim_protocol` | Dimension | protocol_key, tên giao thức (TCP/UDP/ICMP) |
| `dim_port` | Dimension | port_key, số cổng, tên dịch vụ (80=HTTP, 443=HTTPS, 22=SSH...) |
| `dim_label` | Dimension | label_key, nhãn gốc, attack_group, `is_attack` |

- Vẽ sơ đồ schema (dùng dbdiagram.io, draw.io hoặc công cụ có sẵn của SQL Server/pgAdmin).
- Viết script SQL tạo bảng, khóa chính/khóa ngoại, chỉ mục (index) trên các cột hay lọc (time_key, src_ip_key, label_key).

**Tuần 6: Nạp dữ liệu & truy vấn OLAP**
- Nạp dữ liệu vào các bảng dimension trước, sau đó nạp fact table (dùng pandas + SQLAlchemy `to_sql` theo từng lô hoặc `COPY` của PostgreSQL).
- Đối chiếu `dim_ip` với blacklist FireHOL để đánh dấu `is_blacklisted`.
  - *Rủi ro cần biết trước:* các IP tấn công trong CICIDS2017 là máy trong môi trường lab nên **nhiều khả năng không nằm trong blacklist thực tế**. Kết quả "không trùng khớp" vẫn là một phát hiện hợp lệ và nên được báo cáo trung thực; phần lưu lượng Benign có nhiều IP ngoài mạng nên có thể có một số IP trùng blacklist.
- Viết các truy vấn OLAP (GROUP BY, ROLLUP/CUBE, drill-down/roll-up) trả lời câu hỏi 3 và 4:
  - Băng thông theo giao thức × giờ trong ngày, kèm phát hiện giờ lệch bất thường (z-score)
  - Top IP nguồn có số kết nối PortScan nhiều nhất, kèm cờ blacklist
  - Số lượng tấn công theo nhãn × cổng dịch vụ

✅ *Mốc hoàn thành:* sơ đồ star schema + script SQL + ít nhất 6-8 truy vấn OLAP có kết quả.

---

### Giai đoạn 4 — Data Mining (Tuần 7-8)

**Tuần 7: Chuẩn bị và huấn luyện**
- Chọn đặc trưng: lấy các cột số từ fact table; **loại bỏ** các cột định danh (IP, flow_id, timestamp) khỏi tập đặc trưng để mô hình không "học thuộc" địa chỉ.
- Chia train/test theo tỷ lệ 70/30 hoặc 80/20, dùng `stratify` để giữ tỷ lệ các lớp.
- Chuẩn hóa dữ liệu (`StandardScaler`) — **chỉ fit trên tập train** để tránh rò rỉ dữ liệu (data leakage).
- Huấn luyện 3 mô hình: Decision Tree, Random Forest, và SVM. *Mẹo:* SVM chạy rất chậm với dữ liệu lớn → dùng `LinearSVC` hoặc huấn luyện trên tập con 50.000-100.000 dòng.
- Xử lý mất cân bằng bằng `class_weight='balanced'` (đơn giản hơn SMOTE, đủ dùng cho đề tài).
- Làm 2 bài toán: (a) nhị phân Benign vs Attack, (b) đa lớp Benign/DDoS/PortScan/WebAttack/Botnet.

**Tuần 8: Đánh giá và phân tích**
- Đánh giá bằng Accuracy, Precision, Recall, F1 (theo từng lớp), confusion matrix. Với dữ liệu mất cân bằng, **ưu tiên F1 và Recall của lớp tấn công** thay vì chỉ nhìn Accuracy.
- Trả lời **câu hỏi 1**: lấy `feature_importances_` từ Random Forest/Decision Tree, vẽ top 10 đặc trưng; so sánh phân bố (boxplot) của các đặc trưng đó giữa Benign và DDoS (ví dụ: SYN flag count, flow duration, packet size).
- Trả lời **câu hỏi 2**: gom nhóm theo IP nguồn, tính các chỉ số hành vi (số flow, số IP đích khác nhau, tỷ lệ flow bị nhãn Botnet/tấn công) → xếp hạng IP đáng ngờ nhất. Có thể dùng thêm KMeans để phân nhóm hành vi (tùy chọn).
- Thử nghiệm thêm (tùy chọn nếu còn thời gian): Isolation Forest, SMOTE.

✅ *Mốc hoàn thành:* notebook mô hình chạy lại được + bảng so sánh 3 thuật toán + biểu đồ top đặc trưng + bảng xếp hạng IP.

---

### Giai đoạn 5 — Dashboard & tổng hợp (Tuần 9)

- Xây dựng dashboard (Power BI kết nối PostgreSQL, hoặc Streamlit/Plotly bằng Python) gồm 4 khu vực:
  1. Lưu lượng/băng thông theo thời gian và theo giao thức
  2. Tỷ lệ các loại tấn công và phân bố theo cổng dịch vụ
  3. Bảng xếp hạng IP rủi ro cao (kèm cờ blacklist)
  4. Hiệu suất các mô hình (F1, confusion matrix)
- Lập bảng "Câu hỏi → Cách trả lời → Kết quả → Hạn chế" cho đủ 4 câu hỏi nghiệp vụ.
- Phần "cảnh báo sớm": thể hiện dưới dạng danh sách IP/giờ vượt ngưỡng bất thường trên dashboard (tĩnh), không cần làm real-time.

✅ *Mốc hoàn thành:* dashboard chạy được + bảng tổng hợp trả lời 4 câu hỏi.

---

### Giai đoạn 6 — Báo cáo & bảo vệ (Tuần 10)

**Cấu trúc báo cáo gợi ý:**
1. Giới thiệu & mục tiêu
2. Cơ sở lý thuyết ngắn gọn (Data Warehouse/Star Schema, ETL, các thuật toán dùng, chỉ số đánh giá)
3. Mô tả dữ liệu và quy trình ETL
4. Thiết kế Data Warehouse (sơ đồ + truy vấn OLAP tiêu biểu)
5. Xây dựng và đánh giá mô hình khai phá dữ liệu
6. Dashboard và trả lời các câu hỏi nghiệp vụ
7. Kết luận, hạn chế, hướng phát triển
8. Tài liệu tham khảo, phụ lục (mã nguồn, schema SQL)

**Chuẩn bị bảo vệ:**
- Slide 12-15 trang, tập trung vào: sơ đồ pipeline tổng thể, star schema, kết quả so sánh mô hình, demo dashboard.
- Chuẩn bị trả lời các câu hỏi thường gặp: *Vì sao chọn star schema? Vì sao dùng F1 thay vì Accuracy? Vì sao lấy mẫu dữ liệu? Dữ liệu lab có đại diện cho mạng thật không?*
- Dành 2-3 ngày cuối để chạy thử toàn bộ pipeline từ đầu trên máy sạch và quay video demo dự phòng.

---

### Phân bổ thời gian gợi ý
Khoảng 8-10 giờ/tuần cho 1 sinh viên làm một mình (nếu làm nhóm 2-3 người, chia: ETL + DW / Data Mining / Dashboard + báo cáo).

### Rủi ro thường gặp và cách xử lý

| Rủi ro | Cách xử lý |
|---|---|
| File dữ liệu thiếu cột IP/Timestamp/Protocol (như bản Kaggle `chethuhn`) | Chỉ dùng `GeneratedLabelledFlows.zip` từ UNB; kiểm tra đủ 6 cột ngay Tuần 1; có Phương án B (UNSW-NB15 file gốc) nếu không tải được |
| Máy yếu, tràn RAM khi xử lý 2,8 triệu dòng | ETL đọc từng file, chỉ lấy 21 cột (file lớn nhất khoảng 0,7 triệu dòng); nếu vẫn thiếu RAM thì bật `sampling.enabled` trong `config.yaml` và ghi rõ trong báo cáo |
| SVM chạy quá lâu | Dùng `LinearSVC` hoặc huấn luyện trên tập con |
| Accuracy rất cao (>99%) gây nghi ngờ | Bình thường với CICIDS2017; nhưng cần kiểm tra data leakage (không để cột định danh lọt vào đặc trưng) và báo cáo thêm F1/Recall từng lớp |
| Blacklist không trùng IP nào | Báo cáo trung thực là một kết quả; giải thích IP lab không có trong blacklist thực tế |
| Timestamp mơ hồ AM/PM | Quy tắc giờ 1-7 = chiều (cấu hình `time.afternoon_hours`); kiểm tra `rows_outside_8_18` và đối chiếu giờ tấn công chính thức; ghi rõ giả định |
| Trễ tiến độ | Cắt các tính năng tùy chọn (KMeans, Isolation Forest, SMOTE) trước; giữ nguyên 4 tính năng cốt lõi |

---

## 8. Tổ chức thư mục dự án (Best Practice)

### 8.1. Cấu trúc đề xuất

```
network-anomaly-dwdm/
├── README.md                  # Giới thiệu, cách cài đặt, cách chạy lại từ đầu
├── requirements.txt           # Danh sách thư viện (ghi rõ phiên bản)
├── .gitignore                 # Loại trừ data, models, .env, __pycache__
├── .env.example               # Mẫu cấu hình kết nối DB (KHÔNG chứa mật khẩu thật)
├── config.yaml                # Đường dẫn, tham số (seed, tỷ lệ train/test, kích thước mẫu)
│
├── data/
│   ├── raw/                   # Dữ liệu gốc tải về, KHÔNG sửa, KHÔNG đưa lên Git
│   │   ├── cicids2017/        #   8 file CSV theo ngày
│   │   └── blacklist/         #   file FireHOL (.netset/.ipset)
│   ├── interim/               # Dữ liệu trung gian sau từng bước ETL (lấy mẫu, gộp)
│   └── processed/             # Dữ liệu sạch cuối cùng (Parquet/CSV) sẵn sàng nạp DW
│
├── notebooks/                 # Đánh số theo thứ tự thực hiện
│   ├── 01_eda.ipynb
│   ├── 02_etl_prototype.ipynb
│   ├── 03_olap_queries.ipynb
│   ├── 04_modeling.ipynb
│   └── 05_business_questions.ipynb
│
├── src/                       # Mã nguồn chính thức (script chạy lại được)
│   ├── etl/
│   │   ├── extract.py         # Đọc file CSV theo chunk
│   │   ├── transform.py       # Làm sạch, chuẩn hóa IP/Timestamp, gộp nhãn
│   │   ├── load.py            # Nạp vào PostgreSQL (dimension trước, fact sau)
│   │   └── run_etl.py         # Chạy toàn bộ pipeline: extract → transform → load
│   ├── mining/
│   │   ├── features.py        # Chọn đặc trưng, chia train/test, giảm mẫu tập train
│   │   ├── train.py           # Huấn luyện Decision Tree / Random Forest / SVM
│   │   ├── evaluate.py        # Chỉ số, confusion matrix, biểu đồ
│   │   └── business_questions.py  # Trả lời câu hỏi 1 và 2 bằng Data Mining
│   ├── olap/
│   │   └── run_queries.py     # Chạy các truy vấn trong sql/03_olap_queries.sql, xuất CSV ra reports/tables
│   └── utils/
│       ├── config.py          # Đọc config.yaml, .env
│       └── logger.py          # Ghi log số dòng trước/sau mỗi bước
│
├── sql/
│   ├── 01_create_schema.sql   # Tạo bảng fact/dimension, khóa, chỉ mục
│   ├── 02_load_dimensions.sql # (KHÔNG tạo: dimension được nạp bằng Python trong src/etl/load.py)
│   ├── 03_olap_queries.sql    # Các truy vấn OLAP (ROLLUP, drill-down...)
│   └── 04_views.sql           # View phục vụ dashboard
│
├── models/                    # Mô hình đã huấn luyện (.joblib) - không đưa lên Git
│
├── dashboard/                 # File Power BI (.pbix) hoặc app Streamlit
│
├── reports/
│   ├── figures/               # Biểu đồ xuất ra (PNG) dùng trong báo cáo
│   ├── tables/                # Bảng kết quả (CSV): so sánh mô hình, top IP...
│   └── final_report/          # Báo cáo cuối cùng + slide bảo vệ
│
├── docs/
│   ├── star_schema.png        # Sơ đồ star schema
│   ├── pipeline_diagram.png   # Sơ đồ luồng ETL → DW → Mining → Dashboard
│   └── decisions.md           # Nhật ký quyết định (vì sao lấy mẫu, gộp nhãn...)
│
└── tests/                     # test_transform.py, test_mining.py (kiểm thử); make_fixture_csv.py, generate_sample_data.py (dữ liệu GIẢ)
```

### 8.2. Nguyên tắc cần tuân thủ

| Nguyên tắc | Giải thích |
|---|---|
| **Dữ liệu gốc bất biến** | Không bao giờ sửa trực tiếp file trong `data/raw/`. Mọi thay đổi đều đi qua script ETL và ghi ra `interim/` hoặc `processed/`. |
| **Không đưa dữ liệu lớn và mô hình lên Git** | Thêm `data/`, `models/` vào `.gitignore`. Thay vào đó, ghi trong README link tải và cách tái tạo. |
| **Notebook để khám phá, script để chạy chính thức** | Thử nghiệm trong `notebooks/`; khi đã ổn thì chuyển logic sang `src/` để chạy lại được bằng 1 lệnh. |
| **Đánh số tên file** | `01_`, `02_`... cho notebook và file SQL để thấy rõ thứ tự thực hiện. |
| **Tách cấu hình khỏi mã nguồn** | Đường dẫn, seed ngẫu nhiên, kích thước mẫu để trong `config.yaml`; mật khẩu DB để trong `.env` (không commit). |
| **Cố định seed ngẫu nhiên** | Đặt `random_state=42` khi lấy mẫu và chia train/test để kết quả tái lập được. |
| **Ghi lại phiên bản thư viện** | `pip freeze > requirements.txt` để người khác (hoặc giảng viên) chạy lại được. |
| **Ghi nhật ký quyết định** | Mỗi lần chọn lấy mẫu/gộp nhãn/loại cột, ghi 1-2 dòng vào `docs/decisions.md` để dùng khi viết báo cáo và trả lời hội đồng. |

### 8.3. Mẫu `.gitignore`

```
data/
models/
.env
__pycache__/
.ipynb_checkpoints/
*.pbix.bak
```

### 8.4. Mẫu nội dung `README.md`

1. Tên đề tài và mô tả 2-3 dòng
2. Nguồn dữ liệu và cách tải (link, đặt vào thư mục nào)
3. Yêu cầu môi trường (Python, PostgreSQL) và cách cài: `pip install -r requirements.txt`
4. Thứ tự chạy (từ thư mục gốc dự án): chạy `sql/01_create_schema.sql` → `python -m src.etl.run_etl` → `python -m src.mining.train`
5. Cấu trúc thư mục (rút gọn)
6. Kết quả chính và thành viên thực hiện

### 8.5. Quy ước đặt tên
- Thư mục, file Python/SQL: chữ thường, dùng gạch dưới (`flow_features.py`, `01_create_schema.sql`).
- Bảng DW: tiền tố `fact_` / `dim_` (`fact_flow`, `dim_ip`).
- Cột: chữ thường, gạch dưới, không dấu cách (`flow_duration`, `src_ip`).
- Khóa thay thế (surrogate key): hậu tố `_key` (`time_key`, `ip_key`).
- Mô hình lưu: `rf_binary_v1.joblib`, `dt_multiclass_v1.joblib` (kèm phiên bản).

---

## 9. Thiết kế Star Schema

### 9.1. Quy trình thiết kế (4 bước Kimball)

| Bước | Quyết định |
|---|---|
| 1. Chọn quy trình nghiệp vụ | Giám sát lưu lượng mạng và phát hiện tấn công |
| 2. Khai báo **grain** (độ mịn) | **1 dòng fact = 1 luồng kết nối mạng (flow)**, tương ứng 1 dòng trong file CSV của CICIDS2017 |
| 3. Chọn các dimension | Thời gian, IP (nguồn/đích), giao thức, cổng đích/dịch vụ, nhãn traffic |
| 4. Chọn các measure | Thời lượng, số gói, số byte, tốc độ, kích thước gói trung bình, các cờ TCP (SYN/ACK/FIN/RST/PSH) |

### 9.2. Sơ đồ tổng quát

```
                      dim_time
                          |
dim_ip (src) ---+         |         +--- dim_protocol
                \         |        /
                 \        |       /
                  +--- fact_flow ---+
                 /        |       \
dim_ip (dst) ---+         |        +--- dim_label
                          |
                      dim_port
```

`dim_ip` được dùng 2 lần (role-playing dimension): một lần cho IP nguồn (`src_ip_key`), một lần cho IP đích (`dst_ip_key`).

### 9.3. Fact table: `fact_flow`

| Nhóm | Cột | Kiểu | Ý nghĩa |
|---|---|---|---|
| Khóa chính | `flow_key` | BIGSERIAL | Khóa thay thế của mỗi luồng |
| Khóa ngoại | `time_key`, `src_ip_key`, `dst_ip_key`, `protocol_key`, `dst_port_key`, `label_key` | INT/BIGINT | Liên kết tới 5 dimension |
| Degenerate | `flow_id`, `src_port`, `flow_start_ts` | VARCHAR/INT/TIMESTAMP | Thuộc tính của luồng, không đáng tách thành bảng riêng (cổng nguồn thường là cổng ngẫu nhiên) |
| Measure | `flow_duration_us` | BIGINT | Thời lượng luồng (micro giây) |
| Measure | `total_fwd_packets`, `total_bwd_packets`, `total_packets` | INT | Số gói tin chiều đi / về / tổng |
| Measure | `total_fwd_bytes`, `total_bwd_bytes`, `total_bytes` | BIGINT | Số byte chiều đi / về / tổng |
| Measure | `flow_bytes_per_s`, `flow_packets_per_s` | DOUBLE | Tốc độ truyền |
| Measure | `avg_packet_size` | REAL | Kích thước gói trung bình |
| Measure | `syn_flag_count`, `ack_flag_count`, `fin_flag_count`, `rst_flag_count`, `psh_flag_count` | SMALLINT | Số cờ TCP (SYN cao là dấu hiệu quan trọng của DDoS/Port Scan) |

Toàn bộ measure đều là **additive** (cộng được) hoặc **semi-additive**: `total_bytes`, `total_packets` cộng được theo mọi chiều; các cột tốc độ và trung bình (`*_per_s`, `avg_*`) **không được SUM**, chỉ dùng AVG/MIN/MAX.

### 9.4. Các dimension

**`dim_time`** (mức độ chi tiết: phút)

| Cột | Ý nghĩa |
|---|---|
| `time_key` | Khóa dạng yyyymmddHHMM (dùng BIGINT vì vượt giới hạn INT) |
| `full_datetime`, `date_value` | Thời điểm đầy đủ / ngày |
| `year_num`, `month_num`, `day_num`, `day_name`, `hour_num`, `minute_num` | Các cấp bậc thời gian để drill-down |
| `time_period` | Sáng / Chiều / Tối / Đêm |
| `is_business_hours` | TRUE nếu 08:00-17:59 và thứ 2-thứ 6 (phục vụ câu hỏi 3) |

*Lưu ý:* CICIDS2017 chỉ ghi 5 ngày thứ 2-thứ 6 nên không có dữ liệu cuối tuần, vì vậy không cần cột `is_weekend`. Dữ liệu cũng chỉ phủ khoảng 9h-17h nên cột `is_business_hours` gần như luôn TRUE; vẫn giữ cột này (để mở rộng sang dữ liệu khác), nhưng phân tích câu hỏi 3 dùng `hour_num` và `time_period`.

**`dim_ip`** (role-playing: nguồn và đích)

| Cột | Ý nghĩa |
|---|---|
| `ip_key`, `ip_address` | Khóa thay thế / địa chỉ IP (kiểu INET) |
| `is_internal` | IP nội bộ hay IP ngoài mạng |
| `network_segment` | Dải mạng /24, phục vụ roll-up từ IP lên mạng con |
| `is_blacklisted`, `blacklist_source` | Đối chiếu với blacklist FireHOL (phục vụ câu hỏi 4) |

**`dim_protocol`**: `protocol_key`, `protocol_number` (6, 17, 1...), `protocol_name` (TCP/UDP/ICMP).

**`dim_port`**: `port_key`, `port_number`, `service_name` (HTTP, HTTPS, SSH, FTP, DNS... hoặc "Other"), `port_range` (Well-known 0-1023 / Registered 1024-49151 / Dynamic 49152+).

**`dim_label`**: `label_key`, `label_raw` (nhãn gốc, ví dụ "DoS Hulk", "PortScan"), `attack_group` (Benign / DDoS / PortScan / WebAttack / Botnet / Other), `is_attack`.

### 9.5. Phân cấp (hierarchy) phục vụ drill-down / roll-up

| Dimension | Phân cấp |
|---|---|
| Thời gian | Năm → Tháng → Ngày → Giờ → Phút |
| IP | Nội bộ/Ngoài mạng → Dải /24 → Địa chỉ IP |
| Cổng | Dải cổng → Dịch vụ → Số cổng |
| Nhãn | Tấn công/Bình thường → `attack_group` → `label_raw` |

### 9.6. Ma trận bus: câu hỏi nghiệp vụ ↔ dimension

| Câu hỏi | dim_time | dim_ip | dim_protocol | dim_port | dim_label | Measure chính |
|---|:-:|:-:|:-:|:-:|:-:|---|
| Q1. Đặc trưng phân biệt DDoS | | | | | ✔ | syn_flag_count, avg_packet_size, flow_duration, packets/s |
| Q2. IP giống botnet nhất | | ✔ | | | ✔ | số flow, số IP đích khác nhau |
| Q3. Giao thức bất thường ngoài giờ | ✔ | | ✔ | | | total_bytes |
| Q4. IP quét cổng nhiều nhất | | ✔ | | ✔ | ✔ | số flow, số cổng bị quét |

### 9.7. Quyết định thiết kế quan trọng

| Quyết định | Lý do |
|---|---|
| **Fact gọn, không chứa cả ~80 đặc trưng** | Fact chỉ giữ ~15 measure phục vụ OLAP. Bộ đặc trưng đầy đủ để huấn luyện mô hình lưu riêng (file Parquet trong `data/processed/` hoặc bảng `flow_features` nối với fact qua `flow_key`), tránh bảng fact quá rộng và chậm. |
| **Dùng khóa thay thế (surrogate key)** | Không dùng trực tiếp IP/nhãn làm khóa: join nhanh hơn và dễ thay đổi thuộc tính. |
| **`dim_ip` dạng SCD Type 1** | Dữ liệu là snapshot cố định, không có lịch sử thay đổi nên ghi đè là đủ; không cần SCD Type 2. |
| **Cổng nguồn là degenerate dimension** | Cổng nguồn thường là cổng ngẫu nhiên (ephemeral), giá trị rất phân tán, tách thành dimension không mang lại giá trị phân tích. |
| **Star thay vì Snowflake** | Các dimension nhỏ, đơn giản; star giúp truy vấn ít join hơn và dễ giải thích khi bảo vệ. |
| **`dim_time` mức phút** | Đủ cho phân tích theo giờ/khung giờ (5 ngày × 1.440 phút = 7.200 dòng), nhẹ hơn mức giây. |

### 9.8. Thứ tự nạp dữ liệu và kiểm tra

1. Nạp các dimension trước: `dim_time` (sinh theo phạm vi thời gian của dữ liệu), `dim_protocol`, `dim_label`, `dim_port`, `dim_ip` (rồi cập nhật cờ `is_blacklisted`).
2. Nạp `fact_flow` sau cùng, tra cứu khóa thay thế từ từng dimension.
3. Kiểm tra sau khi nạp:
   - Số dòng `fact_flow` = số dòng trong `data/processed/` (không mất dòng).
   - Không có khóa ngoại NULL hoặc mồ côi (mọi `*_key` đều tồn tại trong dimension).
   - `total_bytes` = `total_fwd_bytes` + `total_bwd_bytes`.
   - Tổng số flow theo từng `attack_group` khớp với thống kê ở bước EDA.

### 9.9. File đi kèm
- `01_create_schema.sql`: script tạo toàn bộ bảng, khóa, chỉ mục (PostgreSQL).
- `03_olap_queries.sql`: các truy vấn OLAP mẫu (GROUP BY, ROLLUP, CUBE, drill-down) cho 4 câu hỏi nghiệp vụ.

Hai file này tương ứng với thư mục `sql/` trong cấu trúc dự án ở mục 8.

---

## 10. Triển khai truy vấn OLAP

### 10.1. Ánh xạ phép toán OLAP và truy vấn

| Phép toán OLAP | Ý nghĩa | Truy vấn minh họa |
|---|---|---|
| **Slice** | Cắt theo 1 giá trị của 1 chiều | `olap_slice_friday` (chỉ thứ Sáu) |
| **Dice** | Cắt theo nhiều chiều cùng lúc | `olap_dice_friday_tcp_attacks` (thứ Sáu + TCP + DDoS/PortScan) |
| **Roll-up** | Gộp từ chi tiết lên tổng | `q3_rollup_protocol_period`, `olap_rollup_day_hour_attack` (`GROUP BY ROLLUP`) |
| **Drill-down** | Đi từ tổng xuống chi tiết | `q3_protocol_by_hour` (từ giao thức xuống từng giờ) |
| **Pivot** | Xoay chiều thành cột | `olap_pivot_attack_by_day` (nhóm nhãn × thứ trong tuần) |
| **Cube** | Mọi tổ hợp tổng hợp | `olap_cube_attack_service` (`GROUP BY CUBE`) |
| **Hàm cửa sổ** | Xếp hạng, so sánh trong nhóm | `q2_top_ip_per_attack_group` (RANK), `q3_bytes_zscore` (AVG/STDDEV OVER) |

### 10.2. Danh sách truy vấn (file `sql/03_olap_queries.sql`, 21 truy vấn)

| Nhóm | Truy vấn | Trả lời |
|---|---|---|
| Kiểm tra chất lượng | `qc_row_counts`, `qc_label_distribution`, `qc_measure_consistency`, `qc_time_range` | Nạp đủ dòng chưa, phân bố nhãn, tổng byte/gói có khớp không, dữ liệu phủ khung giờ nào |
| Câu hỏi 1 | `q1_feature_profile`, `q1_ddos_vs_benign`, `q1_traffic_spike_minutes` | Đặc trưng nào khác biệt nhất giữa Benign và DDoS; phút tăng đột biến là hợp lệ hay tấn công |
| Câu hỏi 2 | `q2_src_ip_behavior`, `q2_top_ip_per_attack_group`, `q2_bot_destinations` | IP nào giống botnet nhất, top IP mỗi nhóm tấn công, máy nghi nhiễm đang liên lạc tới đâu |
| Câu hỏi 3 | `q3_protocol_by_hour`, `q3_rollup_protocol_period`, `q3_bytes_zscore`, `q3_offhours_by_protocol` | Băng thông giao thức theo giờ, giờ nào lệch bất thường |
| Câu hỏi 4 | `q4_portscan_sources`, `q4_blacklist_contacts` | IP quét cổng nhiều nhất, máy nào liên lạc với IP trong blacklist |
| Phép toán OLAP | `olap_slice_friday`, `olap_dice_friday_tcp_attacks`, `olap_pivot_attack_by_day`, `olap_rollup_day_hour_attack`, `olap_cube_attack_service` | Minh họa slice/dice/pivot/roll-up/cube |

File `sql/04_views.sql` tạo thêm: `vw_flow_enriched` (view phẳng cho Power BI), `mv_traffic_hourly` (băng thông theo giờ × giao thức) và `mv_ip_risk` (xếp hạng IP rủi ro: mức Cao / Trung bình / Thấp theo tỷ lệ flow tấn công, kèm cờ riêng `co_lien_lac_blacklist`).

### 10.3. Cách chạy

```
# 1. Tạo schema và nạp dữ liệu (ETL), sau đó tạo view
psql -d <ten_db> -f sql/01_create_schema.sql
python -m src.etl.run_etl
psql -d <ten_db> -f sql/04_views.sql

# 2. Chạy toàn bộ truy vấn OLAP, xuất CSV ra reports/tables/
python -m src.olap.run_queries
python -m src.olap.run_queries --only qc_ q4_    # chỉ chạy một số nhóm
python -m src.olap.run_queries --list            # xem danh sách tên truy vấn
```

Script kết nối qua biến môi trường chuẩn của PostgreSQL (`PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD`); một truy vấn lỗi không làm dừng các truy vấn còn lại. CSV xuất ra có mã hóa `utf-8-sig` để mở trong Excel không bị lỗi tiếng Việt.

### 10.4. Kiểm thử trước khi có dữ liệu thật

`tests/generate_sample_data.py` sinh khoảng 70.000 flow **giả** mô phỏng lịch tấn công và các IP của CICIDS2017 rồi nạp vào đúng star schema, để bạn viết và thử SQL ngay cả khi chưa tải được dữ liệu thật:

```
python tests/generate_sample_data.py
```

Mình đã chạy thử trên PostgreSQL 16: script tạo schema chạy được, cả 21 truy vấn OLAP và các view đều chạy thành công. **Chưa kiểm thử trên dữ liệu CICIDS2017 thật**, nên khi có dữ liệu thật cần chạy lại `qc_*` trước tiên. Kết quả từ dữ liệu giả chỉ để kiểm tra SQL đúng, **tuyệt đối không dùng làm số liệu trong báo cáo**.

### 10.5. Những điểm cần chú ý khi chạy trên dữ liệu thật

| Vấn đề | Cách xử lý |
|---|---|
| Không có flow ngoài giờ hành chính (`flows_ngoai_gio = 0` ở `qc_time_range`) | Dùng nhóm `q3_*` (theo giờ và z-score); `q3_offhours_by_protocol` trả rỗng là bình thường |
| IP nguồn tấn công là `172.16.0.1` do NAT | Không lọc theo `is_internal`; ghi rõ trong báo cáo khi diễn giải câu hỏi 2 và 4 |
| `is_blacklisted` toàn FALSE với IP tấn công | Bình thường (IP lab); `q4_blacklist_contacts` mới có thể có kết quả ở phía lưu lượng Benign |
| Nhiều máy cùng bị đánh dấu rủi ro nếu dùng blacklist | Đã tách `risk_level` (theo tỷ lệ tấn công) khỏi `co_lien_lac_blacklist`; không gộp thành một điểm |
| Truy vấn chậm trên vài trăm nghìn đến vài triệu dòng | Chạy `ANALYZE;` sau khi nạp, kiểm tra bằng `EXPLAIN ANALYZE`, dùng materialized view cho dashboard, và làm mới bằng `REFRESH MATERIALIZED VIEW` sau mỗi lần nạp lại |
| Nhãn thật có thể khác tên mẫu (ví dụ ký tự lạ trong "Web Attack") | Truy vấn lọc theo `attack_group` chứ không theo `label_raw`; chỉ cần ETL gộp nhãn đúng |

### 10.6. Gợi ý trình bày kết quả trong báo cáo
- Mỗi câu hỏi nghiệp vụ: nêu truy vấn, dán bảng kết quả (từ `reports/tables/*.csv`) và 2-3 câu nhận xét.
- Biểu đồ nên dùng: cột/đường cho `q3_protocol_by_hour`, heatmap giờ × giao thức cho `q3_bytes_zscore`, cột chồng cho `olap_pivot_attack_by_day`, bảng top-N cho `q2_*` và `q4_*`.
- Nêu rõ giới hạn dữ liệu (snapshot 5 ngày, môi trường lab, NAT) ngay dưới các kết quả liên quan.

---

## 11. Triển khai ETL

### 11.1. Đối chiếu cột nguồn với kho dữ liệu

File `GeneratedLabelledFlows` có **85 cột** (đã đối chiếu với dòng mẫu thật). ETL chỉ nạp 21 cột cần cho star schema; ~64 đặc trưng còn lại để dành cho giai đoạn Data Mining (đọc lại trực tiếp từ file gốc).

| Cột trong CSV | Cột trong kho | Xử lý |
|---|---|---|
| `Flow ID` | `fact_flow.flow_id` | Giữ nguyên; **không duy nhất** (cùng 5-tuple có thể lặp) nên không dùng làm khóa |
| `Source IP`, `Destination IP` | `dim_ip` (nguồn/đích) | Kiểm tra hợp lệ, chuẩn hóa IPv4/IPv6; thêm `is_internal`, `network_segment`, `is_blacklisted` |
| `Source Port` | `fact_flow.src_port` | Degenerate dimension |
| `Destination Port` | `dim_port` | Gắn tên dịch vụ và dải cổng |
| `Protocol` | `dim_protocol` | Số 6/17/0... → TCP/UDP/HOPOPT |
| `Timestamp` | `dim_time`, `fact_flow.flow_start_ts` | Phân tích `d/m/yyyy h:mm`, đổi giờ chiều (+12), tạo `time_key` yyyymmddHHMM |
| `Flow Duration`, `Total Fwd Packets`, `Total Backward Packets`, `Total Length of Fwd/Bwd Packets` | measure cùng tên | Ép số, loại giá trị âm/thiếu; tính thêm `total_packets`, `total_bytes` |
| `Flow Bytes/s`, `Flow Packets/s`, `Average Packet Size` | measure cùng tên | `Infinity`/`NaN` (thời lượng = 0) → NULL (giữ dòng) |
| `FIN/SYN/RST/PSH/ACK Flag Count` | `*_flag_count` | Ép số, thiếu → 0 |
| `Label` | `dim_label` | Sửa ký tự gạch ngang lỗi trong nhãn Web Attack; gộp thành `attack_group` |

### 11.2. Các bước làm sạch (mỗi bước ghi số dòng bị loại vào `reports/tables/etl_summary.csv`)

| Thứ tự | Cột thống kê | Quy tắc |
|---|---|---|
| 1 | `drop_null_key` | Loại dòng thiếu IP, cổng, giao thức, timestamp hoặc nhãn (gồm cả dòng trống/toàn dấu phẩy) |
| 2 | `drop_bad_numeric_key` | Loại dòng có cổng/giao thức không phải số |
| 3 | `drop_invalid_ip` | Loại dòng có IP không hợp lệ |
| 4 | `drop_bad_timestamp`, `drop_out_of_range_date` | Loại dòng không phân tích được timestamp hoặc ngoài khoảng 3-7/7/2017 |
| 5 | `drop_negative_or_missing_measure` | Loại dòng có thời lượng/số gói/số byte âm hoặc thiếu |
| 6 | `drop_duplicates` | Loại dòng trùng hoàn toàn |
| (theo dõi) | `ts_pm_adjusted`, `rows_outside_8_18` | Số dòng đã đổi sang buổi chiều; số dòng còn nằm ngoài 08:00-17:59 (để kiểm chứng quy tắc AM/PM) |

### 11.3. Ba điểm rút ra từ dữ liệu thật (dòng mẫu và blacklist)

1. **Timestamp chỉ chính xác đến phút, không có AM/PM:** `time_key` mức phút khớp hoàn toàn; phân tích theo giây là không thể.
2. **Cột `Fwd Header Length` xuất hiện hai lần** trong header: không ảnh hưởng vì ETL không nạp cột này; nếu dùng cho mô hình, pandas sẽ tự đổi tên thành `Fwd Header Length.1`.
3. **Blacklist FireHOL level1 chứa dải IP nội bộ** (list `fullbogons`). Nếu so khớp tất cả IP, mọi máy `192.168.10.x` và `172.16.0.1` sẽ bị đánh dấu blacklist sai. ETL chỉ kiểm tra IP công cộng (`is_global`).

### 11.4. Cách chạy

```
# Chuẩn bị (một lần)
pip install -r requirements.txt
cp .env.example .env                       # điền thông tin PostgreSQL
# giải nén GeneratedLabelledFlows.zip vào data/raw/cicids2017/
# tải firehol_level1.netset vào data/raw/blacklist/

# Chạy ETL (từ thư mục gốc dự án)
python -m src.etl.run_etl --create-schema  # lần đầu: tạo bảng, làm sạch, nạp, đối soát
python -m src.etl.run_etl --limit-files 1  # chạy thử với 1 file trước khi chạy toàn bộ
python -m src.etl.run_etl --transform-only # chỉ làm sạch -> Parquet + etl_summary.csv
python -m src.etl.run_etl --load-only      # chỉ nạp lại từ Parquet đã có

# Sau khi nạp xong
psql -d <ten_db> -f sql/04_views.sql
python -m src.olap.run_queries --only qc_  # kiểm tra chất lượng dữ liệu trước
python -m src.olap.run_queries
python -m pytest tests -v                  # kiểm thử các hàm làm sạch
```

Lưu ý: `--create-schema` xóa và tạo lại các bảng (kèm các view phụ thuộc), nên cần chạy lại `04_views.sql` sau đó. Bước nạp chạy trong **một transaction**: nếu lỗi giữa chừng thì rollback, không để lại dữ liệu nạp dở. Cuối cùng ETL tự **đối soát** số dòng `fact_flow` với số dòng sạch và kiểm tra khóa thời gian mồ côi.

### 11.5. Đã kiểm thử gì và chưa kiểm thử gì

| Nội dung | Tình trạng |
|---|---|
| 17 kiểm thử đơn vị (`tests/test_transform.py`), dùng dòng mẫu thật bạn cung cấp: định dạng ngày, đổi AM/PM, sửa nhãn, IP, các dòng lỗi | Đã chạy, đạt 17/17 |
| Chạy đầu-cuối trên PostgreSQL 16 với 3 file CSV **mô phỏng đúng 85 cột và cách mã hóa** của file thật (có IPv6, dòng trống, IP sai, giá trị âm, `Infinity`, dòng trùng, byte lạ trong nhãn Web Attack): đối soát khớp, blacklist chỉ đánh dấu IP công cộng, cả 21 truy vấn OLAP chạy được | Đã chạy |
| Chạy trên **8 file CICIDS2017 thật (~2,8 triệu dòng)**: thời gian chạy, dung lượng RAM, tên nhãn thật, giờ thật sau khi đổi AM/PM | **Chưa**; cần chạy và kiểm tra bằng `etl_summary.csv` và `qc_time_range` |

### 11.6. Danh sách kiểm tra khi chạy dữ liệu thật
1. `etl_summary.csv`: số dòng bị loại ở mỗi bước có hợp lý không (không nên loại quá vài phần trăm).
2. `rows_outside_8_18` gần 0; nếu lớn thì xem lại `time.afternoon_hours` trong `config.yaml`.
3. `qc_label_distribution`: các nhãn khớp danh sách chính thức (Benign, DoS Hulk, PortScan, DDoS, Bot, Web Attack..., Infiltration, Heartbleed...).
4. `qc_time_range`: khung giờ mỗi ngày và `flows_ngoai_gio`.
5. Số dòng `fact_flow` khớp với dòng "TỔNG" trong log ETL.

### 11.7. Hạn chế cần nêu trong báo cáo
- Blacklist FireHOL tải ở thời điểm hiện tại (2026) nhưng lưu lượng là của năm 2017: một IP có thể đã đổi chủ, nên cờ `is_blacklisted` chỉ mang tính minh họa.
- Việc loại dòng trùng hoàn toàn có thể loại cả một số flow hợp lệ lặp lại giống hệt nhau trong cùng một phút.
- Chỉ loại trùng trong từng file, không loại trùng giữa các file.
- Địa chỉ multicast IPv6 (ví dụ `ff02::fb`) không được tính là IP nội bộ.

---

## 12. Triển khai Data Mining

### 12.1. Luồng xử lý

```
Parquet sạch (data/processed/clean, ~80 đặc trưng số)
   -> chọn đặc trưng (bỏ IP, timestamp, flow_id, src_port; bỏ hằng số và tương quan > 0,98)
   -> chia train/test (giữ nguyên phân bố tự nhiên ở tập test)
   -> giảm mẫu CHỈ tập train (cân bằng bớt các lớp)
   -> huấn luyện Decision Tree, Random Forest, SVM cho 2 bài toán (nhị phân, đa lớp)
   -> đánh giá, xuất bảng/biểu đồ -> trả lời câu hỏi nghiệp vụ 1 và 2
```

**Việc cần làm một lần trước khi chạy:** Parquet sạch cũ chỉ có 21 cột. ETL đã được sửa để giữ thêm các đặc trưng số (`etl.keep_all_features: true` trong `config.yaml`), nên cần chạy lại bước làm sạch:

```
python -m src.etl.run_etl --transform-only
```

Kho dữ liệu không bị ảnh hưởng (tập dòng giữ nguyên vì việc loại dòng trùng chỉ xét 21 cột chính), nên **không cần nạp lại PostgreSQL**; OLAP và Data Mining dùng chung một tập dòng.

### 12.2. Các quyết định phương pháp (nên nêu trong báo cáo)

| Vấn đề | Quyết định | Lý do |
|---|---|---|
| Đặc trưng bị loại | `src_ip`, `dst_ip`, `flow_start_ts`, `flow_id`, nhãn, và `src_port` | Tránh để mô hình học thuộc địa chỉ, thời điểm hoặc cổng ngẫu nhiên thay vì hành vi traffic |
| `dst_port`, `protocol_number` | **Giữ**, nhưng có tùy chọn bỏ để so sánh | Trong môi trường lab, mỗi loại tấn công nhắm vào cổng cố định (80, 22, 21...), nên mô hình có thể "đi đường tắt" bằng cổng đích. Chạy thêm với `--drop-features dst_port protocol_number` để xem mức giảm điểm |
| Thứ tự chia và cân bằng | Chia train/test **trước**, rồi mới giảm mẫu **chỉ tập train** | Tập test giữ phân bố thật (Benign chiếm đa số) nên Precision, Recall, FPR phản ánh đúng thực tế; giảm mẫu trước khi chia sẽ làm sai các chỉ số này |
| Cách chia | `stratified` (mặc định) và `time_block` (phần đầu theo thời gian của mỗi nhãn để train, phần cuối để test) | Chia ngẫu nhiên khiến các flow liền kề gần như giống hệt nhau nằm ở cả hai tập, làm điểm cao giả tạo. `time_block` khắt khe hơn. Nên báo cáo cả hai và so sánh |
| Mất cân bằng lớp | `class_weight='balanced'` + giảm mẫu tập train (Benign tối đa 200.000, mỗi nhãn tấn công tối đa 50.000) | Đơn giản, không tạo dữ liệu giả như SMOTE |
| Đặc trưng tương quan | Bỏ một trong hai đặc trưng có \|r\| > 0,98 | Làm bảng độ quan trọng đặc trưng dễ đọc, không bị chia đôi giữa các đặc trưng gần như trùng nhau |
| SVM | `LinearSVC` huấn luyện trên tập con (mặc định 50.000 dòng, chia đều theo nhãn); có thể đổi sang RBF (`svm.kernel: rbf`, 20.000 dòng) | SVM không chạy nổi trên hàng trăm nghìn dòng |
| Chỉ số chính | Nhị phân: F1, Recall, Precision của lớp tấn công, **FPR**, ROC-AUC, PR-AUC. Đa lớp: macro-F1, F1 từng lớp | Accuracy gần 100% vì Benign chiếm đa số nên không đủ thông tin; FPR cho biết tỷ lệ báo động nhầm (quan trọng với quản trị viên mạng) |

### 12.3. Cách chạy

```
python -m src.mining.train                               # nhị phân + đa lớp, DT + RF + SVM
python -m src.mining.train --models dt svm               # bỏ Random Forest nếu máy chậm
python -m src.mining.train --split-mode time_block       # chia theo thời gian (kết quả có hậu tố _timeblock)
python -m src.mining.train --drop-features dst_port protocol_number   # thử nghiệm bỏ cổng/giao thức (hậu tố _no_...)
python -m src.mining.train --max-rows 300000             # chạy thử nhanh

python -m src.mining.business_questions                  # trả lời câu hỏi 1 và 2
python -m src.mining.business_questions --only q1 --drop-features dst_port protocol_number
python -m pytest tests -v                                # kiểm thử
```

Mọi tham số (tỷ lệ chia, số dòng tối đa, siêu tham số mô hình, ngưỡng tương quan) nằm trong mục `mining:` của `config.yaml`. Random Forest là bước chậm nhất; trên dữ liệu thật tập train khoảng vài trăm nghìn dòng nên có thể mất vài phút đến vài chục phút tùy CPU. Nếu quá chậm, giảm `train_benign_cap` hoặc `n_estimators`.

### 12.4. File kết quả (đưa vào báo cáo)

| File | Nội dung |
|---|---|
| `reports/tables/model_comparison_binary.csv`, `..._multiclass.csv` | Bảng so sánh 3 mô hình (chỉ số, thời gian huấn luyện/dự đoán) |
| `reports/tables/classification_report_*.csv` | Precision/Recall/F1 và **support** của từng lớp |
| `reports/tables/split_summary.csv` | Số dòng mỗi nhãn ở tập train (sau giảm mẫu) và tập test |
| `reports/tables/feature_importance_*.csv` | Độ quan trọng đặc trưng của từng mô hình |
| `reports/tables/mining_run_info.json` | Tham số, danh sách đặc trưng giữ lại/bị loại, phiên bản thư viện (phục vụ tái lập) |
| `reports/figures/confusion_*.png`, `importance_*.png`, `model_comparison_*.png` | Ma trận nhầm lẫn, top đặc trưng, so sánh mô hình |
| `models/*.joblib` | Mô hình đã huấn luyện (kèm danh sách đặc trưng) |
| `reports/tables/q1_*.csv/.txt/.json`, `reports/figures/q1_top_features_*.png` | Kết quả câu hỏi 1 |
| `reports/tables/q2_*.csv/.json`, `reports/figures/q2_ip_clusters.png` | Kết quả câu hỏi 2 |

### 12.5. Trả lời câu hỏi nghiệp vụ bằng Data Mining

**Câu hỏi 1: đặc trưng nào phân biệt rõ nhất traffic hợp lệ (kể cả khi lưu lượng tăng cao) và DDoS?**
- Chạy với hai phạm vi Benign: `all` (mọi traffic hợp lệ) và `busy` (chỉ traffic hợp lệ trong 5% số phút có lưu lượng cao nhất, tương ứng với "đợt tăng lưu lượng hợp lệ" trong câu hỏi).
- Mỗi phạm vi xếp hạng đặc trưng bằng ba cách để kiểm chứng chéo: (1) AUC đơn biến kèm trung vị từng lớp và chiều khác biệt, (2) permutation importance của Random Forest, (3) cây quyết định độ sâu 3 cho luật dễ đọc (`q1_tree_rules_*.txt`).
- Cách viết kết luận: nêu 3-5 đặc trưng đứng đầu cả ba cách, mô tả chiều khác biệt (ví dụ "DDoS có số gói chiều về thấp hơn nhiều"), và so sánh hai phạm vi `all` với `busy`. Nếu thứ hạng đổi nhiều khi chuyển sang `busy` thì đặc trưng đó chỉ phân biệt được khi so với traffic bình thường chứ không phải khi so với traffic cao điểm.
- Nên chạy thêm bản bỏ `dst_port` và `protocol_number` để loại ảnh hưởng của "đường tắt" cổng đích.

**Câu hỏi 2: IP nào có hành vi giống botnet nhất?**
- Lập hồ sơ hành vi theo IP nguồn (số flow, số IP đích, số cổng đích, thời lượng và số byte trung bình, tốc độ gói, tỷ lệ cờ SYN/RST, tỷ lệ TCP) **không dùng nhãn**, phân cụm KMeans (chọn k bằng silhouette), rồi xếp hạng mọi IP theo khoảng cách tới hồ sơ trung bình của các IP đã biết là botnet.
- Kiểm chứng bằng **leave-one-out**: giấu từng IP botnet, dùng các IP botnet còn lại làm tham chiếu, xem IP bị giấu xếp hạng thứ mấy. Phân vị trung vị càng nhỏ hơn 0,5 (mức ngẫu nhiên) thì cách xếp hạng càng có giá trị.
- **Kết quả có thể là âm tính:** nếu các máy nhiễm botnet vẫn chủ yếu sinh traffic bình thường thì hồ sơ của chúng sẽ không khác biệt. Khi đó phải báo cáo đúng như vậy (đây là một kết luận hợp lệ: hồ sơ hành vi cấp IP không đủ để nhận diện botnet), và dùng bảng xếp hạng OLAP `q2_src_ip_behavior` làm câu trả lời mô tả.

### 12.6. Những điểm cần cẩn thận khi diễn giải

- **Điểm rất cao (99%+) là bình thường với CICIDS2017** và không có nghĩa là bài toán dễ; hãy kèm FPR, kết quả `time_block` và kết quả khi bỏ `dst_port` để thấy mô hình mạnh đến đâu khi bị hạn chế "đường tắt".
- **Các lớp hiếm có rất ít dòng ở tập test** (ví dụ SQL Injection chỉ có 21 dòng, Heartbleed 11 dòng, Infiltration 36 dòng), nên chỉ số của các lớp đó dao động mạnh; luôn nêu cột `support` khi trình bày F1 từng lớp.
- **Nhóm `Other` gộp nhiều kiểu khác nhau** (DoS Hulk/GoldenEye/slowloris/Slowhttptest, FTP/SSH-Patator, Infiltration, Heartbleed) nên F1 của nhóm này khó diễn giải; nếu cần phân tích sâu, đổi `multiclass_target: label_raw` để phân loại theo 15 nhãn gốc.
- Nhãn của CICIDS2017 có sai sót đã được cộng đồng nghiên cứu ghi nhận, nên không nên xem mọi "lỗi" của mô hình là lỗi thật của mô hình.
- Đặc trưng `dst_port` và `protocol_number` là biến phân loại được mã hóa bằng số; biểu đồ boxplot của chúng trong Q1 chỉ mang tính tham khảo.

### 12.7. Đã kiểm thử gì và chưa kiểm thử gì

| Nội dung | Tình trạng |
|---|---|
| 32 kiểm thử đơn vị (ETL và Data Mining: chia train/test, giảm mẫu, loại đặc trưng, chỉ số, hồ sơ IP, leave-one-out, phân cụm) | Đã chạy, đạt 32/32 |
| Chạy đầu-cuối ETL, nạp kho, huấn luyện cả 3 mô hình cho 2 bài toán, chế độ `time_block`, bỏ đặc trưng, Q1 và Q2, trên **56.649 dòng dữ liệu GIẢ** đúng định dạng 85 cột (`tests/make_fixture_csv.py`); các file kết quả và biểu đồ đều được tạo ra | Đã chạy |
| Chạy trên **dữ liệu CICIDS2017 thật** (~2,8 triệu dòng): thời gian chạy, RAM, và chất lượng mô hình thật | **Chưa**; số liệu từ dữ liệu giả hoàn toàn vô nghĩa về mặt kết quả, chỉ chứng minh code chạy đúng |

### 12.8. Gợi ý trình bày trong báo cáo
1. Bảng so sánh 3 mô hình (nhị phân và đa lớp) từ `model_comparison_*.csv`, nêu rõ kích thước tập train/test.
2. Ma trận nhầm lẫn của mô hình tốt nhất và nhận xét các lớp bị nhầm với nhau.
3. Bảng thử nghiệm so sánh: (chia ngẫu nhiên và chia theo thời gian) x (có và không có `dst_port`) để thể hiện độ tin cậy của kết quả.
4. Top đặc trưng và luật cây nông cho câu hỏi 1; bảng xếp hạng IP và kết quả leave-one-out cho câu hỏi 2.
5. Mục hạn chế: dữ liệu mô phỏng trong lab, nhãn có sai sót, phân bố tấn công cố định theo ngày giờ, mô hình chưa kiểm thử trên traffic mạng thật.

---

## 13. Bản đồ file: file nào để ở đâu

Các file đã được sắp đúng theo cấu trúc thư mục dự án; chỉ cần chép nguyên cây thư mục vào thư mục gốc dự án (`network-anomaly-dwdm/`). Mọi lệnh đều chạy từ thư mục gốc này.

### 13.1. Cây thư mục

```
network-anomaly-dwdm/                  <- thư mục gốc, chạy mọi lệnh tại đây
│
├── config.yaml                        # cấu hình (đường dẫn, tham số ETL, tham số mô hình)
├── requirements.txt                   # thư viện: pip install -r requirements.txt
├── .env.example                       # chép thành .env rồi điền mật khẩu PostgreSQL
├── de_cuong_network_anomaly_detection.md   # báo cáo đề cương (tài liệu, không phải mã nguồn)
│
├── sql/
│   ├── 01_create_schema.sql           # tạo star schema
│   ├── 03_olap_queries.sql            # 21 truy vấn OLAP
│   └── 04_views.sql                   # view cho dashboard
│
├── src/
│   ├── __init__.py                    # file rỗng, BẮT BUỘC giữ (5 file __init__.py)
│   ├── etl/
│   │   ├── __init__.py
│   │   ├── extract.py                 # đọc CSV gốc
│   │   ├── transform.py               # làm sạch
│   │   ├── load.py                    # nạp vào PostgreSQL
│   │   └── run_etl.py                 # <- file CHẠY của ETL
│   ├── olap/
│   │   ├── __init__.py
│   │   └── run_queries.py             # <- file CHẠY của OLAP
│   ├── mining/
│   │   ├── __init__.py
│   │   ├── features.py                # chuẩn bị dữ liệu, chia train/test
│   │   ├── evaluate.py                # chỉ số và biểu đồ
│   │   ├── train.py                   # <- file CHẠY: huấn luyện mô hình
│   │   └── business_questions.py      # <- file CHẠY: trả lời câu hỏi 1 và 2
│   └── utils/
│       ├── __init__.py
│       ├── config.py                  # đọc config.yaml, kết nối DB
│       └── logger.py
│
├── tests/
│   ├── test_transform.py              # kiểm thử ETL
│   ├── test_mining.py                 # kiểm thử Data Mining
│   ├── make_fixture_csv.py            # (tùy chọn) sinh CSV GIẢ để thử cả pipeline
│   └── generate_sample_data.py        # (tùy chọn) nạp dữ liệu GIẢ thẳng vào kho để thử SQL
│
│  ---- CÁC THƯ MỤC SAU BẠN TỰ TẠO / CHỈ ĐẶT DỮ LIỆU VÀO ----
├── data/
│   ├── raw/
│   │   ├── cicids2017/                # BẠN ĐẶT 8 file CSV của GeneratedLabelledFlows vào đây
│   │   └── blacklist/                 # BẠN ĐẶT firehol_level1.netset vào đây
│   └── processed/clean/               # (tự tạo) Parquet sạch do ETL sinh ra
│
│  ---- CÁC THƯ MỤC SAU TỰ SINH RA KHI CHẠY, KHÔNG CẦN TẠO ----
├── models/                            # mô hình .joblib
└── reports/
    ├── tables/                        # file CSV/JSON kết quả (OLAP, ETL, mô hình, Q1, Q2)
    └── figures/                       # biểu đồ PNG
```

### 13.2. Thứ tự dùng file

| Bước | Lệnh | File được dùng |
|---|---|---|
| 0. Chuẩn bị | `pip install -r requirements.txt`; chép `.env.example` thành `.env` | `requirements.txt`, `.env.example` |
| 1. ETL + nạp kho | `python -m src.etl.run_etl --create-schema` | `config.yaml`, `src/etl/*`, `src/utils/*`, `sql/01_create_schema.sql` |
| 2. Tạo view | `psql -d <ten_db> -f sql/04_views.sql` | `sql/04_views.sql` |
| 3. OLAP | `python -m src.olap.run_queries` | `src/olap/run_queries.py`, `sql/03_olap_queries.sql` |
| 4. Data Mining | `python -m src.mining.train` rồi `python -m src.mining.business_questions` | `src/mining/*` |
| 5. Kiểm thử (tùy chọn) | `python -m pytest tests -v` | `tests/test_*.py` |

### 13.3. File nào KHÔNG cần quan tâm
- `tests/make_fixture_csv.py` và `tests/generate_sample_data.py`: chỉ để thử code khi chưa có dữ liệu thật; có dữ liệu thật thì không cần dùng, nhưng giữ lại cũng không sao.
- 5 file `__init__.py` đều rỗng; không sửa, không xóa (thiếu chúng thì lệnh `python -m src....` báo lỗi).
- Các file bạn chỉ cần **sửa**: `config.yaml` (nếu đổi đường dẫn/tham số) và `.env` (mật khẩu DB). Mọi file còn lại dùng nguyên trạng.

---

## 14. Nâng cấp: kiến trúc streaming đa nguồn (Docker, CDC, Kafka, Data Lake)

> **Trạng thái:** mục này là **thiết kế và kế hoạch thực hiện**; chưa có mã nguồn hay file Docker chạy thử. Các thông tin về image, phiên bản đã được kiểm tra ngày 22/10/2026 (xem 14.12); phải kiểm tra lại tag bằng `docker pull` trước khi dùng vì tình trạng các image này thay đổi nhanh.

### 14.1. Mục tiêu và giá trị

| Hiện tại | Sau nâng cấp |
|---|---|
| Đọc file CSV tĩnh (batch) | Dữ liệu chảy liên tục: Firewall API → Collector → MySQL → CDC → Kafka → ETL streaming |
| Một nguồn, một kho | Đa nguồn, đa cấu trúc: MySQL (có cấu trúc), sự kiện JSON trên Kafka (bán cấu trúc), Parquet trên S3 (cột), file CSV gốc |
| Parquet lưu ổ đĩa cục bộ | Data Lake theo giao thức S3 (đọc trực tiếp bằng pandas) |
| Cài từng thành phần thủ công | Một lệnh `docker compose up` dựng toàn bộ hạ tầng |

Điểm mạnh về mặt học thuật: nâng cấp này trực tiếp đáp ứng yêu cầu "dữ liệu đa nguồn đa cấu trúc" đặt ra từ đầu đề tài, và thể hiện đủ chuỗi CDC, message broker, micro-batching, dual-write, Data Lake kết hợp Data Warehouse.

**Giữ lại pipeline batch hiện tại** làm đường nạp lịch sử (backfill) và phương án dự phòng khi demo: pipeline streaming bổ sung chứ không thay thế hoàn toàn.

### 14.2. Kiến trúc và luồng dữ liệu

```
CSV UNB ──> [Firewall API] <──poll── [Collector] ──INSERT──> [MySQL: raw_network_logs]
             (HTTP, hệ thống ngoài)   (sleep giữa các lần gọi)           │ binlog
                                                  ▼
                                      [Debezium (Kafka Connect)]
                                                  │ sự kiện JSON
                                                  ▼
                                   [Kafka topic: fw.firewall.raw_network_logs]
                                                  │ poll + commit thủ công
                                                  ▼
                                  [ETL Streaming Consumer (Python)]
                       làm sạch, ép kiểu, đối chiếu FireHOL, micro-batching
                                    │                         │
                      Parquet theo lô │                         │ Fact + Dimension (upsert)
                                    ▼                         ▼
                           [MinIO / S3: network-lake]   [PostgreSQL: Data Warehouse]
                                    │                         │
                        train.py, notebook 04          OLAP, dashboard, notebook 03
```

### 14.3. Về PostgreSQL (câu hỏi của bạn)

**Nên giữ PostgreSQL làm Data Warehouse.** Lý do:
- Star schema, các truy vấn OLAP (`ROLLUP`, `CUBE`, hàm cửa sổ), view và materialized view đã xây trên PostgreSQL và đã chạy được; đổi hệ quản trị sẽ phải viết lại và kiểm thử lại.
- Có sẵn các cơ chế cần cho streaming: `INSERT ... ON CONFLICT` (nạp lặp lại không tạo bản ghi trùng), `COPY`, chỉ mục, phân vùng bảng theo thời gian nếu sau này dữ liệu lớn.
- Với quy mô đề tài (vài triệu dòng fact) PostgreSQL xử lý được trên một máy.

**Phân vai rõ ràng giữa hai cơ sở dữ liệu:** MySQL chỉ là CSDL nguồn (OLTP) giả lập của firewall; PostgreSQL là kho dữ liệu (OLAP). Không dùng PostgreSQL vừa làm nguồn vừa làm kho, để luồng CDC có ý nghĩa và tránh lẫn lộn.

**Điều chỉnh nhỏ cho PostgreSQL:**
- Thêm cột `source_log_id BIGINT` (có ràng buộc UNIQUE) vào `fact_flow`: là khóa idempotent để nạp lặp lại không tạo dòng trùng. PostgreSQL cho phép nhiều giá trị NULL trong cột UNIQUE nên pipeline batch cũ vẫn chạy bình thường.
- Thêm bảng `etl_batch_log` (mỗi micro-batch một dòng: topic, partition, offset đầu/cuối, số dòng vào/ra/bị loại, độ trễ, thời gian) để làm bằng chứng đối soát trong báo cáo.
- Materialized view (`mv_*`) không tự cập nhật: cần lệnh `REFRESH MATERIALIZED VIEW` định kỳ (xem 14.5).

**Di chuyển từ PostgreSQL đang cài trên máy sang container:**
1. *(Khuyên dùng)* Tạo kho mới trong container rồi chạy lại pipeline batch làm backfill; đơn giản và kiểm chứng được tính toàn vẹn.
2. Dùng `pg_dump` trên máy rồi `pg_restore` vào container nếu muốn giữ nguyên dữ liệu.
3. Nếu PostgreSQL trên máy đang chiếm cổng 5432, publish cổng container là `5433:5432` (hoặc tắt PostgreSQL cục bộ khi chạy Docker).

### 14.4. Đề xuất và điều chỉnh so với yêu cầu

| # | Vấn đề | Đề xuất | Lý do |
|---|---|---|---|
| 1 | **MinIO không còn kéo được image như trước (quan trọng nhất)** | Giữ MinIO về mặt khái niệm (S3 Data Lake), nhưng **chọn lại nguồn image**: **(đã cập nhật ngày 22/10/2026, xem 14.13: bản cố định cũ trên `quay.io` cũng không còn kéo được ẩn danh)** dùng fork cộng đồng `pgsty/silo` (mặc định), hoặc image `cgr.dev/chainguard/minio`, hoặc tự build từ mã nguồn, hoặc SeaweedFS. Code dùng giao thức S3 nên đổi nhà cung cấp chỉ cần đổi image, endpoint và khóa truy cập | Theo các nguồn đã kiểm tra: kho mã MinIO bản cộng đồng bị lưu trữ (archived) ngày 25/4/2026; repo `minio/minio` và `minio/mc` trên Docker Hub bị gỡ khoảng ngày 11-12/9/2026, nên `image: minio/minio` sẽ **không kéo được**. Bản cũ không còn nhận vá lỗi bảo mật |
| 2 | Không dùng image `minio/mc` để tạo bucket | Tạo bucket bằng Python (boto3) trong script khởi tạo hoặc khi consumer khởi động | Image `mc` cũng nằm trong số bị gỡ |
| 3 | Zookeeper | **Mặc định đề xuất KRaft** (Kafka không cần Zookeeper). Nếu đề bài bắt buộc có Zookeeper thì dùng cặp `confluentinc/cp-zookeeper` + `cp-kafka` | Tài liệu hướng dẫn hiện hành của Debezium dùng Kafka KRaft, không còn Zookeeper; Apache Kafka 4.0 đã bỏ hẳn Zookeeper. Image Debezium từ bản 3.0 chỉ phát hành trên `quay.io` |
| 4 | Image Debezium | Dùng `quay.io/debezium/connect:<phiên bản 3.x cụ thể>`, **ghim phiên bản**, không dùng `latest` | Tránh thay đổi ngầm; từ 3.0 image không còn cập nhật trên docker.io |
| 5 | Phiên bản MySQL | `mysql:8.4` (LTS) thay vì 8.0 | 8.0 đã đến hạn hết hỗ trợ theo lịch của Oracle; lưu ý 8.4 mặc định dùng `caching_sha2_password` (xem 14.9) |
| 6 | Nhất quán khi ghi hai đích | Idempotent + **chỉ commit offset Kafka sau khi cả PostgreSQL và MinIO đã ghi xong** (xem 14.5.7) | Hai đích không có giao dịch chung; nếu consumer chết giữa chừng, Kafka giao lại thông điệp. Idempotent giúp không trùng dòng và không mất dòng |
| 7 | Bảng `raw_network_logs` | Lưu **giá trị thô** (timestamp dạng chuỗi như trong CSV, IP dạng chuỗi), làm sạch ở ETL | Đúng bản chất log thô từ firewall và cho phép tái sử dụng hàm làm sạch hiện có |
| 8 | Nhãn (Label) trong luồng | Giữ cột `label` như "nhãn chuẩn của môi trường lab", ghi chú rõ trong báo cáo | Firewall thật không biết nhãn; ở đây cần nhãn để huấn luyện/đánh giá. Hướng mở rộng: dùng mô hình đã huấn luyện (từ MinIO) để dự đoán nhãn ngay trên luồng |
| 9 | Khối lượng dữ liệu | **Chỉ phát lại một phần** (ví dụ 100.000-200.000 dòng, có thể chọn đủ các loại tấn công) khi demo; đặt `retention` và nén cho topic Kafka | Ước lượng thô: mỗi sự kiện JSON khoảng 3 KB (85 trường) nên 2,8 triệu dòng có thể chiếm khoảng 8 GB trên Kafka, chưa kể binlog MySQL và bản sao trong MinIO/PostgreSQL |
| 10 | Micro-batch tạo nhiều file Parquet nhỏ | Thêm job gộp file (compaction) theo giờ/ngày | Đọc hàng trăm file nhỏ từ S3 rất chậm khi huấn luyện |
| 11 | Dashboard/OLAP trên dữ liệu đang cập nhật | Dùng view thường cho dashboard "gần thời gian thực"; refresh `mv_*` định kỳ; **đóng băng dữ liệu** (dừng simulator, đợi consumer xử lý hết) trước khi chạy truy vấn lấy số liệu cho báo cáo | Số liệu thay đổi từng giây sẽ không tái lập được |
| 12 | Bí mật (mật khẩu, khóa S3) | Đặt trong `.env` (không commit), compose đọc qua biến môi trường | Tránh lộ khóa khi đưa mã lên Git |
| 13 | Cổng mạng | Chỉ publish những cổng cần dùng từ máy chủ (PostgreSQL, MinIO, Connect REST); không mở ra mạng ngoài | MinIO bản cũ không còn vá lỗi; CSDL không nên lộ ra ngoài |

**Ba quyết định cần bạn chốt trước khi viết mã** (mình đề xuất sẵn mặc định):
1. Kafka: KRaft (mặc định) hay Zookeeper + Kafka của Confluent. **ĐÃ CHỐT: KRaft.**
2. Kho S3: image nào. **ĐÃ CHỐT: tương thích MinIO; image cụ thể xem 14.13 (đề xuất ban đầu về `quay.io` đã lỗi thời).**
3. Số dòng phát lại khi demo (mặc định: 100.000 dòng, chọn có đủ các nhãn). **ĐÃ CHỐT: 100.000 dòng, đủ các nhãn.**
4. *(Tùy chọn)* Có thêm Apache Airflow hay không. **ĐÃ CHỐT: không dùng** (mục 16 giữ để tham khảo).

### 14.5. Thiết kế chi tiết

#### 14.5.1. Các dịch vụ trong `docker-compose.yml`

| Dịch vụ | Image gợi ý (cần kiểm tra tag) | Cổng máy chủ:container | Volume | Ghi chú |
|---|---|---|---|---|
| `mysql` | `mysql:8.4` | `3307:3306` | `mysql_data` | Bật binlog dạng ROW; cổng 3307 để tránh trùng MySQL cục bộ |
| `postgres` | `postgres:16` (hoặc 17) | `5433:5432` | `pg_data` | Mount `sql/01_create_schema.sql` vào `/docker-entrypoint-initdb.d/` để tự tạo schema |
| `zookeeper` *(chỉ nếu chọn phương án có Zookeeper)* | `confluentinc/cp-zookeeper` | nội bộ | `zk_data`, `zk_log` | |
| `kafka` | `quay.io/debezium/kafka:<3.x>` (KRaft) hoặc `confluentinc/cp-kafka` | `29092:29092` (cho ứng dụng chạy trên máy chủ) | `kafka_data` | Hai listener: nội bộ và bên ngoài (xem dưới) |
| `connect` | `quay.io/debezium/connect:<3.x>` | `8083:8083` | không cần (trạng thái lưu trong topic của Kafka) | Chính là "Debezium"; cấu hình REST API |
| `minio` (hoặc thay thế) | xem đề xuất #1 | `9000:9000` (S3 API), `9001:9001` (console nếu có) | `minio_data` | |
| `init` (chạy một lần) | image Python của dự án | không | không | Tạo bucket, đăng ký connector, tạo topic |
| `firewall-api` | build từ `docker/Dockerfile` | `8000:8000` (tài liệu tương tác tại `/docs`) | mount `data/replay` chỉ đọc | Phục vụ dữ liệu CICIDS2017 qua HTTP (14.14); `profiles: ["app"]` |
| `collector` | dùng lại image trên | không | không | Gọi API, ghi MySQL; `profiles: ["app"]`; tự thoát khi API hết dữ liệu |
| `etl-consumer` | build từ `docker/Dockerfile` | không | mount `data/raw/blacklist` chỉ đọc | Dùng `profiles` |

**Mạng:** một mạng bridge riêng (ví dụ `dwdm-net`). Trong mạng này các dịch vụ gọi nhau bằng **tên dịch vụ** (`mysql:3306`, `kafka:9092`, `postgres:5432`, `minio:9000`). Từ máy chủ (notebook, `train.py` chạy ngoài Docker) dùng `localhost` với **cổng đã publish** (`localhost:5433`, `localhost:29092`, `localhost:9000`).

**Lỗi hay gặp nhất của Kafka trong Docker** là listener quảng bá sai địa chỉ: client ngoài Docker kết nối được broker nhưng sau đó bị chuyển hướng tới `kafka:9092` mà máy chủ không phân giải được. Cách xử lý: hai listener, ví dụ

```
INTERNAL://kafka:9092     (cho Connect, simulator, consumer chạy trong Docker)
EXTERNAL://localhost:29092 (cho ứng dụng chạy trên máy chủ)
```

Tên biến môi trường cụ thể để cấu hình listener phụ thuộc vào image, cần xem tài liệu của image đã chọn.

**Volume có tên (named volume)** cho mọi dữ liệu cần bền: `mysql_data`, `pg_data`, `kafka_data`, `minio_data` (và `zk_*` nếu dùng Zookeeper). `docker compose down` giữ dữ liệu; `docker compose down -v` xóa sạch (dùng để làm lại từ đầu).

**Healthcheck và thứ tự khởi động:** mỗi dịch vụ có `healthcheck`, các dịch vụ phụ thuộc dùng `depends_on` với `condition: service_healthy` (MySQL và Kafka khỏe → Connect khởi động → đăng ký connector → simulator và consumer).

#### 14.5.2. MySQL: cấu hình binlog và tài khoản

- Tham số bắt buộc để Debezium hoạt động: bật binlog (`log_bin`), `binlog_format=ROW`, `binlog_row_image=FULL`, `server_id` khác 0. Nên đặt `binlog_expire_logs_seconds` (ví dụ 86400 = 1 ngày) để binlog không làm đầy ổ đĩa khi phát lại nhiều dữ liệu.
- Tài khoản `debezium`: các quyền `SELECT`, `RELOAD`, `SHOW DATABASES`, `REPLICATION SLAVE`, `REPLICATION CLIENT`.
- Tài khoản `simulator` (ứng dụng ghi): chỉ quyền `INSERT` (và `SELECT` nếu dùng bảng trạng thái) trên CSDL `firewall`, theo nguyên tắc quyền tối thiểu.
- Kiểm tra: `SHOW VARIABLES LIKE 'log_bin'; SHOW VARIABLES LIKE 'binlog_format';` và trạng thái binlog (từ MySQL 8.4 dùng `SHOW BINARY LOG STATUS` thay cho `SHOW MASTER STATUS`).

#### 14.5.3. Bảng `raw_network_logs` (MySQL)

| Nhóm cột | Thiết kế |
|---|---|
| Khóa | `log_id BIGINT AUTO_INCREMENT PRIMARY KEY` (làm khóa idempotent ở kho dữ liệu) |
| Định danh | `flow_id VARCHAR(150)`, `source_ip VARCHAR(64)`, `source_port INT`, `destination_ip VARCHAR(64)`, `destination_port INT`, `protocol INT` |
| Thời gian | `event_time_raw VARCHAR(32)` (chuỗi gốc như `7/7/2017 1:00`); `ingested_at TIMESTAMP(3)` mặc định `CURRENT_TIMESTAMP(3)` (thời điểm ghi thật, dùng đo độ trễ) |
| Đặc trưng số (~64 cột) | `DOUBLE`; tên cột là dạng snake_case của tên gốc (cùng quy tắc `feature_name` đã dùng ở ETL) |
| Nhãn, truy vết | `label VARCHAR(64)`, `source_file VARCHAR(100)` |

Nguyên tắc thiết kế:
- Sinh DDL bằng script từ header của CSV (không gõ tay 85 cột); bỏ cột `Fwd Header Length` bị lặp.
- **Không dùng `DECIMAL`**: Debezium mặc định mã hóa DECIMAL thành chuỗi nhị phân khó đọc. Dùng `DOUBLE`.
- `DOUBLE` của MySQL **không lưu được `Infinity`/`NaN`**: simulator chuyển các giá trị này thành `NULL` (khớp với cách ETL batch hiện tại).
- Không tạo chỉ mục phụ (tăng tốc INSERT).
- Cùng với 85 cột, kích thước dòng vẫn nằm trong giới hạn của MySQL.

#### 14.5.4. Firewall Simulator (`src/api_simulator/`)

> **Đã thay bằng phương án B (mục 14.14):** Simulator được tách thành **Firewall API** (`api.py`) và **Collector** (`collector.py`). Các phần dưới đây về đọc CSV, nhịp phát, ghi MySQL theo lô và tiếp tục khi dừng vẫn áp dụng, nhưng con trỏ nằm trong bảng `collector_state` (không phải file/`simulator_state`).

| Thành phần | Mô tả |
|---|---|
| Đọc dữ liệu | Đọc 8 file CSV theo thứ tự thứ Hai đến thứ Sáu và theo thứ tự dòng trong file; `encoding='latin-1'`; bỏ khoảng trắng đầu tên cột; chuyển `Infinity`/`NaN` thành `NULL`; đọc theo từng khối (chunk) để không tốn RAM |
| Phát lại | Vòng lặp theo lô: ghi một lô rồi `time.sleep()` để đạt tốc độ cấu hình. Chế độ `constant` (đều) và `poisson` (khoảng cách ngẫu nhiên, giống lưu lượng thật). Tùy chọn `--burst-attacks`: tăng tốc độ khi gặp dòng tấn công để thấy đột biến trên dashboard (chỉ dùng cho demo) |
| Ghi MySQL | `executemany` theo lô 50-500 dòng trong một giao dịch; thư viện `PyMySQL` (cần thêm `cryptography` nếu dùng `caching_sha2_password`) |
| Tham số dòng lệnh | `--rate` (dòng/giây), `--batch-size`, `--limit` (tổng số dòng), `--files`, `--mode`, `--resume` |
| Tiếp tục khi dừng | Lưu tiến độ (file, số dòng đã ghi) vào file hoặc bảng `simulator_state` để chạy tiếp, không ghi lặp |
| Cấu hình | Biến môi trường (`MYSQL_HOST`, ...); chạy được cả trên máy chủ lẫn trong container |

#### 14.5.5. Debezium MySQL connector

Cấu hình gửi qua REST API của Connect (`PUT /connectors/<tên>/config`, idempotent). Các thuộc tính chính (đối chiếu với tài liệu của đúng phiên bản Debezium bạn dùng):

| Thuộc tính | Giá trị gợi ý | Ý nghĩa |
|---|---|---|
| `connector.class` | `io.debezium.connector.mysql.MySqlConnector` | |
| `database.hostname`, `database.port` | `mysql`, `3306` | Tên dịch vụ trong mạng Docker |
| `database.user`, `database.password` | tài khoản `debezium` | Lấy từ `.env` |
| `database.server.id` | số nguyên duy nhất, khác `server_id` của MySQL | |
| `topic.prefix` | `fw` | Topic có dạng `fw.firewall.raw_network_logs` |
| `database.include.list`, `table.include.list` | `firewall`, `firewall.raw_network_logs` | |
| `schema.history.internal.kafka.bootstrap.servers` | `kafka:9092` | |
| `schema.history.internal.kafka.topic` | `schema-history.firewall` | |
| `include.schema.changes` | `false` | |
| `key.converter`, `value.converter` | `org.apache.kafka.connect.json.JsonConverter` | |
| `key.converter.schemas.enable`, `value.converter.schemas.enable` | `false` | Bỏ phần schema để thông điệp gọn |
| `transforms` | `unwrap` | |
| `transforms.unwrap.type` | `io.debezium.transforms.ExtractNewRecordState` | Làm phẳng thông điệp: consumer nhận thẳng các cột của dòng mới |
| `transforms.unwrap.add.fields` | `source.ts_ms,ts_ms` | Thêm thời điểm giao dịch ở MySQL và thời điểm Debezium xử lý, để đo độ trễ |
| `poll.interval.ms` | thấp hơn mặc định (ví dụ 100) | Giảm độ trễ CDC |
| `topic.creation.default.partitions`, `.replication.factor` | `1`, `1` | Một broker; một partition giữ đúng thứ tự |
| `topic.creation.default.retention.ms`, `.compression.type` | tùy chọn, ví dụ giữ 1-2 ngày, `lz4` | Giới hạn dung lượng |

- Nếu bảng `raw_network_logs` **đang rỗng** khi tạo connector, snapshot ban đầu không phát sinh dữ liệu. Nếu bảng đã có dữ liệu trước khi tạo connector thì các dòng đó sẽ được phát lại ở dạng sự kiện snapshot (`op=r`). Tên các chế độ `snapshot.mode` đã thay đổi giữa các phiên bản, cần xem tài liệu của bản đang dùng.
- Vị trí đọc binlog của Debezium được lưu trong topic của Kafka Connect, nên khi Connect khởi động lại nó **tiếp tục từ chỗ dừng**.

#### 14.5.6. ETL Streaming Consumer (`src/etl/stream_consumer.py`)

Vòng lặp chính:

1. `Consumer` (thư viện `confluent-kafka`) với `enable.auto.commit=false`, `auto.offset.reset=earliest`, một `group.id` cố định.
2. Gom thông điệp vào bộ đệm đến khi đủ `batch_max_rows` (gợi ý 5.000) **hoặc** quá `batch_max_seconds` (gợi ý 30 giây).
3. Chuyển lô thành DataFrame, đổi tên cột về dạng ETL đã dùng, rồi gọi **lõi làm sạch dùng chung** với pipeline batch: ép kiểu, kiểm tra và chuẩn hóa IP, phân tích timestamp (đổi giờ chiều), loại giá trị âm, gộp nhãn.
4. Làm giàu: đối chiếu IP với danh sách FireHOL (nạp vào bộ nhớ lúc khởi động, **chỉ kiểm tra IP công cộng** như ở ETL batch) và đặt kết quả vào cache theo IP.
5. Ghi **cả hai đích** (xem 14.5.7).
6. Chỉ sau khi cả hai đích thành công mới `commit` offset đồng bộ.
7. Ghi một dòng vào `etl_batch_log` và log tốc độ, độ trễ.

Xử lý lỗi và vận hành:
- **Thông điệp hỏng** (thiếu trường bắt buộc, IP sai...) không được chặn cả luồng: ghi vào `s3://network-lake/quarantine/` (hoặc topic `fw.dlq`) kèm lý do rồi tiếp tục; số dòng bị loại được ghi trong `etl_batch_log`.
- **Đích ghi lỗi tạm thời** (PostgreSQL hoặc MinIO tạm ngừng): thử lại có chờ tăng dần, **không commit offset**; khi đích hoạt động lại, lô được xử lý tiếp. Kafka giữ dữ liệu trong thời gian đó.
- **Tắt đúng cách:** bắt tín hiệu `SIGTERM`, ghi nốt lô đang gom, commit rồi thoát.
- **Giao lại thông điệp** (at-least-once) được hấp thụ nhờ idempotent ở 14.5.7.

**Về độ trễ:** có ba mốc cần đo riêng. (1) Độ trễ CDC (từ lúc MySQL commit đến lúc Debezium phát sự kiện, tính từ `ts_ms - source.ts_ms`) thường ở mức mili giây đến vài trăm mili giây; (2) từ commit đến lúc consumer nhận; (3) từ commit đến lúc dữ liệu **xuất hiện trong PostgreSQL**, bị chặn dưới bởi cửa sổ micro-batch (tối đa `batch_max_seconds`). Chỉ mốc (1) và (2) là "mili giây"; báo cáo cần nêu rõ để không nhầm lẫn.

#### 14.5.7. Dual-write: ghi hai đích và tính idempotent

| Đích | Cách ghi | Khóa idempotent |
|---|---|---|
| **PostgreSQL** | Một giao dịch cho mỗi lô: upsert các dimension (`dim_time`, `dim_ip`, `dim_port`, `dim_protocol`, `dim_label`) bằng `INSERT ... ON CONFLICT`, lấy khóa thay thế (có cache trong bộ nhớ), rồi `INSERT` vào `fact_flow` với `ON CONFLICT (source_log_id) DO NOTHING` | `source_log_id` = `log_id` của MySQL |
| **MinIO (S3)** | Gom lô thành Parquet (cùng schema với Parquet batch hiện tại) và ghi một object mỗi (ngày sự kiện, lô). Đường dẫn: `s3://network-lake/clean/event_date=YYYY-MM-DD/part-p<partition>-o<offset đầu>-<offset cuối>.parquet` | Tên object suy ra từ offset nên ghi lại cùng lô sẽ **ghi đè cùng một object**, không tạo bản sao |

Quy tắc commit: **ghi MinIO và PostgreSQL xong → mới commit offset**. Nếu consumer chết giữa chừng thì lô được giao lại và các khóa idempotent bảo đảm kết quả cuối cùng không trùng, không mất.

Hướng nâng cao (không bắt buộc): mỗi đích có cửa sổ gom riêng và chỉ commit offset nhỏ nhất đã ghi xong ở cả hai đích.

#### 14.5.8. Thay đổi mã hiện có

| File | Thay đổi |
|---|---|
| `sql/01_create_schema.sql` | Thêm `source_log_id BIGINT` + chỉ mục UNIQUE vào `fact_flow`; thêm bảng `etl_batch_log` |
| `sql/04_views.sql` | Thêm chỉ mục UNIQUE cho các `mv_*` nếu muốn `REFRESH ... CONCURRENTLY`; thêm cách làm mới định kỳ |
| `src/etl/transform.py` | Tách `clean_flows` thành phần đổi tên cột và phần lõi làm sạch để dùng chung cho batch và streaming |
| `src/etl/load.py` | Tái sử dụng hàm blacklist và dựng dimension; thêm hàm upsert theo lô cho streaming |
| `src/utils/storage.py` *(mới)* | Hàm liệt kê/đọc Parquet qua `fsspec` (chạy được với đường dẫn cục bộ lẫn `s3://`) |
| `src/mining/features.py`, `src/mining/business_questions.py` | Thay `Path.glob` và `read_parquet` cục bộ bằng hàm trong `storage.py` |
| `config.yaml` | Thêm mục `streaming:` (Kafka, topic, kích thước lô), `s3:` (endpoint, bucket, khóa lấy từ biến môi trường); `paths.clean_dir` có thể là `s3://network-lake/clean` |
| `requirements.txt` | Thêm `confluent-kafka`, `PyMySQL`, `cryptography`, `s3fs`, `boto3` |

#### 14.5.9. Đọc dữ liệu từ MinIO trong OLAP và Machine Learning

- **Pandas đọc S3:** `pd.read_parquet("s3://network-lake/clean/", storage_options={"key": ..., "secret": ..., "client_kwargs": {"endpoint_url": "http://localhost:9000"}})` (cần `s3fs`). Với nhà cung cấp tương thích S3, thường phải dùng địa chỉ kiểu path (không dùng subdomain theo tên bucket); cần kiểm tra khi chọn image thay thế MinIO.
- **Notebook `03_olap.ipynb`:** chuỗi kết nối chuyển sang container, ví dụ `postgresql+psycopg2://<user>:<pass>@localhost:5433/<ten_db>`. Nếu notebook chạy **trong** một container thì dùng `postgres:5432`.
- **Notebook `04_modeling.ipynb`:** thay đường dẫn cục bộ bằng URI `s3://` như trên.
- **Script `run_queries.py` và `train.py`:** chỉ cần sửa `.env` (cổng 5433) và `config.yaml` (đường dẫn S3).
- **Tính tái lập khi huấn luyện:** vì dữ liệu trong Data Lake tăng dần, hãy ghi lại danh sách và số lượng file Parquet đã dùng (vào `mining_run_info.json`) và huấn luyện sau khi phát lại xong (hoặc đủ nhiều loại nhãn); huấn luyện khi mới có dữ liệu thứ Hai, thứ Ba sẽ thiếu các loại tấn công.

### 14.6. Các bước thực hiện chi tiết

#### Giai đoạn A: Chuẩn bị và chốt quyết định (khoảng 2 ngày)
1. Cài Docker Desktop (hoặc Docker Engine) và Docker Compose v2; kiểm tra `docker compose version`. Trên Windows dùng WSL2 và cấp cho Docker tối thiểu 8 GB RAM.
2. Chốt 3 quyết định ở mục 14.4 (Kafka KRaft hay Zookeeper, image S3, số dòng phát lại).
3. Chạy `docker pull` cho **tất cả** image dự định dùng, đặc biệt image S3 thay thế MinIO. Image nào không kéo được thì đổi phương án ngay.
4. Sao lưu: `pg_dump` kho hiện tại; giữ nguyên thư mục Parquet cục bộ.
5. Bổ sung `.env` (mật khẩu MySQL/PostgreSQL, khóa S3, tên bucket) và thêm `.env` vào `.gitignore`.

*Nghiệm thu:* mọi image đã kéo về thành công; ghi lại phiên bản đã ghim.

#### Giai đoạn B: Dựng hạ tầng bằng Docker Compose (3-4 ngày)
1. Tạo `docker-compose.yml` ở thư mục gốc: mạng `dwdm-net`, các named volume, các dịch vụ ở 14.5.1, `healthcheck` và `depends_on` có điều kiện.
2. MySQL: mount file SQL khởi tạo vào `/docker-entrypoint-initdb.d/` (tạo CSDL `firewall`, bảng `raw_network_logs`, tài khoản `debezium` và `simulator`); đặt các tham số binlog ở 14.5.2.
3. PostgreSQL: mount `sql/01_create_schema.sql` (đã thêm `source_log_id`, `etl_batch_log`) để tự tạo schema khi khởi động lần đầu.
4. Kafka (và Zookeeper nếu chọn): cấu hình hai listener (nội bộ và bên ngoài) như ở 14.5.1; ghim phiên bản.
5. Connect (Debezium): biến môi trường `BOOTSTRAP_SERVERS`, `GROUP_ID` và ba topic lưu cấu hình/offset/trạng thái của Connect (đặt replication factor là 1 vì chỉ có một broker).
6. Dịch vụ S3: volume dữ liệu, khóa truy cập từ `.env`; viết script Python tạo bucket `network-lake`.
7. Kiểm tra: `docker compose up -d`, `docker compose ps` (tất cả `healthy`), `curl localhost:8083/` (Connect trả về phiên bản), `psql` vào cổng 5433, `mysql` vào cổng 3307, liệt kê bucket bằng boto3.

*Nghiệm thu:* toàn bộ dịch vụ `healthy`; tắt rồi bật lại (`down`, `up`) vẫn còn dữ liệu trong các volume.

#### Giai đoạn C: MySQL nguồn, Firewall API và Collector (5-6 ngày)
1. Viết script sinh DDL `raw_network_logs` từ header CSV (14.5.3); lưu vào `sql/mysql/`.
2. Viết `src/api_simulator/`: `reader.py` (đọc CSV), `api.py` (Firewall API), `collector.py` (Collector), `make_replay_sample.py` (tạo mẫu 100.000 dòng).
3. Kiểm thử: ghi 1.000 dòng, đối chiếu số dòng và giá trị (đặc biệt các dòng có `Infinity`/`NaN`, nhãn có byte lạ); đo tốc độ thực tế so với `--rate`.
4. Viết `docker/Dockerfile` dùng chung cho API, Collector và consumer.

*Nghiệm thu:* `SELECT COUNT(*) FROM raw_network_logs` khớp với số bản ghi API đã phát; dừng đột ngột Collector rồi chạy lại không ghi lặp, không mất.

#### Giai đoạn D: Thiết lập CDC (3 ngày)
1. Kiểm tra binlog đã bật đúng (14.5.2) và tài khoản `debezium` có đủ quyền.
2. Viết `docker/debezium/mysql-connector.json` (14.5.5) và script đăng ký bằng `PUT` (chạy lại nhiều lần không lỗi); đưa vào dịch vụ `init`.
3. Kiểm tra trạng thái: `curl localhost:8083/connectors/<tên>/status` phải là `RUNNING`.
4. Ghi vài dòng bằng simulator, đọc topic bằng `kafka-console-consumer` (đi kèm trong image Kafka), kiểm tra các trường và hai trường thời gian để đo độ trễ.
5. Thử lỗi: dừng container `connect`, ghi thêm dòng, bật lại và kiểm tra không mất sự kiện nào.

*Nghiệm thu:* số sự kiện trên topic bằng số dòng đã ghi vào MySQL; độ trễ CDC được đo và ghi lại (trung vị, phân vị 95).

#### Giai đoạn E: Streaming Consumer (7-10 ngày, phần khó nhất)
1. Refactor `transform.py`: tách phần đổi tên cột và lõi làm sạch dùng chung; chạy lại 32 kiểm thử hiện có để bảo đảm batch không bị hỏng.
2. Viết bộ chuyển đổi (adapter) từ thông điệp Debezium sang DataFrame có cột đúng như ETL cần.
3. Viết `src/etl/sinks.py`: `PostgresSink` (cache dimension, upsert, insert fact idempotent, ghi `etl_batch_log`) và `ObjectStoreSink` (ghi Parquet với tên object suy ra từ offset).
4. Viết `src/etl/stream_consumer.py` theo 14.5.6: gom lô, làm sạch, đối chiếu FireHOL, ghi hai đích, commit sau cùng, xử lý lỗi, tắt đúng cách.
5. Thêm mục `streaming:` vào `config.yaml`; thêm dịch vụ `etl-consumer` vào compose.
6. Kiểm thử đơn vị: adapter; idempotent (cùng một lô xử lý hai lần cho kết quả như một lần); đặt tên object; bảo đảm không commit khi một đích lỗi (dùng đích giả).

*Nghiệm thu:* phát 10.000 dòng, đợi consumer xử lý xong: số dòng ở MySQL, `fact_flow` và tổng số dòng trong Parquet **bằng nhau** (trừ số dòng bị loại có ghi lý do trong `etl_batch_log`).

#### Giai đoạn F: Kiểm thử độ tin cậy từ đầu đến cuối (3 ngày)
Chạy các kịch bản ở 14.8 và ghi kết quả (ảnh chụp, số liệu) để đưa vào báo cáo.

#### Giai đoạn G: Tích hợp OLAP, Machine Learning và notebook (4 ngày)
1. Viết `src/utils/storage.py` và sửa `features.py`, `business_questions.py` dùng hàm này; cập nhật `config.yaml`, `.env`, `requirements.txt`.
2. Chạy `python -m src.olap.run_queries` trỏ vào PostgreSQL container (cổng 5433) khi dữ liệu đang chảy; xác nhận kết quả thay đổi theo thời gian.
3. Thiết lập cách làm mới `mv_*` định kỳ (consumer gọi mỗi vài phút, hoặc đổi dashboard sang view thường).
4. Cập nhật `03_olap.ipynb` và `04_modeling.ipynb` như ở 14.5.9.
5. Viết job gộp file Parquet nhỏ thành file lớn theo ngày (`compacted/`), kiểm tra tổng số dòng không đổi.
6. Chạy `train.py` đọc trực tiếp từ `s3://`; so sánh kết quả với lần chạy bằng file cục bộ (phải khớp nếu cùng tập dòng).

*Nghiệm thu:* `train.py` và `business_questions.py` chạy được bằng dữ liệu từ S3; số dòng đọc được bằng số dòng đã nạp.

#### Giai đoạn H: Hoàn thiện (3 ngày)
1. Viết README: cách chạy từng bước, sơ đồ kiến trúc, bảng cổng, cách xử lý lỗi thường gặp.
2. Chuẩn bị kịch bản demo (phát lại có đủ các loại tấn công, dashboard cập nhật, thử dừng/khởi động lại dịch vụ).
3. Tổng hợp số liệu: thông lượng, độ trễ ở 3 mốc, dung lượng Kafka/MinIO/PostgreSQL, kết quả các kịch bản lỗi.
4. Cập nhật báo cáo: kiến trúc mới, thay đổi so với bản batch, hạn chế.

### 14.7. Cấu trúc thư mục sau nâng cấp (phần thêm mới)

```
network-anomaly-dwdm/
├── docker-compose.yml                  # MỚI: toàn bộ hạ tầng
├── docker/
│   ├── Dockerfile                      # MỚI: image Python cho simulator và consumer
│   ├── requirements-stream.txt         # MỚI: thư viện của image Python
│   ├── debezium/
│   │   └── mysql-connector.json        # MỚI: cấu hình connector
│   ├── mysql/init/01_users.sh          # MỚI: tạo tài khoản debezium và simulator
│   └── init/
│       └── bootstrap.py                # MỚI: tạo bucket S3 + đăng ký connector (gộp 2 việc)
├── sql/                                # các file PostgreSQL (kho dữ liệu) GIỮ NGUYÊN chỗ cũ
│   ├── 01_create_schema.sql            # SỬA NHẸ: thêm cột source_log_id (UNIQUE) và bảng etl_batch_log
│   ├── 03_olap_queries.sql             # giữ nguyên
│   ├── 04_views.sql                    # giữ nguyên (có thể thêm chỉ mục UNIQUE cho mv_* sau)
│   └── mysql/                          # MỚI: thư mục riêng cho CSDL NGUỒN MySQL
│       ├── 02_raw_network_logs.sql     #   DDL bảng nguồn (sinh từ header CSV); số 02 vì 01_users.sh chạy trước
│       └── raw_network_logs_columns.json  # ánh xạ tên cột MySQL <-> tên gốc trong CSV
├── src/
│   ├── api_simulator/                  # MỚI: nguồn dữ liệu "bên ngoài" (phương án B, 14.14)
│   │   ├── __init__.py
│   │   ├── make_ddl.py                 #   sinh DDL bảng MySQL từ header CSV
│   │   ├── reader.py                   #   đọc CSV theo thứ tự thời gian, đổi sang tên cột MySQL
│   │   ├── make_replay_sample.py       #   tạo tập mẫu ~100.000 dòng đủ mọi nhãn (file CHẠY)
│   │   ├── api.py                      #   Firewall API (file CHẠY bằng uvicorn)
│   │   └── collector.py                #   Collector: gọi API, ghi MySQL (file CHẠY)
│   ├── etl/
│   │   ├── stream_consumer.py          # MỚI: file CHẠY của ETL streaming
│   │   ├── sinks.py                    # MỚI: ghi PostgreSQL và S3
│   │   ├── compact_lake.py             # MỚI: gộp file Parquet nhỏ
│   │   └── transform.py                # SỬA: tách lõi làm sạch dùng chung
│   └── utils/storage.py                # MỚI: đọc/ghi Parquet cục bộ hoặc S3
└── tests/                              # THÊM: kiểm thử adapter, idempotent, sinks
```

### 14.8. Kiểm thử và nghiệm thu

| Kịch bản | Cách làm | Kết quả mong đợi |
|---|---|---|
| Khởi động sạch | `docker compose down -v` rồi `up -d` | Tất cả `healthy`, schema và connector tự tạo |
| Thông suốt cơ bản | Phát 10.000 dòng | Số dòng MySQL = Kafka = `fact_flow` = Parquet (có tính số dòng bị loại) |
| Đối soát nội dung | So khớp một mẫu ngẫu nhiên các dòng giữa MySQL, `fact_flow`, Parquet | Cùng giá trị (sau làm sạch) |
| Consumer bị dừng đột ngột | `docker kill` consumer giữa lúc phát, bật lại | Không mất, **không trùng** dòng (nhờ `source_log_id`) |
| PostgreSQL ngừng | Dừng container `postgres` vài phút rồi bật lại | Consumer chờ và thử lại; sau khi PostgreSQL trở lại, đủ dòng, không commit sớm |
| S3 ngừng | Dừng dịch vụ S3 vài phút | Tương tự: không mất dữ liệu |
| Debezium ngừng | Dừng `connect`, ghi thêm dòng, bật lại | Sự kiện được phát tiếp từ vị trí binlog đã lưu |
| Xử lý lại từ đầu | Đặt lại offset của consumer về đầu | Kết quả cuối giữ nguyên (không trùng) |
| Dữ liệu hỏng | Chèn dòng có IP sai/timestamp sai | Dòng đi vào `quarantine`, ghi trong `etl_batch_log`, luồng không bị chặn |
| Thông lượng | Tăng dần `--rate` | Xác định tốc độ tối đa trước khi lag Kafka tăng; ghi lại giá trị đo được |
| Độ trễ | So `source.ts_ms`, thời điểm nhận, thời điểm xuất hiện trong kho | Báo cáo trung vị và phân vị 95 của 3 mốc |
| OLAP khi đang chảy | Chạy `run_queries` lúc simulator đang phát | Chạy được, số liệu tăng dần |
| Đọc ML từ S3 | `train.py` đọc `s3://` | Số dòng đọc = số dòng đã nạp; kết quả khớp bản cục bộ cùng tập dòng |

### 14.9. Rủi ro và cách xử lý

| Rủi ro | Cách xử lý |
|---|---|
| Không kéo được image MinIO | Làm ở Giai đoạn A: thử `docker pull` mọi image trước; có sẵn phương án thay thế (14.4 #1) |
| Client ngoài Docker không kết nối được Kafka | Cấu hình hai listener đúng (14.5.1); kiểm tra bằng client trên máy chủ ngay từ Giai đoạn B |
| Debezium báo lỗi xác thực MySQL 8.4 (`caching_sha2_password`, "Public Key Retrieval is not allowed") | Cho phép lấy khóa công khai trong thuộc tính JDBC của connector (theo tài liệu Debezium của phiên bản đang dùng) hoặc bật SSL |
| Máy thiếu RAM | Ước lượng thô toàn bộ stack cần khoảng 5-6 GB RAM; máy 16 GB, cấp cho Docker ≥ 8 GB; giảm `retention`, tắt dịch vụ không dùng; giới hạn bộ nhớ JVM của Kafka/Connect |
| Ổ đĩa đầy (binlog, Kafka, Parquet) | Đặt `binlog_expire_logs_seconds`, `retention`, nén topic; chỉ phát lại một phần dữ liệu |
| Mất đồng bộ giữa hai đích | Idempotent + commit sau cùng + bảng `etl_batch_log` để đối soát |
| Nhiều file Parquet nhỏ | Job gộp file; đọc theo `event_date` |
| Dữ liệu đổi liên tục làm số liệu báo cáo không tái lập | Đóng băng dữ liệu trước khi lấy số liệu; ghi danh sách file/số dòng đã dùng |
| Phụ thuộc vào image không còn được bảo trì | Chỉ dùng trong lab; không mở cổng ra Internet; ghi chú hạn chế này trong báo cáo |
| Phạm vi quá lớn so với thời gian | Làm theo giai đoạn A-H; sau mỗi giai đoạn có nghiệm thu; có thể dừng ở Giai đoạn E (đủ yêu cầu 1-5) và coi G là phần mở rộng |

### 14.10. Tài nguyên và thời gian

| Giai đoạn | Thời gian ước tính (làm một mình, bán thời gian) |
|---|---|
| A. Chuẩn bị | 2 ngày |
| B. Hạ tầng Docker | 3-4 ngày |
| C. MySQL, Firewall API và Collector | 5-6 ngày |
| D. CDC | 3 ngày |
| E. Streaming Consumer | 7-10 ngày |
| F. Kiểm thử độ tin cậy | 3 ngày |
| G. OLAP, ML, notebook | 4 ngày |
| H. Hoàn thiện, báo cáo | 3 ngày |
| **Tổng** | **khoảng 4-5 tuần** |

Máy khuyến nghị: RAM 16 GB (tối thiểu 8 GB cho Docker), ổ SSD còn trống ít nhất 30 GB nếu phát lại nhiều dữ liệu. Đây là ước lượng thô, cần đo lại trên máy của bạn.

### 14.11. Những điểm cần nêu trong báo cáo
- Đây là **mô phỏng thời gian thực**: dữ liệu CICIDS2017 năm 2017 được phát lại; thời gian sự kiện (2017) khác thời gian nhập (`ingested_at`); kho dùng thời gian sự kiện.
- Nêu rõ ba mốc độ trễ và chỉ gọi mốc CDC là mili giây.
- Nhãn trong luồng là nhãn chuẩn của môi trường lab, không phải đầu ra của hệ thống phát hiện.
- Nêu giới hạn về image không còn được bảo trì (MinIO bản cũ) và lý do chọn phương án đã dùng.
- Pipeline batch vẫn được giữ như phương án backfill và đối chứng kết quả.

### 14.12. Nguồn đã kiểm tra (ngày 22/10/2026)
- Debezium, chuyển image sang quay.io từ bản 3.0: https://debezium.io/blog/2024/09/18/quay-io-reminder/
- Hướng dẫn Debezium hiện hành (Kafka KRaft, không Zookeeper): https://debezium.io/documentation/reference/stable/kc-tutorial.html
- Mẫu docker-compose MySQL của Debezium: https://github.com/debezium/debezium-examples/blob/main/tutorial/docker-compose-mysql.yaml
- Tình trạng MinIO sau khi `quay.io/minio/minio` cũng trả 401 (kiểm tra thực tế ngày 30/9/2026) và các phương án thay thế: https://jacar.es/error-pull-access-denied-minio-docker/
- Tình trạng MinIO (bản cộng đồng bị lưu trữ, image Docker Hub bị gỡ): https://www.stablebuild.com/blog/minio-images-disappeared-from-docker-hub và https://pinggy.io/blog/minio_archived_self_hosted_s3_alternatives/


### 14.13. Quyết định đã chốt và điều chỉnh khi bắt đầu triển khai (22/10/2026)

#### 14.13.1. Quyết định đã chốt

| Hạng mục | Quyết định |
|---|---|
| Message broker | **Kafka KRaft** (không Zookeeper), image `quay.io/debezium/kafka`, phiên bản Debezium **3.7** |
| Kho S3 (Data Lake) | **Tương thích MinIO**, mặc định `pgsty/silo` (chi tiết ở 14.13.2) |
| Số dòng phát lại khi demo | **100.000 dòng, đủ các nhãn** (cách chọn ở công việc 12) |
| Điều phối | **Không dùng Airflow** |
| CSDL nguồn / kho | MySQL **8.4**, PostgreSQL **16** (giữ 16 vì thư mục dữ liệu của bản 18 đổi cấu trúc) |

#### 14.13.2. Cập nhật quan trọng: đề xuất MinIO ban đầu đã lỗi thời

Ở mục 14.4 mình đề xuất dùng "bản cố định cũ trên `quay.io`". Kiểm tra lại ngày 22/10/2026 cho thấy **đề xuất đó không còn đúng**: theo một bài kiểm tra thực tế ngày 30/9/2026 và ghi chú của một kho gương trên Docker Hub, `quay.io/minio/minio` cũng bắt đầu trả lỗi 401 cho mọi lượt kéo ẩn danh từ khoảng 24/9/2026, sau khi Docker Hub đã bỏ trước đó. Nguồn này là một bài viết đơn lẻ, nên hãy tự xác nhận bằng `docker pull`.

| Phương án | Ưu điểm | Nhược điểm | Kết luận |
|---|---|---|---|
| **`pgsty/silo`** (fork cộng đồng của MinIO, có tag phiên bản) | Kéo được không cần tài khoản; có tag cố định; nhận biến `MINIO_ROOT_USER` / `MINIO_ROOT_PASSWORD` nên cấu hình giống MinIO; chạy bằng quyền root nên dùng được volume có tên | Là bản fork của cộng đồng, không phải sản phẩm chính thức; thông tin về tag lấy từ một bài viết, mình chưa tự kéo thử | **Mặc định** (đặt trong `S3_IMAGE`) |
| `cgr.dev/chainguard/minio` | Có image dựng sẵn | Chỉ có tag `latest` (không tái lập được); chạy bằng UID 65532 nên thư mục dữ liệu phải chown trước; không có curl/wget | Phương án dự phòng |
| **Tự build từ mã nguồn MinIO** (bản phát hành cuối) | Mã chính thức, tái lập được, có bản vá lỗi mới nhất | Cần thời gian build và RAM; thêm bước phức tạp | Phương án dự phòng khi `pgsty/silo` không kéo được |
| Kho gương của bên thứ ba trên Docker Hub | Kéo được | Không rõ nguồn gốc image (rủi ro chuỗi cung ứng) | **Không khuyến nghị** |
| SeaweedFS hoặc kho S3 khác | Còn được bảo trì | Hành vi S3 có thể khác một chút; phải kiểm tra tương thích với `s3fs`/`boto3` | Phương án cuối cùng |

Vì toàn bộ hệ thống chỉ nói chuyện với kho qua **giao thức S3** (endpoint, khóa, tên bucket), đổi phương án chỉ cần sửa biến `S3_IMAGE` (và có thể một dòng lệnh khởi động) trong `.env`/compose.

#### 14.13.3. Các điều chỉnh khác so với thiết kế ở mục 14

| # | Điều chỉnh | Lý do |
|---|---|---|
| 1 | **Bỏ listener Kafka ra ngoài máy chủ** trong bản cơ sở: Kafka chỉ nghe `kafka:9092` trong mạng Docker | Simulator, Connect và consumer đều chạy trong Docker nên không cần; file mẫu chính thức của Debezium cũng chỉ dùng một listener. Muốn chạy consumer ngoài Docker để gỡ lỗi thì phải thêm listener thứ hai (chưa kiểm chứng với image KRaft của Debezium) |
| 2 | Mọi cổng publish chỉ gắn vào `127.0.0.1` | Không để CSDL, Kafka Connect và kho S3 bị truy cập từ mạng ngoài |
| 3 | Dịch vụ `init` nằm trong `profile` riêng và chạy bằng `docker compose up init` | Chạy một lần, tự thoát; không chạy lẫn khi bật cả hệ thống |
| 4 | Kiểm tra sức khỏe Kafka và Connect bằng kết nối TCP; kho S3 không đặt kiểm tra sức khỏe | Image thay thế có thể không có `curl`; `init` tự thử lại đến khi S3 và Connect sẵn sàng |
| 5 | Tạo bucket và đăng ký connector bằng `docker/init/bootstrap.py` (Python, thư viện chuẩn và `boto3`) | Không phụ thuộc image `mc` đã bị gỡ; chạy lại nhiều lần không lỗi |
| 6 | Cột Debezium thêm vào thông điệp: `op`, `ts_ms`, `source.ts_ms` | Để đo độ trễ CDC. Nếu connector báo `FAILED` vì không nhận trường nào đó, bỏ bớt trường đó trong `add.fields` rồi đăng ký lại |
| 7 | Ánh xạ tên cột: file `sql/mysql/raw_network_logs_columns.json` (tên cột MySQL → tên cột gốc của CSV) | Dùng chung cho Simulator và consumer; consumer đổi tên cột về dạng gốc rồi gọi lại đúng hàm làm sạch đã có |

#### 14.13.4. File đã tạo ở giai đoạn hạ tầng và vị trí

| File | Vị trí | Công việc |
|---|---|---|
| `docker-compose.yml` | thư mục gốc | 6 |
| `.env.example`, `.gitignore` | thư mục gốc | 5 |
| `docker/Dockerfile`, `docker/requirements-stream.txt` | `docker/` | 6 |
| `docker/mysql/init/01_users.sh` | `docker/mysql/init/` | 13 |
| `docker/debezium/mysql-connector.json` | `docker/debezium/` | 14 |
| `docker/init/bootstrap.py` | `docker/init/` | 6, 14 |
| `src/api_simulator/make_ddl.py` (+ `__init__.py`) | `src/api_simulator/` | 9 |
| `sql/mysql/02_raw_network_logs.sql`, `sql/mysql/raw_network_logs_columns.json` | `sql/mysql/` | 9 |
| `sql/01_create_schema.sql` (đã thêm `source_log_id`, `etl_batch_log`) | `sql/` | 17 |

#### 14.13.5. Đã kiểm thử gì và chưa kiểm thử gì

| Nội dung | Tình trạng |
|---|---|
| Cú pháp YAML của compose, mọi biến `${...}` đều có trong `.env.example`, các `depends_on`/volume/mạng hợp lệ, các file được mount đều tồn tại | Đã kiểm tra |
| Star schema PostgreSQL mới: cột `source_log_id`, chỉ mục UNIQUE, ghi trùng bị bỏ qua (`ON CONFLICT DO NOTHING`), nhiều dòng NULL vẫn hợp lệ; bộ nạp dữ liệu batch cũ và các view vẫn chạy | Đã chạy |
| MySQL **8.0.46** (chưa có 8.4 trong môi trường thử) với đúng các tham số binlog của compose: script tạo tài khoản chạy được và chạy lại được (trong lúc thử có một lần đăng nhập bằng tài khoản vừa tạo bị từ chối mà mình không tái hiện được; chạy lại từ trạng thái sạch thì đạt cả lần đầu lẫn lần lặp), DDL tạo 87 cột, tài khoản `simulator` INSERT được nhưng bị từ chối DELETE và UPDATE, giá trị `NULL` cho cột `Infinity` | Đã chạy |
| `bootstrap.py` với Kafka Connect giả và S3 giả: tạo bucket, chạy lại không lỗi, connector `FAILED` thì thoát mã 1 kèm trace, thiếu biến thì báo rõ, S3 không chạy thì hết thời gian chờ | Đã chạy (chỉ với dịch vụ giả) |
| `docker compose config` và `docker compose up` thật; kéo các image; image Kafka KRaft và Connect của Debezium khởi động; đường dẫn dữ liệu `/kafka/data`; kiểm tra sức khỏe | **Chưa** (môi trường soạn thảo không có Docker) |
| Debezium đăng ký thành công với MySQL **8.4** (đặc biệt `add.fields` với `source.ts_ms`, `topic.creation.default.*`, `poll.interval.ms`) | **Chưa** |
| `pgsty/silo` kéo được và tương thích S3 với `boto3` | **Chưa** |

#### 14.13.6. Việc tiếp theo trên máy của bạn (công việc 4, 6, 7, 8)

1. Chép toàn bộ cây thư mục mới vào thư mục gốc dự án; chép `.env.example` thành `.env`, điền mật khẩu (chỉ dùng chữ, số, gạch dưới).
2. Kéo thử từng image: `mysql:8.4`, `postgres:16`, `quay.io/debezium/kafka:3.7`, `quay.io/debezium/connect:3.7`, image trong `S3_IMAGE`. **Nếu image S3 không kéo được, báo lại để chọn phương án khác ở bảng 14.13.2.**
3. `docker compose config` (kiểm tra cú pháp và biến).
4. `docker compose up -d mysql postgres`, đợi `healthy`; kiểm tra bằng DBeaver (MySQL cổng 3307, PostgreSQL cổng 5433).
5. `docker compose up -d kafka`, đợi `healthy`.
6. `docker compose up -d connect minio`.
7. `docker compose up init` (tạo bucket và đăng ký connector); đọc kết quả cuối: `HOÀN THÀNH` hoặc thông báo lỗi.
8. Tắt rồi bật lại (`down`, `up -d`) và kiểm tra dữ liệu còn.

Nếu bước nào lỗi, gửi lại log (`docker compose logs <dịch vụ>`) để chỉnh file cấu hình.

#### 14.13.7. Thành phần đề xuất cho mẫu phát lại 100.000 dòng

Số dòng gốc từng nhãn lấy theo số liệu công bố của CICIDS2017; sau bước ETL của bạn có thể lệch đôi chút, hãy đối chiếu với kết quả `qc_label_distribution` rồi chỉnh.

| Nhóm | Nhãn (số dòng gốc) | Số dòng lấy | Cách lấy |
|---|---|---|---|
| Hiếm: lấy toàn bộ | Heartbleed (11), Web Attack SQL Injection (21), Infiltration (36), Web Attack XSS (652), Web Attack Brute Force (1.507), Bot (1.966) | 4.193 | Lấy hết |
| Trung bình | FTP-Patator, SSH-Patator, DoS slowloris, DoS Slowhttptest: mỗi nhãn 3.000; DoS GoldenEye: 5.000 | 17.000 | Một đoạn liên tục từ đầu đoạn tấn công |
| Lớn | DoS Hulk, PortScan, DDoS: mỗi nhãn 10.000 | 30.000 | Một đoạn liên tục |
| Benign | BENIGN | 48.807 | Lấy trải đều các file |
| **Tổng** | | **100.000** | |

Mẫu này có khoảng một nửa là tấn công (thực tế chỉ khoảng 19%) để buổi demo thấy được các đợt tấn công. Vì vậy **mẫu chỉ dùng để demo luồng streaming, không dùng để đánh giá mô hình hay lấy số liệu báo cáo** (việc đó dùng toàn bộ dữ liệu bằng pipeline batch). Giữ nguyên thứ tự dòng trong mỗi file để các đoạn tấn công vẫn liền nhau.


### 14.14. Phương án B: nguồn dữ liệu "bên ngoài" qua HTTP API (đã chọn ngày 23/10/2026)

> **Đã chọn.** Người thực hiện xác nhận ý của giảng viên là: lấy dữ liệu CICIDS2017 năm 2017 rồi viết thành API. Phương án B đáp ứng đúng ý này và đã được cài đặt (xem 14.14.8).

**Bối cảnh.** Giảng viên có nhắc đến "outsource dữ liệu" và/hoặc "viết API cho dữ liệu đó" (chưa nhớ nguyên văn). Cách hiểu hợp lý nhất: dữ liệu đến từ một **hệ thống bên ngoài** và được lấy về **qua API** mà nhóm tự viết. Thiết kế ở 14.5.4 (Simulator ghi thẳng vào MySQL) không có API nên có thể chưa đáp ứng cách hiểu này. Phương án B thêm một lớp API HTTP mà **không làm thay đổi các phần phía sau** (MySQL, Debezium, Kafka, consumer, kho dữ liệu, Data Lake).

#### 14.14.1. So sánh hai phương án

| Tiêu chí | A: Simulator ghi thẳng MySQL (14.5.4) | B: Firewall API + Collector |
|---|---|---|
| Có API HTTP | Không | Có (API do nhóm viết, đóng vai hệ thống firewall bên ngoài) |
| Thể hiện "dữ liệu từ nguồn ngoài" | Yếu: chương trình trong cùng hệ thống ghi thẳng vào CSDL | Rõ hơn: dữ liệu đi qua ranh giới HTTP có xác thực, giới hạn tốc độ |
| Số thành phần cần viết | 1 (Simulator) | 2 (Firewall API và Collector) |
| Thời gian | Theo kế hoạch | Thêm khoảng 2-3 ngày |
| Ảnh hưởng đến phần sau | Không | Không (vẫn kết thúc ở bảng `raw_network_logs`) |

Khuyến nghị: chọn **B** vì thỏa cả hai cách hiểu của câu thầy nói, chi phí thấp.

#### 14.14.2. Kiến trúc phương án B

```
CSV UNB ──> [Firewall API (HTTP)] <──poll── [Collector (Python)] ──INSERT──> [MySQL: raw_network_logs]
             hệ thống "bên ngoài"            sleep giữa các lần gọi                 │ binlog
                                                                                    ▼
                                                           Debezium -> Kafka -> ETL consumer -> MinIO/S3 + PostgreSQL
```

#### 14.14.3. Firewall API (`src/api_simulator/api.py`)

| Điểm | Thiết kế |
|---|---|
| Công nghệ | Một web framework Python gọn nhẹ, tự sinh tài liệu OpenAPI (ví dụ FastAPI + uvicorn); trang tài liệu tương tác dùng để demo |
| Điểm cuối | `GET /health` (kiểm tra sống); `GET /v1/logs?after=<seq>&limit=<n>` (lấy các bản ghi mới sau con trỏ `seq`); `GET /v1/stats` (tiến độ phát lại, số bản ghi đã "xảy ra") |
| Con trỏ | Mỗi bản ghi có `seq` tăng dần (thứ tự phát lại). Client gửi `after=<seq cuối đã nhận>`, nên gọi lại không bị mất hay trùng |
| Nhịp phát | API giữ một "đồng hồ phát lại": chỉ những bản ghi **đã đến lúc** (theo tốc độ cấu hình, ví dụ 200 dòng/giây) mới được trả về, nên Collector gọi nhanh hay chậm thì dòng dữ liệu vẫn chảy theo tốc độ thật |
| Xác thực, giới hạn | Khóa API trong header; trả 401 nếu sai khóa; 429 nếu gọi quá dày; khóa lấy từ `.env` |
| Định dạng | JSON; mỗi bản ghi có đủ các trường của CSV (tên theo `raw_network_logs_columns.json`); `Infinity`/`NaN` được đổi thành `null` ngay tại API |
| Nguồn | Đọc các file CSV mẫu 100.000 dòng (14.13.7) theo đúng thứ tự dòng; mount thư mục dữ liệu chỉ đọc |

#### 14.14.4. Collector (`src/api_simulator/collector.py`)

- Vòng lặp: gọi API với `after=<seq>` → nhận một lô → ghi vào MySQL → `time.sleep()` ngắn → lặp lại (chính vòng lặp này đáp ứng yêu cầu "dùng `time.sleep()` để mô phỏng độ trễ").
- **Bảo đảm không trùng, không mất:** lưu con trỏ trong một bảng nhỏ `collector_state` của MySQL và cập nhật **trong cùng giao dịch** với việc ghi lô bản ghi; nếu Collector chết giữa chừng, lần chạy sau tiếp tục đúng chỗ.
- Xử lý lỗi: hết thời gian chờ, mã 429/5xx thì thử lại có chờ tăng dần; mã 401 thì dừng và báo rõ.
- Cần bổ sung vào `sql/mysql/02_raw_network_logs.sql` bảng `collector_state` và cấp thêm quyền `SELECT, INSERT, UPDATE` trên bảng này cho tài khoản ghi dữ liệu trong `docker/mysql/init/01_users.sh` (tài khoản vẫn **không** có quyền xóa dữ liệu của `raw_network_logs`).

#### 14.14.5. Thay đổi so với kế hoạch

| Mục | Thay đổi |
|---|---|
| Công việc 10 (mục 15) | Tách thành 10a (Firewall API: đọc CSV, nhịp phát, con trỏ, xác thực) và 10b (Collector: gọi API, ghi MySQL, con trỏ trong giao dịch) |
| Công việc 11 | Kiểm thử cả hai: gọi API bằng trang tài liệu tương tác, thử con trỏ, thử sai khóa, thử tắt API giữa chừng rồi bật lại |
| `docker-compose.yml` | Thêm hai dịch vụ `firewall-api` và `collector` (profile `app`); `collector` đợi `mysql` khỏe và `firewall-api` chạy |
| `docker/requirements-stream.txt` | Thêm thư viện web framework, máy chủ ASGI và thư viện gọi HTTP |
| `src/api_simulator/` | `reader.py` (đọc CSV, dùng chung), `api.py` (API), `collector.py` (Collector), `make_ddl.py` (đã có) |
| Thời gian | Thêm khoảng 2-3 ngày vào giai đoạn 2 |

#### 14.14.6. Lưu ý khi trình bày
- Trong báo cáo nói rõ đây là **hệ thống bên ngoài được mô phỏng** (do nhóm tự viết và tự chạy), không phải dịch vụ của bên thứ ba.
- Nếu giảng viên muốn dịch vụ bên ngoài **thật**, có thể thêm bước làm giàu `dim_ip` bằng một API bên thứ ba (tra cứu vị trí địa lý hoặc mức độ nguy hiểm của IP). Cần kiểm tra điều khoản và giới hạn dùng của dịch vụ đó trước, và không để buổi demo phụ thuộc vào mạng Internet.

#### 14.14.7. Câu hỏi nên hỏi lại giảng viên (mẫu)
> "Thưa thầy, em hiểu yêu cầu 'outsource dữ liệu' là dữ liệu phải đến từ một hệ thống bên ngoài thông qua API do em tự viết (em dùng dữ liệu CICIDS2017 phát lại qua API đó), đúng không ạ? Hay thầy muốn dùng một API dữ liệu có sẵn của bên thứ ba?"


#### 14.14.8. File đã tạo và kết quả kiểm thử (23/10/2026)

| File | Vai trò |
|---|---|
| `src/api_simulator/reader.py` | Đọc CSV theo đúng thứ tự thời gian, đổi sang tên cột MySQL, `Infinity`/`NaN` thành giá trị thiếu |
| `src/api_simulator/api.py` | Firewall API (FastAPI): `/health`, `/v1/logs`, `/v1/stats`; khóa API; giới hạn 429; đồng hồ phát lại |
| `src/api_simulator/collector.py` | Gọi API theo chu kỳ, ghi MySQL; con trỏ trong `collector_state` cập nhật cùng giao dịch |
| `src/api_simulator/make_replay_sample.py` | Tạo `data/replay/replay_sample.csv` (~100.000 dòng, đủ mọi nhãn) từ dữ liệu gốc |
| `src/api_simulator/make_ddl.py`, `sql/mysql/02_raw_network_logs.sql` | **Sửa:** thêm bảng `collector_state` và quyền `UPDATE` trên bảng này cho tài khoản `simulator` (tài khoản này vẫn không xóa/sửa được `raw_network_logs`) |
| `docker-compose.yml` | **Sửa:** thêm dịch vụ `firewall-api` và `collector` (`profiles: ["app"]`) |
| `.env.example`, `docker/requirements-stream.txt` | **Sửa:** thêm `FIREWALL_API_KEY`, `REPLAY_RATE`..., thư viện `fastapi`, `uvicorn` |
| `tests/test_api_simulator.py` | 13 kiểm thử tự động |

**Cách chạy (trên máy, không cần Docker để thử)**

1. Tạo tập mẫu: chạy `python -m src.api_simulator.make_replay_sample` (đọc `data/raw/cicids2017`, ghi `data/replay/replay_sample.csv`).
2. Chạy API bằng uvicorn với tham số `--factory` trỏ tới `src.api_simulator.api:create_app_from_env`; đặt biến môi trường `API_KEY`, `REPLAY_DIR`, `REPLAY_RATE`, rồi mở trang `/docs`.
3. Chạy `python -m src.api_simulator.collector` với biến môi trường `API_URL`, `API_KEY` và thông tin MySQL (tài khoản `simulator`).
4. Trong Docker: `docker compose --profile app up -d firewall-api collector`.

**Kết quả kiểm thử**

| Nội dung | Kết quả |
|---|---|
| 13 kiểm thử đơn vị (API: xác thực, đồng hồ phát lại, phân trang không hở/không trùng, giới hạn tham số, 429, thống kê; reader: tên cột, `Infinity`/`NaN`, từ chối bản `MachineLearningCSV`, thứ tự file; tạo mẫu: hạn ngạch, đoạn liên tục, giữ thứ tự và header; Collector: commit hoặc rollback theo con trỏ) | Đạt 13/13; toàn bộ bộ kiểm thử của dự án (ETL, Data Mining, API) đạt 45/45 |
| Chạy thật API (uvicorn) + Collector + MySQL 8.0.46 với 56.649 dòng dữ liệu **giả** đúng định dạng 85 cột: sai khóa API; `kill -9` Collector giữa chừng; tắt API khi Collector đang chạy rồi bật lại | Đạt: sai khóa thì thoát với thông báo rõ; MySQL có đúng 56.649 dòng bằng tổng của API và bằng con trỏ; tập (`flow_id`, cổng nguồn, giờ, nhãn) giống hệt CSV kể cả số lần lặp; thứ tự được giữ; nhãn có byte lạ nguyên vẹn; không mất, không trùng |
| Tốc độ ghi | Ở lần chạy đầu, Collector ghi được khoảng 10.700 dòng trong chừng 5 giây trong môi trường thử (CPU hạn chế, một kết nối, lô 500 dòng). Máy bạn sẽ khác; hãy đo lại ở công việc 11 |

**Chưa kiểm thử:** chạy trong Docker; kết hợp với Debezium (sự kiện CDC sinh ra từ các INSERT theo lô); dữ liệu CICIDS2017 **thật** (`make_replay_sample` mới chỉ thử trên dữ liệu giả; với 2,8 triệu dòng nó duyệt nhãn bằng vòng lặp Python nên có thể mất vài phút); MySQL 8.4.

**Lưu ý khi vận hành**
- Tốc độ cả hệ thống bị chặn bởi `REPLAY_RATE` của API (mặc định 200 dòng/giây): Collector gọi nhanh hơn cũng chỉ nhận được những dòng "đã đến lúc". Đặt `REPLAY_RATE=0` để phát hết ngay khi muốn kiểm thử tốc độ ghi.
- Đồng hồ phát lại khởi động ở lần gọi `/v1/logs` đầu tiên. Nếu khởi động lại API, đồng hồ chạy lại từ đầu nhưng `seq` của từng bản ghi giữ nguyên, nên Collector chỉ phải chờ rồi tiếp tục đúng chỗ.
- Collector tự thoát khi API báo hết dữ liệu; thêm `--follow` nếu muốn chạy mãi.
- Khi Collector bị dừng giữa giao dịch, MySQL hủy giao dịch đó; cột `log_id` (tự tăng) có thể có khoảng trống. Điều này không ảnh hưởng vì kho dữ liệu chỉ cần `log_id` duy nhất, không cần liên tục.

---

## 15. Cẩm nang thực hiện nâng cấp: công việc tuần tự, công cụ và các bước chi tiết

Mục này cụ thể hóa các giai đoạn ở mục 14.6 thành **28 công việc làm lần lượt**, mô tả bằng lời (không kèm mã nguồn). Mỗi công việc có: mục tiêu, công cụ, các bước và cách kiểm tra. Khi cần chi tiết kỹ thuật (thuộc tính connector, thiết kế bảng, cấu hình listener...) hãy xem mục 14.5.

**Quy tắc làm việc xuyên suốt**
- Làm đúng thứ tự; **chỉ sang công việc tiếp theo khi "cách kiểm tra" của công việc trước đã đạt**.
- Sau mỗi công việc: commit lên Git với mô tả ngắn; sau mỗi giai đoạn: gắn tag.
- Ghi vào `docs/decisions.md`: phiên bản image đã ghim, lỗi gặp và cách khắc phục (dùng làm tư liệu cho báo cáo).
- Luôn thử với **lượng dữ liệu nhỏ** (100 → 1.000 → 10.000 dòng) trước khi tăng.
- **Điểm dừng an toàn:** nếu thiếu thời gian, dừng sau công việc 20 (đã đủ yêu cầu 1-5 của đề nâng cấp); các công việc 21-28 là phần hoàn thiện và mở rộng.

### 15.1. Bảng tổng hợp công việc

| # | Công việc | Công cụ chính | Đầu ra |
|---|---|---|---|
| **Giai đoạn 0: Chuẩn bị (khoảng 2 ngày)** | | | |
| 1 | Kiểm tra máy, cài Docker | Docker Desktop, WSL2 | Docker chạy được, cấp đủ RAM |
| 2 | Cài công cụ hỗ trợ | Git, VS Code, Python, DBeaver, Postman, S3 client | Bộ công cụ sẵn sàng |
| 3 | Sao lưu và đánh dấu mốc | Git, DBeaver/pgAdmin | Bản sao lưu, tag `v1-batch` |
| 4 | Chốt quyết định và kéo thử image | Docker, trình duyệt | Danh sách phiên bản đã ghim |
| **Giai đoạn 1: Hạ tầng (3-4 ngày)** | | | |
| 5 | Lập biến môi trường và cấu trúc thư mục | VS Code, Git | `.env`, thư mục mới |
| 6 | Cấu hình `docker-compose.yml` | VS Code, tài liệu image | File compose hoàn chỉnh |
| 7 | Khởi động và kiểm tra từng dịch vụ | Docker Desktop, DBeaver, trình duyệt, S3 client | Mọi dịch vụ khỏe |
| 8 | Kiểm tra tính bền vững | Docker Desktop | Dữ liệu còn sau khi tắt/bật |
| **Giai đoạn 2: Nguồn dữ liệu (3 ngày)** | | | |
| 9 | Thiết kế và tạo bảng `raw_network_logs` | DBeaver, VS Code | Bảng nguồn trong MySQL |
| 10 | Xây Firewall API và Collector | VS Code, Python | API phục vụ log và Collector ghi vào MySQL |
| 11 | Kiểm thử API và Collector | Trang `/docs`, DBeaver | Đúng số dòng, giá trị, không mất/trùng khi dừng giữa chừng |
| 12 | Tạo tập dữ liệu phát lại | `make_replay_sample`, `qc_label_distribution` | `data/replay/replay_sample.csv` (~100.000 dòng) |
| **Giai đoạn 3: CDC (3 ngày)** | | | |
| 13 | Chuẩn bị MySQL cho CDC | DBeaver | Binlog đúng, hai tài khoản |
| 14 | Đăng ký Debezium connector | Postman hoặc curl, trình duyệt | Connector `RUNNING` |
| 15 | Quan sát sự kiện trên Kafka, đo độ trễ | Công cụ xem Kafka (UI hoặc dòng lệnh) | Bảng đo độ trễ CDC |
| 16 | Thử gián đoạn Debezium | Docker Desktop | Không mất sự kiện |
| **Giai đoạn 4: ETL streaming (7-10 ngày)** | | | |
| 17 | Cập nhật schema PostgreSQL | DBeaver, VS Code | Cột và bảng mới |
| 18 | Tách lõi làm sạch dùng chung | VS Code, pytest | Batch vẫn chạy, 32 kiểm thử đạt |
| 19 | Xây consumer và các đích ghi | VS Code, Python | `stream_consumer` chạy được |
| 20 | Kiểm thử consumer từ nhỏ đến lớn | DBeaver, S3 client, công cụ xem Kafka | Số dòng khớp ở mọi nơi |
| **Giai đoạn 5: Độ tin cậy (3 ngày)** | | | |
| 21 | Chạy các kịch bản lỗi và đối soát | Docker Desktop, DBeaver | Bảng kết quả kịch bản |
| **Giai đoạn 6: Tích hợp phân tích (4 ngày)** | | | |
| 22 | Cấu hình OLAP và ML đọc từ PostgreSQL và S3 | VS Code | Script chạy được trên hạ tầng mới |
| 23 | Cập nhật hai notebook | Jupyter | Notebook 03 và 04 chạy được |
| 24 | Gộp file Parquet nhỏ, huấn luyện lại | Python, S3 client | Kết quả so sánh với bản batch |
| **Giai đoạn 7: Hoàn thiện (3 ngày)** | | | |
| 25 | Dashboard (tùy chọn) | Power BI Desktop hoặc Streamlit | Dashboard gần thời gian thực |
| 26 | Thu thập số liệu và ảnh chụp | DBeaver, Docker Desktop, công cụ Kafka | Bộ số liệu cho báo cáo |
| 27 | Đóng gói, README, kịch bản demo | VS Code, Git | Dự án chạy được trên máy sạch |
| 28 | Cập nhật báo cáo | Trình soạn thảo | Báo cáo hoàn chỉnh |

### 15.2. Công cụ cần chuẩn bị

| Công cụ | Dùng để làm gì | Ghi chú |
|---|---|---|
| Docker Desktop (hoặc Docker Engine + Compose v2) | Chạy toàn bộ hạ tầng | Windows cần WSL2 |
| Git | Quản lý phiên bản, tag mốc | |
| VS Code (+ tiện ích Docker, YAML, Python) | Soạn file cấu hình và mã nguồn | |
| Python 3.11 trở lên, môi trường ảo (venv) | Chạy simulator, consumer, ETL batch, OLAP, ML | Cài từ `requirements.txt` |
| DBeaver | Một công cụ kết nối cả MySQL lẫn PostgreSQL để xem bảng, chạy truy vấn kiểm tra | Có thể thay bằng MySQL Workbench và pgAdmin |
| Postman (hoặc curl, trình duyệt) | Gọi REST API của Debezium/Kafka Connect | Trình duyệt đủ cho các lệnh chỉ đọc |
| Công cụ xem Kafka | Xem topic, thông điệp, độ trễ của consumer | Dùng công cụ dòng lệnh đi kèm image Kafka, hoặc một giao diện web (ví dụ Kafdrop, AKHQ) nếu muốn trực quan |
| S3 client (Cyberduck, S3 Browser hoặc AWS CLI) | Xem bucket, file Parquet trong Data Lake | Console web của dịch vụ S3 nếu image có kèm |
| Jupyter | Chạy hai notebook 03 và 04 | |
| Power BI Desktop (tùy chọn) | Dashboard | Có thể dùng Streamlit thay thế |

### 15.3. Hướng dẫn chi tiết từng công việc

#### Giai đoạn 0: Chuẩn bị

**Công việc 1. Kiểm tra máy, cài Docker**
- *Công cụ:* Docker Desktop, WSL2 (Windows).
- *Các bước:*
  1. Xác nhận cấu hình: RAM khuyến nghị 16 GB (tối thiểu dành được 8 GB cho Docker), ổ cứng trống tối thiểu 30 GB.
  2. Bật ảo hóa (virtualization) trong BIOS nếu máy chưa bật.
  3. Windows: bật WSL2, cài Docker Desktop và chọn WSL2 làm nền. macOS/Linux: cài bản tương ứng.
  4. Cấp bộ nhớ cho Docker: Windows dùng file cấu hình `.wslconfig` trong thư mục người dùng để đặt giới hạn bộ nhớ; macOS vào Settings, mục Resources.
  5. Mở Docker Desktop, kiểm tra Compose là phiên bản 2 (lệnh `docker compose version`).
  6. Chạy thử container mẫu `hello-world`.
- *Kiểm tra:* container mẫu chạy được; mục Resources hiển thị đúng bộ nhớ đã cấp.

**Công việc 2. Cài công cụ hỗ trợ**
- *Công cụ:* theo bảng 15.2.
- *Các bước:*
  1. Cài Git, VS Code và các tiện ích Docker, YAML, Python.
  2. Cài Python, tạo môi trường ảo cho dự án và cài thư viện theo `requirements.txt` (sẽ bổ sung thư viện mới ở công việc 22).
  3. Cài DBeaver; lần đầu tạo kết nối sẽ tự tải driver cho MySQL và PostgreSQL.
  4. Cài Postman (hoặc dùng curl/trình duyệt) và một S3 client.
- *Kiểm tra:* mở được từng công cụ; môi trường ảo chạy được bộ kiểm thử hiện có (32 kiểm thử đạt).

**Công việc 3. Sao lưu và đánh dấu mốc**
- *Công cụ:* Git, DBeaver hoặc pgAdmin.
- *Các bước:*
  1. Commit toàn bộ mã hiện tại, gắn tag `v1-batch`.
  2. Sao lưu cơ sở dữ liệu PostgreSQL hiện tại (chức năng Backup của DBeaver/pgAdmin).
  3. Sao chép thư mục Parquet sạch và `reports/` sang nơi an toàn.
  4. Ghi lại các con số chuẩn của bản batch: số dòng `fact_flow`, số dòng từng nhãn, kết quả mô hình. Đây là cơ sở đối chiếu sau khi nâng cấp.
- *Kiểm tra:* có thể quay lại bản batch bất cứ lúc nào.

**Công việc 4. Chốt quyết định và kéo thử image**
- *Công cụ:* Docker, trình duyệt (trang image trên quay.io/Docker Hub, tài liệu Debezium).
- *Các bước:*
  1. Chốt ba quyết định ở mục 14.4: Kafka KRaft hay Zookeeper; image cho kho S3; số dòng phát lại.
  2. Với mỗi image (MySQL 8.4, PostgreSQL, Kafka, Debezium Connect 3.x, kho S3), mở trang image, chọn tag **cụ thể** (không dùng `latest`).
  3. Kéo từng image về máy. Image kho S3 là rủi ro cao nhất: nếu không kéo được thì đổi sang phương án thay thế ngay (14.4 #1). Đã xác nhận ở 14.13: image MinIO chính thức không kéo được; hãy thử image trong biến `S3_IMAGE` của `.env.example` trước.
  4. Đọc tài liệu connector MySQL của **đúng phiên bản Debezium** đã chọn (tên thuộc tính đã đổi giữa các phiên bản).
  5. Ghi phiên bản đã ghim vào `docs/decisions.md`.
- *Kiểm tra:* mọi image đã kéo thành công; có danh sách phiên bản.

#### Giai đoạn 1: Hạ tầng

**Công việc 5. Lập biến môi trường và cấu trúc thư mục**
- *Công cụ:* VS Code, Git.
- *Các bước:*
  1. Tạo các thư mục mới theo mục 14.7 (`docker/`, `docker/debezium/`, `sql/mysql/`, `src/api_simulator/`).
  2. Mở rộng `.env.example`: mật khẩu root MySQL, tài khoản/mật khẩu `debezium` và `simulator`, thông tin PostgreSQL, khóa truy cập và khóa bí mật S3, tên bucket, các cổng.
  3. Sao chép thành `.env`, bảo đảm `.env` nằm trong `.gitignore`.
  4. Chọn cổng trên máy chủ (gợi ý: MySQL 3307, PostgreSQL 5433, Kafka ngoài 29092, Connect 8083, S3 9000) và kiểm tra cổng nào đang bị chiếm (Resource Monitor trên Windows, hoặc công cụ tương đương); đổi số cổng nếu trùng.
- *Kiểm tra:* không cổng nào trùng; `.env` không bị Git theo dõi.

**Công việc 6. Cấu hình `docker-compose.yml`**
- *Công cụ:* VS Code (tiện ích YAML/Docker), tài liệu của từng image.
- *Các bước:* **làm từng khối, không viết tất cả một lần**; sau mỗi khối kiểm tra cú pháp bằng lệnh `docker compose config` rồi khởi động thử khối đó.
  1. Khai báo mạng chung và các volume có tên (`mysql_data`, `pg_data`, `kafka_data`, `minio_data`, thêm hai volume Zookeeper nếu dùng).
  2. Khối nền: `mysql` và `postgres`. MySQL: ghim phiên bản, mật khẩu từ `.env`, bật binlog dạng ROW (`binlog_row_image=FULL`, `server_id`, thời hạn giữ binlog), mount thư mục SQL khởi tạo, cổng và kiểm tra sức khỏe. PostgreSQL: ghim phiên bản, mount file schema để tự tạo bảng, cổng, kiểm tra sức khỏe.
  3. Khối Kafka: cấu hình hai listener (nội bộ và bên ngoài), ghim phiên bản, volume dữ liệu, kiểm tra sức khỏe; thêm Zookeeper nếu chọn phương án đó.
  4. Khối `connect` (Debezium): địa chỉ broker, nhóm Connect, tên ba topic lưu cấu hình/offset/trạng thái (replication factor 1), chờ Kafka và MySQL khỏe rồi mới chạy.
  5. Khối kho S3: khóa truy cập từ `.env`, volume dữ liệu, cổng.
  6. Khối `init` (chạy một lần): tạo bucket và đăng ký connector; chỉ thêm khi các công việc 9-14 đã làm xong.
  7. Khối `api-simulator` và `etl-consumer`: để trong `profiles` riêng, thêm ở công việc 10 và 19.
- *Kiểm tra:* `docker compose config` không báo lỗi.

**Công việc 7. Khởi động và kiểm tra từng dịch vụ**
- *Công cụ:* Docker Desktop (tab Containers, Logs), DBeaver, trình duyệt, S3 client.
- *Các bước:*
  1. Khởi động theo thứ tự: MySQL và PostgreSQL → Kafka → Connect → kho S3. Quan sát cột trạng thái trong Docker Desktop đến khi `healthy`; nếu lỗi, đọc tab Logs của dịch vụ đó.
  2. *MySQL:* trong DBeaver tạo kết nối tới máy chủ cổng 3307. Nếu báo lỗi "Public Key Retrieval is not allowed", vào thuộc tính driver của kết nối và bật tùy chọn cho phép lấy khóa công khai. Kiểm tra CSDL `firewall` và bảng `raw_network_logs` đã được tạo.
  3. *PostgreSQL:* kết nối cổng 5433; kiểm tra có đủ bảng fact, dimension, `etl_batch_log`.
  4. *Kafka:* dùng công cụ trong container Kafka (hoặc giao diện web) tạo một topic thử, gửi một thông điệp và đọc lại.
  5. *Connect:* mở trong trình duyệt địa chỉ Connect cổng 8083 để thấy phiên bản; mở đường dẫn danh sách plugin và xác nhận có connector MySQL của Debezium.
  6. *Kho S3:* trong S3 client nhập địa chỉ endpoint và khóa từ `.env`; xác nhận bucket `network-lake` tồn tại, thử tải lên rồi xóa một file.
- *Kiểm tra:* cả 5 dịch vụ trả lời đúng; nếu client ngoài Docker không kết nối được Kafka, xem lại cấu hình listener (14.5.1).

**Công việc 8. Kiểm tra tính bền vững**
- *Công cụ:* Docker Desktop (hoặc lệnh `docker compose down` / `up`).
- *Các bước:*
  1. Chèn thủ công một dòng thử vào MySQL và một dòng vào bảng PostgreSQL (bằng DBeaver).
  2. Tắt toàn bộ bằng `down` (không kèm tùy chọn xóa volume), rồi bật lại.
  3. Kiểm tra hai dòng thử vẫn còn; kiểm tra tab Volumes của Docker Desktop thấy đủ các volume.
  4. Ghi lại quy trình **"làm lại từ đầu"** (tắt kèm xóa volume rồi bật lại) để dùng khi cần reset.
- *Kiểm tra:* dữ liệu không mất khi tắt/bật thông thường; reset sạch hoạt động.

#### Giai đoạn 2: Nguồn dữ liệu

**Công việc 9. Thiết kế và tạo bảng `raw_network_logs`**
- *Công cụ:* DBeaver, VS Code.
- *Các bước:*
  1. Mở một file CSV gốc, lấy dòng tiêu đề (85 cột) và liệt kê tên cột.
  2. Áp dụng quy tắc ở 14.5.3: đổi tên sang snake_case, bỏ cột `Fwd Header Length` bị lặp, thêm `log_id` (khóa tự tăng), `event_time_raw`, `ingested_at`, `label`, `source_file`; dùng kiểu `DOUBLE` cho đặc trưng số (không dùng `DECIMAL`).
  3. Viết một script nhỏ sinh câu lệnh tạo bảng từ dòng tiêu đề (tránh gõ tay 85 cột); lưu kết quả vào thư mục `sql/mysql/`.
  4. Đưa vào cơ chế khởi tạo của MySQL (thư mục SQL khởi tạo), tạo lại container MySQL để áp dụng.
  5. Trong DBeaver kiểm tra cấu trúc bảng (số cột, kiểu dữ liệu) và chèn thử một dòng bằng tay.
- *Kiểm tra:* bảng có đủ cột; dòng thử chèn được.

**Công việc 10. Xây Firewall API và Collector (đã có mã, xem 14.14.8)**
- *Công cụ:* VS Code, Python, trang tài liệu tương tác của API (`/docs`), Docker.
- *Các bước:* mã đã được viết; bạn cần hiểu, chạy và kiểm tra theo từng mức:
  1. Mức 1, đọc dữ liệu: `reader.py` đọc 8 file CSV theo thứ tự thứ Hai đến thứ Sáu (sắp theo tên file thông thường sẽ cho thứ Sáu lên trước), mã hóa `latin-1`, bỏ khoảng trắng đầu tên cột, đổi tên cột theo `raw_network_logs_columns.json`, `Infinity`/`NaN` thành giá trị thiếu.
  2. Mức 2, tạo tập phát lại: chạy `make_replay_sample` để tạo `data/replay/replay_sample.csv` (xem công việc 12).
  3. Mức 3, Firewall API: chạy `api.py` bằng uvicorn trên máy (đặt khóa API và tốc độ phát), mở `/docs`, bấm Authorize, thử `GET /v1/logs` với `after` và `limit`. Quan sát: lần gọi đầu tiên khởi động đồng hồ phát lại; các lần sau chỉ trả những bản ghi "đã đến lúc".
  4. Mức 4, Collector: chạy `collector.py` với biến môi trường trỏ tới API và MySQL; quan sát log tiến độ (số dòng, dòng/giây, seq).
  5. Mức 5, đóng gói: chạy trong Docker bằng `docker compose --profile app up -d firewall-api collector`.
- *Kiểm tra:* chạy được ở cả hai chế độ (trên máy và trong container).

**Công việc 11. Kiểm thử API và Collector**
- *Công cụ:* trang `/docs` của API, DBeaver, Docker Desktop.
- *Các bước:*
  1. Chạy kiểm thử tự động `tests/test_api_simulator.py` (13 kiểm thử, không cần MySQL hay Docker).
  2. Trên `/docs`: gọi không có khóa hoặc sai khóa phải nhận 401; gọi quá dày phải nhận 429; `limit` ngoài phạm vi phải nhận 422.
  3. Phát hết tập mẫu, rồi trong DBeaver so số dòng `raw_network_logs` với `GET /v1/stats` (`total`) và với `collector_state.last_seq`: ba số phải bằng nhau.
  4. So vài dòng với CSV: IP, cổng, chuỗi thời gian, nhãn phải giống; nhãn Web Attack giữ nguyên byte lạ.
  5. **Dừng đột ngột Collector** giữa chừng (kill hoặc dừng container), chạy lại: số dòng cuối vẫn bằng tổng, không trùng.
  6. **Tắt API** khi Collector đang chạy: Collector phải chờ và thử lại; bật API lại thì chạy tiếp.
  7. Đo tốc độ ghi thực tế (dòng/giây) trên máy của bạn và ghi lại.
- *Kiểm tra:* đủ 7 điều trên.

**Công việc 12. Tạo tập dữ liệu phát lại**
- *Công cụ:* `make_replay_sample`, kết quả `qc_label_distribution` đã có.
- *Các bước:*
  1. Xem số dòng từng nhãn của dữ liệu đầy đủ và đối chiếu bảng thành phần ở 14.13.7.
  2. Chạy `python -m src.api_simulator.make_replay_sample --raw-dir data/raw/cicids2017 --out data/replay/replay_sample.csv`: lấy toàn bộ nhãn hiếm, một đoạn liên tục cho các nhãn lớn, và Benign cách đều.
  3. Kiểm tra bảng số dòng từng nhãn mà script in ra; chỉnh hạn ngạch trong `make_replay_sample.py` nếu cần.
  4. Ghi **bảng thành phần mẫu** (số dòng từng nhãn) để đưa vào báo cáo.
- *Kiểm tra:* mẫu có đủ mọi nhãn; ghi lại tổng số dòng (gần 100.000).

**Công việc 13. Chuẩn bị MySQL cho CDC**
- *Công cụ:* DBeaver (trình soạn SQL).
- *Các bước:*
  1. Kiểm tra các biến: binlog đang bật, định dạng ROW, `binlog_row_image` là FULL, `server_id` khác 0.
  2. Tạo tài khoản `debezium` với các quyền theo 14.5.2; tạo tài khoản `simulator` chỉ có quyền chèn trên CSDL `firewall`.
  3. Đặt thời hạn giữ binlog (ví dụ một ngày).
  4. Trong DBeaver tạo kết nối thử bằng tài khoản `debezium` để xác nhận đăng nhập và quyền.
- *Kiểm tra:* các biến đúng giá trị; hai tài khoản đăng nhập được; `simulator` không xóa/sửa được dữ liệu.

**Công việc 14. Đăng ký Debezium connector**
- *Công cụ:* Postman (hoặc curl), trình duyệt, tab Logs của container `connect`.
- *Các bước:*
  1. Soạn nội dung cấu hình connector theo bảng thuộc tính ở 14.5.5 (địa chỉ MySQL theo tên dịch vụ, tài khoản, tiền tố topic, danh sách bảng, topic lưu lịch sử schema, bộ chuyển đổi JSON không kèm schema, bước làm phẳng thông điệp).
  2. Dùng Postman gửi cấu hình bằng phương thức cập nhật (PUT) tới đường dẫn cấu hình của connector trên cổng 8083.
  3. Gửi yêu cầu xem trạng thái connector: cả connector lẫn task phải ở trạng thái `RUNNING`.
  4. Nếu `FAILED`: đọc thông báo lỗi trong phản hồi trạng thái và log container `connect`. Lỗi thường gặp: sai mật khẩu hoặc thiếu quyền, `server id` trùng với MySQL, lỗi xác thực của MySQL 8.4, sai tên bảng.
  5. Khi ổn, đưa bước đăng ký vào dịch vụ `init` để tự động mỗi lần khởi động.
- *Kiểm tra:* trạng thái `RUNNING`; chạy lại lệnh đăng ký nhiều lần không gây lỗi.

**Công việc 15. Quan sát sự kiện trên Kafka và đo độ trễ**
- *Công cụ:* công cụ xem Kafka, Simulator, DBeaver.
- *Các bước:*
  1. Liệt kê topic: phải thấy topic dữ liệu (dạng `fw.firewall.raw_network_logs`), topic lịch sử schema và các topic nội bộ của Connect.
  2. Phát 100 dòng bằng Simulator, đọc thông điệp từ đầu topic.
  3. Mở một thông điệp: kiểm tra có đủ các cột của dòng và hai trường thời gian do Debezium thêm vào (thời điểm giao dịch ở MySQL, thời điểm Debezium xử lý).
  4. Đếm thông điệp trên topic: phải bằng số dòng đã phát.
  5. Đo độ trễ CDC trên khoảng 20 mẫu: lấy chênh lệch giữa thời điểm Debezium xử lý và thời điểm giao dịch; lập bảng trung vị và phân vị 95. Nếu muốn giảm độ trễ, thử giảm khoảng thời gian thăm dò của connector.
- *Kiểm tra:* đủ 100 thông điệp, có bảng độ trễ.

**Công việc 16. Thử gián đoạn Debezium**
- *Công cụ:* Docker Desktop, Simulator, công cụ xem Kafka.
- *Các bước:*
  1. Dừng container `connect`.
  2. Phát thêm 500 dòng bằng Simulator (MySQL vẫn nhận bình thường).
  3. Bật lại `connect`, đợi connector về `RUNNING`.
  4. Đếm lại số thông điệp trên topic: phải tăng đúng 500 và không trùng (đối chiếu theo `log_id`).
- *Kiểm tra:* không mất, không trùng.

#### Giai đoạn 4: ETL streaming

**Công việc 17. Cập nhật schema PostgreSQL**
- *Công cụ:* DBeaver, VS Code.
- *Các bước:*
  1. Thêm cột `source_log_id` vào `fact_flow` và ràng buộc UNIQUE.
  2. Tạo bảng `etl_batch_log` (batch, topic, partition, offset đầu/cuối, số dòng vào/ra/bị loại, độ trễ, thời gian bắt đầu/kết thúc).
  3. Nếu muốn làm mới `mv_*` không khóa bảng, thêm chỉ mục UNIQUE cho các materialized view.
  4. Ghi các thay đổi vào file `sql/01_create_schema.sql` để lần khởi tạo sau tự có.
  5. Chạy thử pipeline batch cũ vào kho này để chắc rằng nó vẫn hoạt động.
- *Kiểm tra:* batch cũ chạy được; hai dòng thêm tay có cùng `source_log_id` bị từ chối.

**Công việc 18. Tách lõi làm sạch dùng chung**
- *Công cụ:* VS Code, pytest.
- *Các bước:*
  1. Chạy toàn bộ bộ kiểm thử hiện có và xác nhận đạt trước khi sửa.
  2. Tách bước "đổi tên cột" khỏi phần lõi làm sạch (ép kiểu, kiểm tra IP, phân tích timestamp, loại dòng lỗi, gộp nhãn) để streaming dùng được lõi này.
  3. Sửa đường gọi của batch cho khớp.
  4. Chạy lại kiểm thử; chạy batch trên một file nhỏ và so số dòng với kết quả trước khi sửa.
- *Kiểm tra:* kiểm thử vẫn đạt; kết quả batch không đổi.

**Công việc 19. Xây consumer và các đích ghi**
- *Công cụ:* VS Code, Python, thư viện Kafka, PostgreSQL và S3 cho Python.
- *Các bước:* xây theo từng khối, **mỗi khối chạy thử với 100 thông điệp** trước khi sang khối kế:
  1. Kết nối Kafka và đọc thông điệp, chỉ in log (tắt tự động commit).
  2. Bộ chuyển đổi: biến lô thông điệp thành bảng dữ liệu có cột đúng như lõi làm sạch cần.
  3. Áp dụng lõi làm sạch.
  4. Nạp danh sách FireHOL vào bộ nhớ khi khởi động; làm giàu cờ blacklist (chỉ IP công cộng).
  5. Đích PostgreSQL: upsert dimension (có cache), chèn fact với `source_log_id`, ghi `etl_batch_log`; toàn bộ trong một giao dịch mỗi lô.
  6. Đích S3: ghi Parquet cho mỗi (ngày sự kiện, lô) với tên object suy ra từ offset.
  7. Chỉ commit offset sau khi cả hai đích thành công.
  8. Xử lý lỗi: thông điệp hỏng vào khu cách ly (quarantine); đích lỗi tạm thời thì thử lại có chờ và không commit.
  9. Tắt đúng cách khi nhận tín hiệu dừng; ghi log tốc độ và độ trễ.
  10. Thêm mục `streaming:` vào `config.yaml` (kích thước lô, thời gian tối đa) và khối `etl-consumer` vào compose.
- *Kiểm tra:* chạy 100 thông điệp qua đủ cả hai đích.

**Công việc 20. Kiểm thử consumer từ nhỏ đến lớn**
- *Công cụ:* DBeaver, S3 client, công cụ xem Kafka, log của consumer.
- *Các bước:* lặp lại cho các mức 1.000 → 10.000 → 100.000 dòng:
  1. Reset hạ tầng sạch, bật consumer, phát lượng dữ liệu của mức đó.
  2. Theo dõi độ trễ của consumer so với đầu topic (công cụ xem nhóm consumer, cột lag) đến khi về 0.
  3. Đối soát bốn nơi: số dòng ở MySQL, số thông điệp Kafka, số dòng `fact_flow`, tổng số dòng các file Parquet (đếm bằng Jupyter/pandas); cộng số dòng bị loại ở `etl_batch_log` phải khớp.
  4. So một mẫu ngẫu nhiên vài chục dòng giữa MySQL, `fact_flow` và Parquet.
  5. Kiểm tra cờ blacklist ở `dim_ip`: IP nội bộ không bị đánh dấu.
  6. Ghi lại thông lượng đạt được, kích thước lô, dung lượng Kafka/S3/PostgreSQL; thử vài giá trị kích thước lô và thời gian tối đa, chọn cấu hình hợp lý.
- *Kiểm tra:* bốn nơi khớp ở cả ba mức dữ liệu.

#### Giai đoạn 5: Độ tin cậy

**Công việc 21. Chạy các kịch bản lỗi và đối soát**
- *Công cụ:* Docker Desktop (nút Stop/Start từng container), DBeaver, công cụ xem Kafka.
- *Các bước:* với mỗi kịch bản, bắt đầu từ hạ tầng đang chạy ổn và đang phát dữ liệu; sau khi khắc phục, đợi lag về 0 rồi đối soát như công việc 20 (bước 3):
  1. Tắt đột ngột consumer giữa lúc phát, bật lại → không mất, không trùng.
  2. Dừng PostgreSQL vài phút, bật lại → consumer chờ, thử lại, không commit sớm, cuối cùng đủ dòng.
  3. Dừng dịch vụ S3 vài phút, bật lại → tương tự.
  4. Dừng Debezium (đã làm ở công việc 16, lặp lại khi có consumer).
  5. Đặt lại offset consumer về đầu topic và xử lý lại → số dòng cuối không đổi.
  6. Chèn vài dòng hỏng (IP sai, timestamp sai) vào MySQL → vào khu cách ly, ghi trong `etl_batch_log`, luồng không bị chặn.
  7. Tăng dần tốc độ phát đến khi lag tăng liên tục → ghi lại ngưỡng thông lượng.
- *Kiểm tra:* lập bảng kết quả mỗi kịch bản (đã làm gì, kết quả mong đợi, kết quả thực tế, ảnh chụp).

#### Giai đoạn 6: Tích hợp phân tích

**Công việc 22. Cấu hình OLAP và ML đọc từ PostgreSQL và S3**
- *Công cụ:* VS Code, terminal.
- *Các bước:*
  1. Bổ sung vào `requirements.txt` các thư viện đọc S3 (s3fs, boto3), Kafka và MySQL; cài lại môi trường.
  2. Sửa `.env` cho script chạy trên máy chủ: máy `localhost`, cổng PostgreSQL 5433.
  3. Thêm mục S3 (endpoint, bucket, khóa lấy từ biến môi trường) vào `config.yaml`; đổi đường dẫn Parquet sang dạng `s3://`.
  4. Viết lớp tiện ích lưu trữ dùng chung (đọc cả đường dẫn cục bộ lẫn `s3://`) và sửa hai module khai phá dữ liệu để dùng nó.
  5. Chạy nhóm truy vấn kiểm tra chất lượng, sau đó chạy toàn bộ OLAP khi Simulator đang phát dữ liệu: kết quả thay đổi theo thời gian.
  6. Chọn cách làm mới `mv_*`: để consumer làm mới mỗi vài phút, hoặc dùng view thường cho dashboard.
- *Kiểm tra:* OLAP và khai phá dữ liệu chạy được trên hạ tầng mới.

**Công việc 23. Cập nhật hai notebook**
- *Công cụ:* Jupyter.
- *Các bước:*
  1. Notebook 03 (OLAP): đổi chuỗi kết nối sang PostgreSQL trong container: máy `localhost`, cổng 5433, tên CSDL, tài khoản từ biến môi trường. Nếu notebook chạy **trong** một container thì dùng tên dịch vụ `postgres` và cổng 5432. Chạy lại từng ô; xác nhận kết quả khớp với kết quả chạy bằng script.
  2. Notebook 04 (mô hình): cài và dùng thư viện S3 cho pandas; thay đường dẫn cục bộ bằng `s3://network-lake/clean/`; truyền endpoint và khóa qua tùy chọn lưu trữ.
  3. Đọc thử một file, rồi đọc cả thư mục; so số dòng với số dòng đã nạp.
  4. Thêm một ô ghi lại danh sách file và số dòng đã dùng để huấn luyện (phục vụ tái lập).
- *Kiểm tra:* cả hai notebook chạy hết từ đầu đến cuối.

**Công việc 24. Gộp file Parquet nhỏ, huấn luyện lại**
- *Công cụ:* Python, S3 client, các script khai phá dữ liệu.
- *Các bước:*
  1. Viết và chạy job gộp các file nhỏ thành file lớn theo ngày vào vùng `compacted/`; kiểm tra tổng số dòng không đổi.
  2. **Đóng băng dữ liệu:** dừng Simulator, đợi lag consumer về 0.
  3. Chạy huấn luyện mô hình và hai câu hỏi nghiệp vụ đọc từ S3.
  4. So sánh với kết quả bản batch: cùng tập dòng thì kết quả phải gần như trùng; nếu khác (do dùng mẫu khác) thì giải thích.
- *Kiểm tra:* có bảng so sánh batch và streaming.

#### Giai đoạn 7: Hoàn thiện

**Công việc 25. Dashboard (tùy chọn)**
- *Công cụ:* Power BI Desktop hoặc Streamlit.
- *Các bước:*
  1. Power BI: tạo kết nối PostgreSQL tới `localhost:5433`; chọn view `vw_flow_enriched` và các `mv_*`.
  2. Chọn chế độ truy vấn trực tiếp (DirectQuery) nếu muốn gần thời gian thực (chậm hơn khi nhiều dòng) hoặc chế độ nhập (Import) kèm làm mới định kỳ.
  3. Dựng bốn khu vực: lưu lượng theo thời gian và giao thức; tỷ lệ các loại tấn công; bảng IP rủi ro cao; hiệu suất mô hình.
  4. Đặt làm mới tự động và thử khi Simulator đang phát.
- *Kiểm tra:* dashboard thay đổi khi dữ liệu mới đến.

**Công việc 26. Thu thập số liệu và ảnh chụp**
- *Công cụ:* DBeaver, Docker Desktop, công cụ xem Kafka, S3 client.
- *Việc cần có cho báo cáo:* ảnh trạng thái các container `healthy`; ảnh trạng thái connector `RUNNING`; bảng độ trễ ba mốc; bảng thông lượng; ảnh số dòng khớp ở bốn nơi; bảng kết quả kịch bản lỗi; ảnh cấu trúc bucket Parquet; dung lượng Kafka/S3/PostgreSQL; bảng so sánh kết quả batch và streaming.

**Công việc 27. Đóng gói, README, kịch bản demo**
- *Công cụ:* VS Code, Git.
- *Các bước:*
  1. Viết README: yêu cầu máy, cách cài, cách chạy từng bước, bảng cổng, cách reset, các lỗi thường gặp và cách xử lý.
  2. Soạn **kịch bản demo** (khoảng 10 bước): bật hạ tầng → xem các dịch vụ khỏe → bật consumer → bật Simulator → xem sự kiện trên Kafka → xem dữ liệu xuất hiện ở PostgreSQL và S3 → chạy truy vấn OLAP/dashboard → mô phỏng sự cố (dừng một dịch vụ) và cho thấy hệ thống tự phục hồi → chạy huấn luyện từ S3.
  3. Quay video demo dự phòng.
  4. Thử toàn bộ trên một máy sạch (tải mã về, tạo `.env`, bật hạ tầng, chạy demo) để chắc không phụ thuộc vào cấu hình riêng của máy bạn.
  5. Gắn tag `v2-streaming`.
- *Kiểm tra:* người khác làm theo README chạy được.

**Công việc 28. Cập nhật báo cáo**
- *Các bước:* cập nhật kiến trúc mới và sơ đồ; thêm kết quả đo (bảng, ảnh ở công việc 26); nêu các điểm ở mục 14.11 (mô phỏng thời gian thực, ba mốc độ trễ, nhãn của môi trường lab, giới hạn của image không còn được bảo trì, vai trò của pipeline batch); cập nhật cây thư mục và danh sách file.
- *Kiểm tra:* mọi con số trong báo cáo đều truy được về một bảng hoặc ảnh chụp đã thu thập.

---

## 16. Bổ sung tùy chọn: điều phối bằng Apache Airflow

> **Quyết định ngày 22/10/2026: KHÔNG dùng Airflow** (mục này giữ để tham khảo). Thiết kế ở mục 14 chưa dùng Airflow **có chủ ý**. Mục này giải thích lý do, và nếu bạn muốn thì đây là cách thêm Airflow vào mà không làm hỏng phần còn lại. Đây vẫn là thiết kế, chưa có mã chạy thử.

### 16.1. Vì sao mục 14 chưa có Airflow

- **Đường streaming không cần bộ điều phối.** Debezium, Kafka và consumer là các dịch vụ **chạy liên tục**; chúng không chạy "theo lịch" nên không có việc cho Airflow. Airflow được thiết kế để chạy các tác vụ có đầu và có cuối (batch) theo lịch hoặc khi được kích hoạt, không phải để giữ một tiến trình đọc Kafka chạy mãi.
- **Chi phí lớn.** Hướng dẫn chính thức của Airflow cho bộ khởi động nhanh bằng Docker Compose yêu cầu cấp **ít nhất 4 GB bộ nhớ cho Docker (lý tưởng 8 GB)** và bộ này gồm nhiều dịch vụ (bộ lập lịch, máy chủ web, worker, Redis, cơ sở dữ liệu metadata). Hạ tầng ở mục 14 đã cần khoảng 5-6 GB (ước lượng thô), nên cộng thêm Airflow có thể vượt 10 GB.
- **Nhưng có việc phù hợp với Airflow.** Kế hoạch hiện tại đang xử lý các tác vụ định kỳ một cách rời rạc: làm mới `mv_*` do consumer gọi, gộp file Parquet làm tay, kiểm tra chất lượng làm tay, huấn luyện lại làm tay. Đây chính là loại việc Airflow làm tốt, nên **đáng thêm nếu máy đủ RAM hoặc đề bài yêu cầu thành phần điều phối (orchestration)**.

### 16.2. Khi nào nên và không nên thêm

| Nên thêm nếu | Không nên thêm nếu |
|---|---|
| Đề bài/giảng viên yêu cầu có thành phần điều phối pipeline | Máy chỉ có 8 GB RAM hoặc ít hơn |
| Máy có 16 GB RAM trở lên | Đã trễ tiến độ ở các công việc 17-21 (ưu tiên hoàn thành đường streaming trước) |
| Muốn thể hiện chuỗi hoàn chỉnh: nạp, kiểm tra chất lượng, huấn luyện lại theo lịch | Chỉ cần demo luồng thời gian thực |

### 16.3. Vai trò của Airflow trong hệ thống

Airflow chạy **bên cạnh** hệ thống, gọi lại các mã đã có (`run_queries`, `train`, job gộp file, `run_etl`) chứ không viết lại logic.

| DAG | Lịch | Các tác vụ | Dùng lại |
|---|---|---|---|
| `refresh_mv` | mỗi 5 phút | Làm mới `mv_traffic_hourly`, `mv_ip_risk` | `sql/04_views.sql` |
| `lake_compaction` | hàng giờ hoặc hàng ngày | Liệt kê file Parquet nhỏ theo `event_date` → gộp thành file lớn → kiểm tra tổng số dòng không đổi → (tùy chọn) dọn file nhỏ | job gộp file ở công việc 24 |
| `data_quality` | hàng giờ | Chạy nhóm truy vấn `qc_*`; đối soát số dòng MySQL, `fact_flow`, Parquet; kiểm tra trạng thái connector và lag consumer; **báo lỗi nếu vượt ngưỡng** | `03_olap_queries.sql`, REST API của Connect |
| `model_retrain` | theo lịch hoặc kích hoạt tay | Kiểm tra đủ dữ liệu và đủ nhãn → huấn luyện → so sánh F1 và FPR với mô hình hiện tại → chỉ lưu thành phiên bản mới nếu tốt hơn → ghi nhật ký | `src.mining.train` |
| `batch_backfill` | kích hoạt tay | Chạy ETL batch để nạp lịch sử hoặc đối chiếu với kết quả streaming | `src.etl.run_etl` |
| `daily_report` *(tùy chọn)* | hàng ngày | Chạy toàn bộ OLAP, xuất CSV vào `reports/tables/` | `src.olap.run_queries` |

**Không đưa vào Airflow:** consumer streaming, Simulator, Debezium, Kafka. Đây là các dịch vụ chạy liên tục; cứ để trong Docker Compose.

**Chọn một nơi duy nhất chịu trách nhiệm mỗi việc.** Nếu dùng DAG `refresh_mv` thì bỏ phần làm mới view khỏi consumer (và ngược lại), tránh hai nơi cùng làm.

### 16.4. Thiết kế triển khai

| Nội dung | Đề xuất |
|---|---|
| Cách chạy | Thêm các dịch vụ Airflow vào `docker-compose.yml` trong một `profile` riêng (ví dụ `orchestration`), chỉ bật khi cần demo hoặc kiểm thử |
| Executor | Chọn loại nhẹ chạy trong cùng tiến trình (LocalExecutor) thay vì bản Celery + Redis của bộ khởi động nhanh, để giảm số container và bộ nhớ; cần kiểm tra tài liệu của đúng phiên bản Airflow bạn dùng |
| Cơ sở dữ liệu metadata | Một **database riêng tên `airflow`** (có thể đặt trong cùng container PostgreSQL nhưng tách khỏi database kho dữ liệu, không trộn với star schema) hoặc một container PostgreSQL nhỏ riêng |
| Mã nguồn cho DAG | Thư mục `dags/` mount vào Airflow; mã dự án (`src/`) và `requirements.txt` đưa vào image tùy chỉnh (build từ image Airflow chính thức) hoặc mount vào |
| Kết nối | Khai báo kết nối tới PostgreSQL kho và tới S3 trong Airflow bằng biến môi trường lấy từ `.env`, không ghi mật khẩu vào DAG |
| Cổng | Giao diện web Airflow mặc định cổng 8080; kiểm tra trùng với các dịch vụ khác trước khi bật |
| Phiên bản | Tài liệu hiện hành của Airflow ở nhánh 3.x; ghim phiên bản và đọc đúng hướng dẫn Docker của phiên bản đó |
| Cấu hình DAG | Tắt chạy bù tự động các lần lỡ lịch (`catchup`) để khởi động lại không kích hoạt hàng loạt lần chạy; đặt `retries`, thời gian chờ tối đa (timeout); đặt múi giờ rõ ràng |

### 16.5. Các bước thực hiện (giai đoạn 8, làm sau công việc 24)

**Công việc 29. Quyết định và đo tài nguyên**
- *Công cụ:* Docker Desktop (Resources), trang tài liệu Airflow.
- *Các bước:* (1) chạy toàn bộ hạ tầng mục 14 và ghi lại mức RAM đang dùng ở Docker Desktop; (2) nếu còn dư ít nhất 4 GB thì tiếp tục, nếu không thì dừng và dùng phương án nhẹ ở 16.7; (3) đọc hướng dẫn Docker của đúng phiên bản Airflow; (4) kéo thử image Airflow chính thức.
- *Kiểm tra:* có số đo RAM trước khi thêm Airflow và quyết định "làm" hoặc "không".

**Công việc 30. Dựng Airflow trong Docker Compose**
- *Công cụ:* VS Code, Docker Desktop.
- *Các bước:* (1) thêm các dịch vụ Airflow vào compose trong profile riêng; (2) tạo database metadata và chạy bước khởi tạo (initialization) của Airflow; (3) tạo tài khoản quản trị từ biến môi trường; (4) mở giao diện web, đăng nhập; (5) ghi lại mức RAM sau khi bật.
- *Kiểm tra:* giao diện web mở được; bộ lập lịch báo khỏe; tắt profile thì phần còn lại của hệ thống không bị ảnh hưởng.

**Công việc 31. Đóng gói mã dự án và khai báo kết nối**
- *Công cụ:* VS Code, giao diện Airflow (mục Connections).
- *Các bước:* (1) tạo image Airflow tùy chỉnh có sẵn thư viện của dự án (hoặc mount `src/`); (2) tạo thư mục `dags/`; (3) khai báo kết nối tới PostgreSQL kho và tới S3 (qua biến môi trường); (4) thử một DAG mẫu rỗng để chắc Airflow thấy thư mục `dags/`.
- *Kiểm tra:* DAG mẫu hiện trong giao diện và chạy thành công.

**Công việc 32. Viết ba DAG đầu: `refresh_mv`, `data_quality`, `lake_compaction`**
- *Công cụ:* VS Code, giao diện Airflow (Graph, Logs).
- *Các bước:* làm từng DAG theo thứ tự: (1) viết các tác vụ gọi lại mã đã có; (2) kích hoạt **bằng tay** một lần và xem Graph và Logs; (3) chỉnh `retries`, timeout; (4) chỉ sau khi chạy tay ổn mới bật chạy theo lịch; (5) với `data_quality`, thử cố ý làm lệch số dòng để thấy DAG báo lỗi.
- *Kiểm tra:* mỗi DAG chạy thành công bằng tay; chạy lại hai lần liên tiếp không gây trùng dữ liệu (idempotent).

**Công việc 33. Viết `model_retrain` và `batch_backfill`**
- *Công cụ:* VS Code, giao diện Airflow.
- *Các bước:* (1) `model_retrain`: tác vụ kiểm tra điều kiện (đủ dòng và đủ nhãn, đã đóng băng dữ liệu) → huấn luyện → so sánh chỉ số với mô hình hiện có → lưu phiên bản mới nếu tốt hơn; (2) `batch_backfill`: chỉ kích hoạt tay, kèm tham số (file nào, có tạo schema không); (3) kiểm tra rằng khi điều kiện không đạt thì DAG dừng và ghi lý do.
- *Kiểm tra:* chạy tay thành công; trường hợp thiếu dữ liệu dừng đúng cách.

**Công việc 34. Kiểm thử và thu thập bằng chứng**
- *Công cụ:* giao diện Airflow, Docker Desktop, DBeaver.
- *Các bước:* (1) tắt PostgreSQL giữa lúc một DAG chạy, bật lại và xem tác vụ thử lại (retry); (2) khởi động lại Airflow và xác nhận không có chạy bù hàng loạt; (3) chụp ảnh Graph, Gantt và lịch sử chạy; (4) so sánh RAM trước và sau khi thêm Airflow.
- *Kiểm tra:* có ảnh và số liệu đưa vào báo cáo.

### 16.6. Thời gian bổ sung
Khoảng 5-7 ngày làm việc cho giai đoạn 8 (công việc 29-34), cộng vào tổng 4-5 tuần ở mục 14.10. Nếu thiếu thời gian, chỉ làm công việc 29-32 (ba DAG đầu).

### 16.7. Phương án nhẹ hơn nếu không dùng Airflow

Hệ thống ở mục 14 vẫn đáp ứng đủ 6 yêu cầu nâng cấp mà không cần Airflow. Các tác vụ định kỳ có thể xử lý đơn giản hơn:

| Việc | Cách nhẹ hơn |
|---|---|
| Làm mới `mv_*` | Consumer tự gọi mỗi vài phút; hoặc dùng view thường cho dashboard |
| Gộp file Parquet, kiểm tra chất lượng, huấn luyện lại | Chạy tay theo kịch bản demo; hoặc một container nhỏ chạy lịch bằng thư viện lập lịch của Python |
| Chạy theo lịch trên máy | Lập lịch của hệ điều hành (Task Scheduler trên Windows, cron trên Linux/macOS) |

Điểm cần nêu trong báo cáo: nếu không dùng Airflow, nói rõ lý do (luồng chính chạy liên tục nên không cần bộ điều phối; tiết kiệm tài nguyên) và các tác vụ định kỳ được xử lý bằng cách nào.

### 16.8. Đề xuất của mình
- Nếu **máy từ 16 GB RAM trở lên** hoặc **đề bài yêu cầu điều phối**: thêm Airflow ở phạm vi nhỏ (công việc 29-32 là đủ, thêm 33 nếu còn thời gian), dùng executor nhẹ, chỉ bật khi demo.
- Nếu **máy 8-12 GB RAM**: dùng phương án nhẹ ở 16.7 và ghi rõ trong báo cáo.
- Dù chọn cách nào, **làm xong đường streaming (công việc 1-20) trước**, vì đó là phần cốt lõi của nâng cấp.
