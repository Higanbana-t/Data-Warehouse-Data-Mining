-- =====================================================================
-- Star Schema: Security Data Warehouse (CICIDS2017) - PostgreSQL
-- Grain: 1 dòng fact_flow = 1 luồng kết nối mạng (network flow)
-- =====================================================================

-- CASCADE: nếu đã tạo view (04_views.sql) thì các view phụ thuộc cũng bị xóa; chạy lại 04_views.sql sau khi nạp dữ liệu.
DROP TABLE IF EXISTS etl_batch_log CASCADE;
DROP TABLE IF EXISTS fact_flow CASCADE;
DROP TABLE IF EXISTS dim_time CASCADE;
DROP TABLE IF EXISTS dim_ip CASCADE;
DROP TABLE IF EXISTS dim_protocol CASCADE;
DROP TABLE IF EXISTS dim_port CASCADE;
DROP TABLE IF EXISTS dim_label CASCADE;

-- ---------------------------------------------------------------------
-- DIMENSIONS
-- ---------------------------------------------------------------------

-- Thời gian, mức độ chi tiết: phút (time_key dạng yyyymmddHHMM nên dùng BIGINT)
CREATE TABLE dim_time (
    time_key           BIGINT PRIMARY KEY,
    full_datetime      TIMESTAMP   NOT NULL,
    date_value         DATE        NOT NULL,
    year_num           SMALLINT    NOT NULL,
    month_num          SMALLINT    NOT NULL,
    day_num            SMALLINT    NOT NULL,
    day_name           VARCHAR(10) NOT NULL,
    hour_num           SMALLINT    NOT NULL,
    minute_num         SMALLINT    NOT NULL,
    time_period        VARCHAR(10) NOT NULL,   -- Sang / Chieu / Toi / Dem
    is_business_hours  BOOLEAN     NOT NULL    -- 08:00-17:59, thứ 2 - thứ 6
);

-- Địa chỉ IP (dùng làm role-playing dimension: IP nguồn và IP đích)
CREATE TABLE dim_ip (
    ip_key            SERIAL PRIMARY KEY,
    ip_address        INET         NOT NULL UNIQUE,
    is_internal       BOOLEAN      NOT NULL,   -- IP nội bộ (10.x, 172.16-31.x, 192.168.x)
    network_segment   VARCHAR(50),             -- vd: 192.168.10.0/24 (IPv4) hoặc /64 (IPv6), phục vụ roll-up
    is_blacklisted    BOOLEAN      NOT NULL DEFAULT FALSE,
    blacklist_source  VARCHAR(100)             -- vd: firehol_level1
);

CREATE TABLE dim_protocol (
    protocol_key     SMALLINT PRIMARY KEY,
    protocol_number  SMALLINT    NOT NULL UNIQUE,  -- 6, 17, 1...
    protocol_name    VARCHAR(20) NOT NULL          -- TCP, UDP, ICMP
);

-- Cổng đích / dịch vụ
CREATE TABLE dim_port (
    port_key      SERIAL PRIMARY KEY,
    port_number   INTEGER     NOT NULL UNIQUE,
    service_name  VARCHAR(30) NOT NULL,            -- HTTP, HTTPS, SSH, FTP, Other
    port_range    VARCHAR(20) NOT NULL             -- Well-known / Registered / Dynamic
);

-- Nhãn traffic
CREATE TABLE dim_label (
    label_key     SMALLSERIAL PRIMARY KEY,
    label_raw     VARCHAR(60) NOT NULL UNIQUE,     -- nhãn gốc của dataset
    attack_group  VARCHAR(20) NOT NULL,            -- Benign / DDoS / PortScan / WebAttack / Botnet / Other
    is_attack     BOOLEAN     NOT NULL
);

-- ---------------------------------------------------------------------
-- FACT
-- ---------------------------------------------------------------------
CREATE TABLE fact_flow (
    flow_key            BIGSERIAL PRIMARY KEY,

    -- Khóa ngoại tới các dimension
    time_key            BIGINT    NOT NULL REFERENCES dim_time(time_key),
    src_ip_key          INTEGER   NOT NULL REFERENCES dim_ip(ip_key),
    dst_ip_key          INTEGER   NOT NULL REFERENCES dim_ip(ip_key),
    protocol_key        SMALLINT  NOT NULL REFERENCES dim_protocol(protocol_key),
    dst_port_key        INTEGER   NOT NULL REFERENCES dim_port(port_key),
    label_key           SMALLINT  NOT NULL REFERENCES dim_label(label_key),

    -- Degenerate dimensions (thuộc tính nằm trực tiếp trong fact)
    flow_id             VARCHAR(150),       -- Flow ID của dataset, KHÔNG duy nhất (cùng 5-tuple có thể lặp lại)
    src_port            INTEGER,
    flow_start_ts       TIMESTAMP,          -- CICIDS2017 chỉ có độ phân giải PHÚT

    -- Measures (số đo)
    flow_duration_us    BIGINT,              -- micro giây
    total_fwd_packets   INTEGER,
    total_bwd_packets   INTEGER,
    total_fwd_bytes     BIGINT,
    total_bwd_bytes     BIGINT,
    total_packets       INTEGER,             -- = fwd + bwd
    total_bytes         BIGINT,              -- = fwd + bwd
    flow_bytes_per_s    DOUBLE PRECISION,
    flow_packets_per_s  DOUBLE PRECISION,
    avg_packet_size     REAL,
    syn_flag_count      SMALLINT,
    ack_flag_count      SMALLINT,
    fin_flag_count      SMALLINT,
    rst_flag_count      SMALLINT,
    psh_flag_count      SMALLINT,

    -- Dùng cho ETL streaming: khóa idempotent = log_id của bảng raw_network_logs (MySQL).
    -- NULL với dữ liệu nạp bằng ETL batch; PostgreSQL cho phép nhiều NULL trong cột UNIQUE.
    source_log_id       BIGINT
);

-- ---------------------------------------------------------------------
-- INDEXES (cho các cột hay lọc / join)
-- ---------------------------------------------------------------------
CREATE INDEX idx_fact_time      ON fact_flow(time_key);
CREATE INDEX idx_fact_src_ip    ON fact_flow(src_ip_key);
CREATE INDEX idx_fact_dst_ip    ON fact_flow(dst_ip_key);
CREATE INDEX idx_fact_protocol  ON fact_flow(protocol_key);
CREATE INDEX idx_fact_dst_port  ON fact_flow(dst_port_key);
CREATE INDEX idx_fact_label     ON fact_flow(label_key);
CREATE INDEX idx_fact_label_src ON fact_flow(label_key, src_ip_key);

-- Mỗi flow từ nguồn streaming chỉ được vào kho một lần: nạp lại cùng một lô sẽ bị bỏ qua (INSERT ... ON CONFLICT DO NOTHING)
CREATE UNIQUE INDEX uq_fact_source_log ON fact_flow(source_log_id);

-- ---------------------------------------------------------------------
-- NHẬT KÝ ETL STREAMING: mỗi micro-batch một dòng (bằng chứng đối soát, đo độ trễ và thông lượng)
-- ---------------------------------------------------------------------
CREATE TABLE etl_batch_log (
    batch_id         BIGSERIAL PRIMARY KEY,
    consumer_group   VARCHAR(100) NOT NULL,
    topic            VARCHAR(200) NOT NULL,
    kafka_partition  INTEGER      NOT NULL,
    start_offset     BIGINT       NOT NULL,
    end_offset       BIGINT       NOT NULL,
    rows_in          INTEGER      NOT NULL,   -- số thông điệp nhận được
    rows_loaded      INTEGER      NOT NULL,   -- số dòng vào fact_flow (bỏ dòng trùng/bị loại)
    rows_rejected    INTEGER      NOT NULL DEFAULT 0,   -- số dòng bị loại khi làm sạch (đưa vào khu cách ly)
    latency_p50_ms   INTEGER,
    latency_p95_ms   INTEGER,
    started_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    finished_at      TIMESTAMPTZ,
    note             TEXT
);