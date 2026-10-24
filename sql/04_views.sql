-- 1. View phẳng phục vụ kéo thả trên Power BI
CREATE OR REPLACE VIEW vw_flow_enriched AS
SELECT 
    f.flow_id, t.full_datetime, t.day_name, t.hour_num, t.is_business_hours,
    src.ip_address AS source_ip, src.is_blacklisted AS src_blacklisted,
    dst.ip_address AS destination_ip,
    p.protocol_name, pt.port_number, pt.service_name,
    l.label_raw, l.attack_group, l.is_attack,
    f.flow_duration_us, f.total_packets, f.total_bytes, f.syn_flag_count
FROM fact_flow f
JOIN dim_time t ON f.time_key = t.time_key
JOIN dim_ip src ON f.src_ip_key = src.ip_key
JOIN dim_ip dst ON f.dst_ip_key = dst.ip_key
JOIN dim_protocol p ON f.protocol_key = p.protocol_key
JOIN dim_port pt ON f.dst_port_key = pt.port_key
JOIN dim_label l ON f.label_key = l.label_key;

-- 2. Materialized View: Lưu sẵn khối băng thông theo giờ (Tương đương vw_cube_traffic_hourly)
DROP MATERIALIZED VIEW IF EXISTS mv_traffic_hourly;
CREATE MATERIALIZED VIEW mv_traffic_hourly AS
SELECT 
    t.full_datetime, p.protocol_name, 
    SUM(f.total_bytes) AS total_bytes, SUM(f.total_packets) AS total_packets
FROM fact_flow f
JOIN dim_time t ON f.time_key = t.time_key
JOIN dim_protocol p ON f.protocol_key = p.protocol_key
GROUP BY t.full_datetime, p.protocol_name;

-- 3. Materialized View: Lưu sẵn khối hạng rủi ro IP (Tương đương vw_cube_attack_source)
DROP MATERIALIZED VIEW IF EXISTS mv_ip_risk;
CREATE MATERIALIZED VIEW mv_ip_risk AS
SELECT 
    ip.ip_address, COUNT(*) AS total_flows,
    SUM(CASE WHEN l.is_attack THEN 1 ELSE 0 END) AS attack_flows,
    ROUND(100.0 * SUM(CASE WHEN l.is_attack THEN 1 ELSE 0 END) / COUNT(*), 2) AS attack_rate_pct,
    ip.is_blacklisted AS co_lien_lac_blacklist,
    CASE 
        WHEN ROUND(100.0 * SUM(CASE WHEN l.is_attack THEN 1 ELSE 0 END) / COUNT(*), 2) > 80 THEN 'Cao'
        WHEN ROUND(100.0 * SUM(CASE WHEN l.is_attack THEN 1 ELSE 0 END) / COUNT(*), 2) > 30 THEN 'Trung bình'
        ELSE 'Thấp'
    END AS risk_level
FROM fact_flow f
JOIN dim_ip ip ON f.src_ip_key = ip.ip_key
JOIN dim_label l ON f.label_key = l.label_key
GROUP BY ip.ip_address, ip.is_blacklisted
HAVING COUNT(*) > 50;