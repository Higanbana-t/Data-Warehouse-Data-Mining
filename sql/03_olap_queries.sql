-- ==============================================================================
-- NHÓM 1: KIỂM TRA CHẤT LƯỢNG (QC)
-- ==============================================================================
-- name: qc_row_counts
SELECT 'fact_flow' AS table_name, COUNT(*) AS row_count FROM fact_flow
UNION ALL SELECT 'dim_ip', COUNT(*) FROM dim_ip
UNION ALL SELECT 'dim_time', COUNT(*) FROM dim_time;

-- name: qc_label_distribution
SELECT l.attack_group, l.label_raw, COUNT(f.flow_key) AS total_flows
FROM fact_flow f JOIN dim_label l USING (label_key)
GROUP BY l.attack_group, l.label_raw ORDER BY total_flows DESC;

-- name: qc_measure_consistency
SELECT SUM(total_packets) = SUM(total_fwd_packets + total_bwd_packets) AS is_packet_consistent,
       SUM(total_bytes) = SUM(total_fwd_bytes + total_bwd_bytes) AS is_byte_consistent
FROM fact_flow;

-- name: qc_time_range
SELECT t.day_name, MIN(t.hour_num) AS start_hour, MAX(t.hour_num) AS end_hour,
       SUM(CASE WHEN t.is_business_hours = FALSE THEN 1 ELSE 0 END) AS flows_ngoai_gio
FROM fact_flow f JOIN dim_time t USING (time_key)
GROUP BY t.day_name ORDER BY t.day_name;

-- ==============================================================================
-- NHÓM 2: CÂU HỎI 1 (ĐẶC TRƯNG DDoS)
-- ==============================================================================
-- name: q1_feature_profile
SELECT l.attack_group, COUNT(*) AS so_flow,
       ROUND(AVG(f.flow_duration_us)) AS tb_thoi_luong_us,
       ROUND(AVG(f.avg_packet_size)::numeric, 2) AS tb_kich_thuoc_goi,
       ROUND(AVG(f.syn_flag_count)::numeric, 3) AS tb_syn_flag
FROM fact_flow f JOIN dim_label l USING (label_key)
GROUP BY l.attack_group ORDER BY so_flow DESC;

-- name: q1_ddos_vs_benign
SELECT l.attack_group, MAX(f.flow_duration_us) AS max_duration, MIN(f.flow_duration_us) AS min_duration
FROM fact_flow f JOIN dim_label l USING (label_key)
WHERE l.attack_group IN ('Benign', 'DDoS') GROUP BY l.attack_group;

-- name: q1_traffic_spike_minutes
SELECT t.full_datetime, COUNT(*) AS total_flows, SUM(CASE WHEN l.is_attack THEN 1 ELSE 0 END) AS attack_flows
FROM fact_flow f JOIN dim_time t USING (time_key) JOIN dim_label l USING (label_key)
GROUP BY t.full_datetime ORDER BY total_flows DESC LIMIT 20;

-- ==============================================================================
-- NHÓM 3: CÂU HỎI 2 (BOTNET & IP RỦI RO)
-- ==============================================================================
-- name: q2_src_ip_behavior
SELECT ip.ip_address, COUNT(*) AS tong_flow, COUNT(DISTINCT f.dst_ip_key) AS so_ip_dich,
       SUM(CASE WHEN l.is_attack THEN 1 ELSE 0 END) AS flow_tan_cong
FROM fact_flow f JOIN dim_ip ip ON ip.ip_key = f.src_ip_key JOIN dim_label l USING (label_key)
GROUP BY ip.ip_address HAVING COUNT(*) >= 100 ORDER BY flow_tan_cong DESC LIMIT 20;

-- name: q2_top_ip_per_attack_group
SELECT attack_group, ip_address, attack_count, rank_in_group
FROM (
    SELECT l.attack_group, ip.ip_address, COUNT(*) AS attack_count,
           RANK() OVER(PARTITION BY l.attack_group ORDER BY COUNT(*) DESC) as rank_in_group
    FROM fact_flow f JOIN dim_ip ip ON ip.ip_key = f.src_ip_key JOIN dim_label l USING (label_key)
    WHERE l.is_attack = TRUE GROUP BY l.attack_group, ip.ip_address
) ranked WHERE rank_in_group <= 5;

-- name: q2_bot_destinations
SELECT dst_ip.ip_address AS target_ip, COUNT(*) AS hits
FROM fact_flow f JOIN dim_ip src_ip ON f.src_ip_key = src_ip.ip_key 
JOIN dim_ip dst_ip ON f.dst_ip_key = dst_ip.ip_key JOIN dim_label l USING (label_key)
WHERE l.attack_group = 'Botnet' GROUP BY dst_ip.ip_address ORDER BY hits DESC LIMIT 10;

-- ==============================================================================
-- NHÓM 4: CÂU HỎI 3 (BĂNG THÔNG & GIAO THỨC)
-- ==============================================================================
-- name: q3_protocol_by_hour
SELECT p.protocol_name, t.hour_num, SUM(f.total_bytes)/(1024*1024.0) AS mb_consumed
FROM fact_flow f JOIN dim_protocol p USING (protocol_key) JOIN dim_time t USING (time_key)
GROUP BY p.protocol_name, t.hour_num ORDER BY t.hour_num, mb_consumed DESC;

-- name: q3_rollup_protocol_period
SELECT p.protocol_name, t.time_period, SUM(f.total_bytes)/(1024*1024.0) AS mb_consumed
FROM fact_flow f JOIN dim_protocol p USING (protocol_key) JOIN dim_time t USING (time_key)
GROUP BY ROLLUP(p.protocol_name, t.time_period);

-- name: q3_bytes_zscore
WITH hourly_stats AS (
    SELECT t.hour_num, SUM(f.total_bytes) AS hourly_bytes
    FROM fact_flow f JOIN dim_time t USING (time_key) GROUP BY t.hour_num
), overall_stats AS (
    SELECT AVG(hourly_bytes) AS avg_bytes, STDDEV(hourly_bytes) AS std_bytes FROM hourly_stats
)
SELECT h.hour_num, h.hourly_bytes, (h.hourly_bytes - o.avg_bytes) / NULLIF(o.std_bytes, 0) AS z_score
FROM hourly_stats h CROSS JOIN overall_stats o ORDER BY z_score DESC;

-- name: q3_offhours_by_protocol
SELECT p.protocol_name, COUNT(*) AS flows_ngoai_gio
FROM fact_flow f JOIN dim_protocol p USING (protocol_key) JOIN dim_time t USING (time_key)
WHERE t.is_business_hours = FALSE GROUP BY p.protocol_name;

-- ==============================================================================
-- NHÓM 5: CÂU HỎI 4 (PORTSCAN & BLACKLIST)
-- ==============================================================================
-- name: q4_portscan_sources
SELECT ip.ip_address, ip.is_internal, ip.is_blacklisted,
       COUNT(*) AS so_flow_portscan, COUNT(DISTINCT f.dst_port_key) AS so_cong_bi_quet
FROM fact_flow f JOIN dim_label l ON l.label_key = f.label_key JOIN dim_ip ip ON ip.ip_key = f.src_ip_key
WHERE l.attack_group = 'PortScan'
GROUP BY ip.ip_address, ip.is_internal, ip.is_blacklisted ORDER BY so_flow_portscan DESC LIMIT 20;

-- name: q4_blacklist_contacts
SELECT src.ip_address AS internal_ip, dst.ip_address AS blacklisted_ip, COUNT(*) AS connection_count
FROM fact_flow f JOIN dim_ip src ON f.src_ip_key = src.ip_key JOIN dim_ip dst ON f.dst_ip_key = dst.ip_key
WHERE src.is_internal = TRUE AND dst.is_blacklisted = TRUE
GROUP BY src.ip_address, dst.ip_address ORDER BY connection_count DESC;

-- ==============================================================================
-- NHÓM 6: CÁC PHÉP TOÁN OLAP MINH HỌA ĐIỂN HÌNH
-- ==============================================================================
-- name: olap_slice_friday
SELECT l.attack_group, COUNT(*) as flows FROM fact_flow f 
JOIN dim_time t USING (time_key) JOIN dim_label l USING (label_key)
WHERE t.day_name = 'Friday' GROUP BY l.attack_group;

-- name: olap_dice_friday_tcp_attacks
SELECT t.hour_num, COUNT(*) as attacks FROM fact_flow f 
JOIN dim_time t USING (time_key) JOIN dim_label l USING (label_key) JOIN dim_protocol p USING (protocol_key)
WHERE t.day_name = 'Friday' AND p.protocol_name = 'TCP' AND l.is_attack = TRUE GROUP BY t.hour_num;

-- name: olap_pivot_attack_by_day
SELECT l.attack_group,
       SUM(CASE WHEN t.day_name = 'Monday' THEN 1 ELSE 0 END) AS Mon,
       SUM(CASE WHEN t.day_name = 'Tuesday' THEN 1 ELSE 0 END) AS Tue,
       SUM(CASE WHEN t.day_name = 'Wednesday' THEN 1 ELSE 0 END) AS Wed,
       SUM(CASE WHEN t.day_name = 'Thursday' THEN 1 ELSE 0 END) AS Thu,
       SUM(CASE WHEN t.day_name = 'Friday' THEN 1 ELSE 0 END) AS Fri
FROM fact_flow f JOIN dim_time t USING (time_key) JOIN dim_label l USING (label_key)
GROUP BY l.attack_group;

-- name: olap_rollup_day_hour_attack
SELECT t.day_name, t.hour_num, COUNT(*) AS attacks
FROM fact_flow f JOIN dim_time t USING (time_key) JOIN dim_label l USING (label_key)
WHERE l.is_attack = TRUE GROUP BY ROLLUP(t.day_name, t.hour_num);

-- name: olap_cube_attack_service
SELECT l.attack_group, pt.service_name, COUNT(*) AS so_flow
FROM fact_flow f JOIN dim_label l USING (label_key) JOIN dim_port pt ON pt.port_key = f.dst_port_key
WHERE l.is_attack = TRUE GROUP BY CUBE (l.attack_group, pt.service_name);