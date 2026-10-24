# nạp vào SQL Server (dimension trước, fact sau)
"""LOAD: dựng các bảng dimension từ dữ liệu sạch rồi nạp dimension trước, fact sau (PostgreSQL COPY)."""
import io
import ipaddress
from bisect import bisect_right
from pathlib import Path

import pandas as pd

from src.etl.transform import make_time_key

SERVICES = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 123: "NTP", 135: "RPC", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
    587: "SMTP", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}
PROTOCOLS = {0: "HOPOPT", 1: "ICMP", 6: "TCP", 17: "UDP"}

FACT_COLS = ["time_key", "src_ip_key", "dst_ip_key", "protocol_key", "dst_port_key", "label_key",
             "flow_id", "src_port", "flow_start_ts", "flow_duration_us", "total_fwd_packets", "total_bwd_packets",
             "total_fwd_bytes", "total_bwd_bytes", "total_packets", "total_bytes", "flow_bytes_per_s",
             "flow_packets_per_s", "avg_packet_size", "syn_flag_count", "ack_flag_count", "fin_flag_count",
             "rst_flag_count", "psh_flag_count"]
DIM_SCAN_COLS = ["src_ip", "dst_ip", "dst_port", "protocol_number", "label_raw", "attack_group", "is_attack",
                 "flow_start_ts"]


# ---------------------------------------------------------------- blacklist
def _parse_netset(path):
    """Đọc file .netset/.ipset (mỗi dòng 1 IP hoặc CIDR, '#' là chú thích) -> danh sách khoảng IPv4 đã gộp."""
    ivs = []
    for line in Path(path).read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        if net.version == 4:
            ivs.append((int(net.network_address), int(net.broadcast_address)))
    ivs.sort()
    merged = []
    for a, b in ivs:
        if merged and a <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    return [m[0] for m in merged], [m[1] for m in merged]


def load_blacklists(blacklist_dir, logger):
    lists = {}
    d = Path(blacklist_dir)
    for p in sorted(list(d.glob("*.netset")) + list(d.glob("*.ipset"))) if d.exists() else []:
        starts, ends = _parse_netset(p)
        lists[p.stem] = (starts, ends)
        logger.info("Blacklist %s: %d khoảng IPv4", p.stem, len(starts))
    if not lists:
        logger.warning("Không có file blacklist trong '%s' -> is_blacklisted = FALSE cho mọi IP.", blacklist_dir)
    return lists


def _in_list(ip_int, starts, ends):
    i = bisect_right(starts, ip_int) - 1
    return i >= 0 and ip_int <= ends[i]


# ---------------------------------------------------------------- dựng dimension
def build_dim_time(ts, tcfg):
    minutes = pd.Series(pd.unique(ts.dt.floor("min"))).sort_values().reset_index(drop=True)
    t = pd.DataFrame({"full_datetime": minutes})
    t["time_key"] = make_time_key(t["full_datetime"])
    t["date_value"] = t["full_datetime"].dt.date
    t["year_num"], t["month_num"], t["day_num"] = (t["full_datetime"].dt.year, t["full_datetime"].dt.month,
                                                   t["full_datetime"].dt.day)
    t["day_name"] = t["full_datetime"].dt.day_name()
    t["hour_num"], t["minute_num"] = t["full_datetime"].dt.hour, t["full_datetime"].dt.minute
    h = t["hour_num"]
    t["time_period"] = pd.Series("Dem", index=t.index).mask(h.between(5, 11), "Sang") \
        .mask(h.between(12, 17), "Chieu").mask(h.between(18, 21), "Toi")
    t["is_business_hours"] = (t["full_datetime"].dt.dayofweek < 5) & h.between(tcfg["business_start"], tcfg["business_end"])
    return t


def build_dim_ip(ips, blacklists):
    d = pd.DataFrame({"ip_address": sorted(ips)})
    d["ip_key"] = range(1, len(d) + 1)
    objs = d["ip_address"].map(ipaddress.ip_address)
    d["is_internal"] = objs.map(lambda o: o.is_private)

    def segment(o):
        prefix = 24 if o.version == 4 else 64
        return str(ipaddress.ip_network(f"{o}/{prefix}", strict=False))
    d["network_segment"] = objs.map(segment)

    # CHỈ kiểm tra IP công cộng: blacklist FireHOL level1 chứa cả dải 10/8, 172.16/12, 192.168/16 (fullbogons),
    # nếu không loại trừ thì mọi IP nội bộ (kể cả 172.16.0.1) sẽ bị đánh dấu blacklist sai.
    bl, src = [], []
    for o in objs:
        hits = []
        if o.version == 4 and o.is_global:
            hits = [name for name, (s, e) in blacklists.items() if _in_list(int(o), s, e)]
        bl.append(bool(hits))
        src.append(",".join(hits) if hits else None)
    d["is_blacklisted"], d["blacklist_source"] = bl, src
    return d


def build_dim_port(ports):
    d = pd.DataFrame({"port_number": sorted(ports)})
    d["port_key"] = range(1, len(d) + 1)
    d["service_name"] = d["port_number"].map(lambda p: SERVICES.get(int(p), "Other"))
    d["port_range"] = d["port_number"].map(
        lambda p: "Well-known" if p < 1024 else "Registered" if p < 49152 else "Dynamic")
    return d


def build_dim_protocol(protos):
    d = pd.DataFrame({"protocol_number": sorted(protos)})
    d["protocol_key"] = d["protocol_number"]
    d["protocol_name"] = d["protocol_number"].map(lambda p: PROTOCOLS.get(int(p), f"PROTO_{int(p)}"))
    return d


def build_dim_label(df_labels):
    d = df_labels.drop_duplicates("label_raw").sort_values("label_raw").reset_index(drop=True)
    d["label_key"] = range(1, len(d) + 1)
    return d[["label_key", "label_raw", "attack_group", "is_attack"]]


# ---------------------------------------------------------------- COPY
def copy_df(cur, table, df, cols):
    buf = io.StringIO()
    df[cols].to_csv(buf, index=False, header=False, na_rep="\\N")
    buf.seek(0)
    cur.copy_expert(f"COPY {table} ({','.join(cols)}) FROM STDIN WITH (FORMAT csv, NULL '\\N')", buf)


def load_warehouse(conn, cfg, logger):
    clean_files = sorted(Path(cfg["paths"]["clean_dir"]).glob("*.parquet"))
    if not clean_files:
        raise FileNotFoundError(f"Chưa có file Parquet trong {cfg['paths']['clean_dir']}; hãy chạy bước transform trước.")

    # 1. Quét các cột cần thiết để dựng dimension
    logger.info("Quét %d file sạch để dựng dimension...", len(clean_files))
    scan = pd.concat([pd.read_parquet(f, columns=DIM_SCAN_COLS) for f in clean_files], ignore_index=True)
    blacklists = load_blacklists(cfg["paths"]["blacklist_dir"], logger)

    dim_time = build_dim_time(scan["flow_start_ts"], cfg["time"])
    dim_ip = build_dim_ip(set(scan["src_ip"]) | set(scan["dst_ip"]), blacklists)
    dim_port = build_dim_port(set(scan["dst_port"]))
    dim_protocol = build_dim_protocol(set(scan["protocol_number"]))
    dim_label = build_dim_label(scan[["label_raw", "attack_group", "is_attack"]])
    del scan

    ip_map = dim_ip.set_index("ip_address")["ip_key"]
    port_map = dim_port.set_index("port_number")["port_key"]
    label_map = dim_label.set_index("label_raw")["label_key"]

    with conn, conn.cursor() as cur:  # 1 transaction: lỗi thì rollback toàn bộ
        if cfg["database"]["truncate_before_load"]:
            cur.execute("TRUNCATE fact_flow, dim_time, dim_ip, dim_protocol, dim_port, dim_label RESTART IDENTITY CASCADE")

        # 2. Nạp dimension TRƯỚC
        copy_df(cur, "dim_time", dim_time, ["time_key", "full_datetime", "date_value", "year_num", "month_num",
                                            "day_num", "day_name", "hour_num", "minute_num", "time_period",
                                            "is_business_hours"])
        copy_df(cur, "dim_ip", dim_ip, ["ip_key", "ip_address", "is_internal", "network_segment",
                                        "is_blacklisted", "blacklist_source"])
        copy_df(cur, "dim_protocol", dim_protocol, ["protocol_key", "protocol_number", "protocol_name"])
        copy_df(cur, "dim_port", dim_port, ["port_key", "port_number", "service_name", "port_range"])
        copy_df(cur, "dim_label", dim_label, ["label_key", "label_raw", "attack_group", "is_attack"])
        for tbl, col in [("dim_ip", "ip_key"), ("dim_port", "port_key"), ("dim_label", "label_key")]:
            cur.execute(f"SELECT setval(pg_get_serial_sequence('{tbl}','{col}'), (SELECT MAX({col}) FROM {tbl}))")
        logger.info("Đã nạp dimension: time=%d, ip=%d, protocol=%d, port=%d, label=%d",
                    len(dim_time), len(dim_ip), len(dim_protocol), len(dim_port), len(dim_label))

        # 3. Nạp fact SAU, tra khóa thay thế
        chunk = cfg["database"]["copy_chunk_rows"]
        total = 0
        for f in clean_files:
            df = pd.read_parquet(f)
            df["time_key"] = make_time_key(df["flow_start_ts"])
            df["src_ip_key"] = df["src_ip"].map(ip_map)
            df["dst_ip_key"] = df["dst_ip"].map(ip_map)
            df["dst_port_key"] = df["dst_port"].map(port_map)
            df["protocol_key"] = df["protocol_number"]
            df["label_key"] = df["label_raw"].map(label_map)
            key_cols = ["src_ip_key", "dst_ip_key", "dst_port_key", "label_key"]
            if df[key_cols].isna().any().any():
                raise ValueError(f"{f.name}: có khóa dimension bị thiếu, kiểm tra lại bước dựng dimension.")
            for i in range(0, len(df), chunk):
                copy_df(cur, "fact_flow", df.iloc[i:i + chunk], FACT_COLS)
            total += len(df)
            logger.info("Đã nạp fact từ %s: %d dòng", f.name, len(df))

        cur.execute("ANALYZE")

    return {"fact_rows_loaded": total}


def reconcile(conn, expected_rows, logger):
    """Kiểm tra sau nạp: số dòng fact phải khớp số dòng sạch; không có khóa mồ côi."""
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM fact_flow")
        n = cur.fetchone()[0]
        cur.execute("""SELECT COUNT(*) FROM fact_flow f
                       LEFT JOIN dim_time t ON t.time_key = f.time_key WHERE t.time_key IS NULL""")
        orphan_time = cur.fetchone()[0]
    ok = (n == expected_rows) and orphan_time == 0
    (logger.info if ok else logger.error)("Đối soát: fact_flow=%d | dòng sạch=%d | khóa thời gian mồ côi=%d -> %s",
                                          n, expected_rows, orphan_time, "KHỚP" if ok else "LỆCH")
    return ok