"""
FastAPI Backend: API Cảnh báo An ninh Mạng & Thống kê DW/Streaming.
"""
import os
import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from src.api_service.db import execute_query, execute_single

app = FastAPI(
    title="Network Anomaly Detection & Security DW API",
    description="Backend API phục vụ giám sát luồng traffic mạng, phát hiện tấn công theo thời gian thực và phân tích OLAP.",
    version="1.0.0"
)

# Kích hoạt CORS cho phép truy cập từ dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DASHBOARD_DIR = Path(__file__).resolve().parent.parent.parent / "dashboard"


# -----------------------------------------------------------------------------
# 1. GET /health
# -----------------------------------------------------------------------------
@app.get("/health", tags=["System"])
def health_check():
    """Kiểm tra trạng thái kết nối Database và tình trạng vận hành hệ thống."""
    try:
        res = execute_single("SELECT 1 AS healthy, current_database() AS db, version() AS version;")
        return {
            "status": "healthy",
            "service": "network-anomaly-dw-api",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "database": {
                "status": "connected",
                "name": res["db"],
                "engine": res["version"].split(",")[0]
            }
        }
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail={
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }
        )


# -----------------------------------------------------------------------------
# 2. GET /stats/overview
# -----------------------------------------------------------------------------
@app.get("/stats/overview", tags=["Metrics"])
def get_overview_stats():
    """
    Tổng quan các chỉ số KPI:
    - Tổng số luồng mạng (fact_flow)
    - Tổng số cảnh báo AI (network_alerts)
    - Tỉ lệ luồng tấn công (%)
    - Thông số độ trễ xử lý streaming (P50, P95 ms) từ etl_batch_log
    """
    try:
        # Đếm tổng flow và alert
        flow_row = execute_single("SELECT COUNT(*) AS total_flows FROM fact_flow;")
        alert_row = execute_single("SELECT COUNT(*) AS total_alerts FROM network_alerts;")
        
        total_flows = flow_row["total_flows"] if flow_row else 0
        total_alerts = alert_row["total_alerts"] if alert_row else 0
        
        attack_ratio = round((total_alerts / total_flows * 100), 2) if total_flows > 0 else 0.0

        # Lấy độ trễ trung bình của 50 micro-batch gần nhất
        latency_row = execute_single("""
            SELECT 
                COUNT(*) AS total_batches,
                COALESCE(AVG(latency_p50_ms), 0) AS avg_p50,
                COALESCE(AVG(latency_p95_ms), 0) AS avg_p95,
                COALESCE(MAX(latency_p95_ms), 0) AS max_p95,
                COALESCE(SUM(rows_loaded), 0) AS total_rows_loaded,
                COALESCE(SUM(rows_in), 0) AS total_rows_in
            FROM (
                SELECT latency_p50_ms, latency_p95_ms, rows_loaded, rows_in
                FROM etl_batch_log
                ORDER BY batch_id DESC
                LIMIT 50
            ) b;
        """)

        return {
            "total_flows": total_flows,
            "total_alerts": total_alerts,
            "attack_ratio_pct": attack_ratio,
            "streaming": {
                "latency_p50_ms": round(float(latency_row["avg_p50"]), 1),
                "latency_p95_ms": round(float(latency_row["avg_p95"]), 1),
                "latency_max_p95_ms": int(latency_row["max_p95"]),
                "recent_batches_evaluated": latency_row["total_batches"],
                "total_rows_loaded": int(latency_row["total_rows_loaded"])
            },
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi truy vấn thống kê: {str(e)}")


# -----------------------------------------------------------------------------
# 3. GET /alerts/recent
# -----------------------------------------------------------------------------
@app.get("/alerts/recent", tags=["Alerts"])
def get_recent_alerts(
    limit: int = Query(50, ge=1, le=500, description="Số lượng cảnh báo trả về tối đa"),
    attack_type: Optional[str] = Query(None, description="Lọc theo loại tấn công (DDoS, PortScan, WebAttack, Botnet, v.v.)")
):
    """
    Danh sách các cảnh báo tấn công mới nhất theo thời gian thực.
    Bao gồm IP nguồn, IP đích, Port đích, loại tấn công do AI phân loại và thời gian.
    """
    try:
        sql = """
            SELECT 
                alert_id,
                source_log_id,
                flow_start_ts,
                src_ip,
                dst_ip,
                dst_port,
                attack_type,
                alert_time
            FROM network_alerts
        """
        params = []
        if attack_type and attack_type.strip():
            sql += " WHERE LOWER(attack_type) = LOWER(%s)"
            params.append(attack_type.strip())
            
        sql += " ORDER BY alert_time DESC, alert_id DESC LIMIT %s;"
        params.append(limit)

        rows = execute_query(sql, tuple(params))
        # Format datetimes
        alerts = []
        for r in rows:
            alerts.append({
                "alert_id": r["alert_id"],
                "source_log_id": r["source_log_id"],
                "flow_start_ts": r["flow_start_ts"].isoformat() if r["flow_start_ts"] else None,
                "src_ip": r["src_ip"],
                "dst_ip": r["dst_ip"],
                "dst_port": r["dst_port"],
                "attack_type": r["attack_type"],
                "alert_time": r["alert_time"].isoformat() if r["alert_time"] else None,
            })
            
        return {
            "count": len(alerts),
            "limit": limit,
            "filter_attack_type": attack_type,
            "alerts": alerts
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi lấy danh sách cảnh báo: {str(e)}")


# -----------------------------------------------------------------------------
# 4. GET /analytics/attack-distribution
# -----------------------------------------------------------------------------
@app.get("/analytics/attack-distribution", tags=["Analytics"])
def get_attack_distribution():
    """
    Thống kê số lượng cuộc tấn công gom nhóm theo:
    - attack_type (tổng số lượng và tỷ lệ %)
    - timeline theo giờ/ngày
    """
    try:
        # Gom nhóm theo attack_type
        type_rows = execute_query("""
            SELECT 
                attack_type,
                COUNT(*) AS count
            FROM network_alerts
            GROUP BY attack_type
            ORDER BY count DESC;
        """)

        total_alerts = sum(r["count"] for r in type_rows) if type_rows else 0
        distribution = []
        for r in type_rows:
            pct = round((r["count"] / total_alerts * 100), 2) if total_alerts > 0 else 0.0
            distribution.append({
                "attack_type": r["attack_type"],
                "count": r["count"],
                "percentage": pct
            })

        # Gom nhóm theo thời gian (theo từng giờ dựa trên flow_start_ts)
        timeline_rows = execute_query("""
            SELECT 
                DATE_TRUNC('hour', flow_start_ts) AS time_bucket,
                attack_type,
                COUNT(*) AS count
            FROM network_alerts
            WHERE flow_start_ts IS NOT NULL
            GROUP BY time_bucket, attack_type
            ORDER BY time_bucket ASC, count DESC
            LIMIT 100;
        """)

        timeline = []
        for r in timeline_rows:
            timeline.append({
                "time": r["time_bucket"].isoformat() if r["time_bucket"] else None,
                "attack_type": r["attack_type"],
                "count": r["count"]
            })

        return {
            "total_alerts": total_alerts,
            "distribution": distribution,
            "timeline": timeline
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi phân tích phân bố tấn công: {str(e)}")


# -----------------------------------------------------------------------------
# 5. GET /analytics/top-talkers
# -----------------------------------------------------------------------------
@app.get("/analytics/top-talkers", tags=["Analytics"])
def get_top_talkers(limit: int = Query(10, ge=1, le=50)):
    """
    Top IP nguồn phát tán tấn công nhiều nhất (kèm cờ Blacklist FireHOL từ dim_ip nếu có)
    và Top cổng đích (dst_port) bị nhắm tới.
    """
    try:
        # Top IP nguồn
        ip_rows = execute_query("""
            SELECT 
                a.src_ip,
                COUNT(*) AS attack_count,
                ARRAY_AGG(DISTINCT a.attack_type) AS attack_types,
                COALESCE(dip.is_blacklisted, FALSE) AS is_blacklisted,
                COALESCE(dip.blacklist_source, 'None') AS blacklist_source
            FROM network_alerts a
            LEFT JOIN dim_ip dip ON a.src_ip::inet = dip.ip_address
            GROUP BY a.src_ip, dip.is_blacklisted, dip.blacklist_source
            ORDER BY attack_count DESC
            LIMIT %s;
        """, (limit,))

        top_attackers = []
        for r in ip_rows:
            top_attackers.append({
                "ip": r["src_ip"],
                "attack_count": r["attack_count"],
                "attack_types": r["attack_types"],
                "is_blacklisted": r["is_blacklisted"],
                "blacklist_source": r["blacklist_source"]
            })

        # Top Cổng đích (dst_port)
        port_rows = execute_query("""
            SELECT 
                a.dst_port,
                COUNT(*) AS attack_count,
                COALESCE(dp.service_name, 'Other') AS service_name
            FROM network_alerts a
            LEFT JOIN dim_port dp ON a.dst_port = dp.port_number
            GROUP BY a.dst_port, dp.service_name
            ORDER BY attack_count DESC
            LIMIT %s;
        """, (limit,))

        top_ports = []
        for r in port_rows:
            top_ports.append({
                "port": r["dst_port"],
                "service_name": r["service_name"],
                "attack_count": r["attack_count"]
            })

        return {
            "top_attackers": top_attackers,
            "top_targeted_ports": top_ports
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi lấy danh sách top talkers: {str(e)}")


# -----------------------------------------------------------------------------
# 6. Serving Dashboard Frontend
# -----------------------------------------------------------------------------
if DASHBOARD_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(DASHBOARD_DIR)), name="static")

@app.get("/", include_in_schema=False)
@app.get("/dashboard", include_in_schema=False)
def serve_dashboard():
    index_file = DASHBOARD_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return JSONResponse(
        content={"message": "Dashboard UI is building. Please visit /docs for API documentation."},
        status_code=200
    )
