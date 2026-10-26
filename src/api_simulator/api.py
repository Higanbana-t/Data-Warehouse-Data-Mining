"""
Firewall API: đóng vai "hệ thống bên ngoài" phục vụ dữ liệu CICIDS2017 (năm 2017) qua HTTP.

Chạy (trong Docker hoặc trên máy):
    API_KEY=<khóa> REPLAY_DIR=data/replay REPLAY_RATE=200 \
        uvicorn --factory src.api_simulator.api:create_app_from_env --port 8000
Tài liệu tương tác (OpenAPI): http://localhost:8000/docs

Điểm cuối:
    GET /health                               kiểm tra sống (không cần khóa)
    GET /v1/logs?after=<seq>&limit=<n>        lấy các bản ghi mới sau con trỏ `seq` (cần header X-API-Key)
    GET /v1/stats                             tiến độ phát lại (cần khóa)

Nhịp phát: API giữ một "đồng hồ phát lại" bắt đầu chạy từ LẦN GỌI /v1/logs ĐẦU TIÊN. Chỉ những bản ghi đã "đến lúc"
(theo REPLAY_RATE dòng/giây) mới được trả về, nên Collector gọi nhanh hay chậm thì dòng dữ liệu vẫn chảy đúng tốc độ.
REPLAY_RATE=0 nghĩa là phát hết ngay (dùng khi kiểm thử).
"""
import os
import secrets
import threading
import time
from collections import deque

from fastapi import Depends, FastAPI, HTTPException, Query, Response
from fastapi.security import APIKeyHeader

from src.api_simulator import reader

MAX_LIMIT = 2000


class ReplayStore:
    """Giữ toàn bộ tập phát lại trong bộ nhớ và tính số bản ghi đã "đến lúc" theo thời gian."""

    def __init__(self, df, rate, clock=time.monotonic):
        self.df, self.rate, self.clock = df, float(rate), clock
        self.total = len(df)
        self._t0 = None
        self._lock = threading.Lock()

    def released(self, start=False):
        """start=True: lần gọi đầu tiên sẽ khởi động đồng hồ phát lại."""
        if self.rate <= 0:
            return self.total
        with self._lock:
            if self._t0 is None:
                if not start:
                    return 0
                self._t0 = self.clock()
            return min(self.total, int((self.clock() - self._t0) * self.rate))

    @property
    def started(self):
        return self.rate <= 0 or self._t0 is not None

    def fetch(self, after, limit):
        """Các bản ghi có seq trong (after, min(after+limit, released)]. seq bắt đầu từ 1."""
        rel = self.released(start=True)
        hi = min(after + limit, rel)
        if hi <= after:
            return [], rel
        records = reader.to_records(self.df.iloc[after:hi])
        return [{"seq": after + 1 + i, **r} for i, r in enumerate(records)], rel


class RequestLimiter:
    """Giới hạn số lần gọi mỗi giây (cửa sổ trượt 1 giây)."""

    def __init__(self, max_per_second, clock=time.monotonic):
        self.max, self.clock, self.hits, self._lock = max_per_second, clock, deque(), threading.Lock()

    def allow(self):
        if self.max <= 0:
            return True
        with self._lock:
            now = self.clock()
            while self.hits and now - self.hits[0] >= 1.0:
                self.hits.popleft()
            if len(self.hits) >= self.max:
                return False
            self.hits.append(now)
            return True


def create_app(store, api_key, max_rps=50):
    if not api_key:
        raise ValueError("API_KEY không được để trống.")
    app = FastAPI(title="Firewall API (mô phỏng)", version="1.0",
                  description="Phục vụ dữ liệu luồng mạng CICIDS2017 (2017) theo con trỏ `seq`, đóng vai hệ thống bên ngoài.")
    key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
    limiter = RequestLimiter(max_rps)

    def guard(response: Response, key: str = Depends(key_header)):
        if not key or not secrets.compare_digest(key, api_key):
            raise HTTPException(401, "Thiếu hoặc sai khóa API (header X-API-Key).", headers={"WWW-Authenticate": "ApiKey"})
        if not limiter.allow():
            raise HTTPException(429, "Gọi quá dày, hãy thử lại sau.", headers={"Retry-After": "1"})

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/v1/stats", dependencies=[Depends(guard)])
    def stats():
        return {"total": store.total, "released": store.released(), "rate_per_second": store.rate,
                "replay_started": store.started}

    @app.get("/v1/logs", dependencies=[Depends(guard)])
    def logs(after: int = Query(0, ge=0, description="seq cuối cùng đã nhận (0 = từ đầu)"),
             limit: int = Query(500, ge=1, le=MAX_LIMIT)):
        records, rel = store.fetch(after, limit)
        last = records[-1]["seq"] if records else after
        return {"after": after, "count": len(records), "next_after": last, "released": rel, "total": store.total,
                "end": last >= store.total, "records": records}

    return app


def create_app_from_env():
    column_map = reader.load_column_map()
    df = reader.load_replay_frame(os.getenv("REPLAY_DIR", "/data"), column_map,
                                  max_rows=int(os.getenv("REPLAY_MAX_ROWS", "0")) or None)
    store = ReplayStore(df, rate=float(os.getenv("REPLAY_RATE", "200")))
    return create_app(store, api_key=os.environ["API_KEY"], max_rps=int(os.getenv("MAX_REQUESTS_PER_SECOND", "50")))
