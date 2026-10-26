"""
Kết nối và truy vấn CSDL PostgreSQL Data Warehouse (network_dw).
"""
import os
from contextlib import contextmanager
import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor

_pool = None

def get_db_pool():
    global _pool
    if _pool is None:
        host = os.getenv("PGHOST", "postgres")
        port = int(os.getenv("PGPORT", "5432"))
        user = os.getenv("PGUSER", os.getenv("POSTGRES_USER", "dw_admin"))
        password = os.getenv("PGPASSWORD", os.getenv("POSTGRES_PASSWORD", "doi_mat_khau_postgres"))
        dbname = os.getenv("PGDATABASE", os.getenv("POSTGRES_DB", "network_dw"))
        
        _pool = pool.ThreadedConnectionPool(
            minconn=1,
            maxconn=10,
            host=host,
            port=port,
            user=user,
            password=password,
            dbname=dbname
        )
    return _pool

@contextmanager
def get_db_cursor(commit=False):
    db_pool = get_db_pool()
    conn = db_pool.getconn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            yield cur
        if commit:
            conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        db_pool.putconn(conn)

def execute_query(sql, params=None):
    with get_db_cursor() as cur:
        cur.execute(sql, params or ())
        return cur.fetchall()

def execute_single(sql, params=None):
    with get_db_cursor() as cur:
        cur.execute(sql, params or ())
        return cur.fetchone()
