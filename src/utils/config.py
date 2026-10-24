import os
import yaml
import psycopg2
from dotenv import load_dotenv

def load_config(config_path="config.yaml"):
    """Đọc file cấu hình YAML."""
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def get_connection():
    """Tạo kết nối đến PostgreSQL dựa trên biến môi trường (.env)."""
    load_dotenv()  # Tự động nạp các biến từ file .env vào os.environ
    
    return psycopg2.connect(
        host=os.environ.get("PGHOST", "localhost"),
        port=os.environ.get("PGPORT", "5432"),
        dbname=os.environ.get("PGDATABASE", "cicids2017_dw"),
        user=os.environ.get("PGUSER", "postgres"),
        password=os.environ.get("PGPASSWORD", "123456")
    )