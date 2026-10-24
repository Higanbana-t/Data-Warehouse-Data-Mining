import logging
import sys

def get_logger(name="etl"):
    """Tạo bộ ghi log chuẩn ra màn hình Terminal."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        # Định dạng dòng log: [Thời gian] [Mức độ] Tin nhắn
        fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        
        # In log ra màn hình console
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(fmt)
        logger.addHandler(sh)
        
    return logger