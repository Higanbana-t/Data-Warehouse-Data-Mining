#!/bin/bash
# Chạy tự động bởi image MySQL ở lần khởi tạo đầu tiên (thư mục /docker-entrypoint-initdb.d).
# Tạo 2 tài khoản theo nguyên tắc quyền tối thiểu. Mật khẩu lấy từ biến môi trường của dịch vụ `mysql`.
# (Không dùng `set -e` vì file này có thể được "source" bởi entrypoint nếu không có quyền thực thi.)

mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" <<SQL || exit 1
CREATE USER IF NOT EXISTS '${DEBEZIUM_USER:-debezium}'@'%' IDENTIFIED BY '${DEBEZIUM_PASSWORD}';
-- Quyền Debezium MySQL connector cần để chụp snapshot và đọc binlog
GRANT SELECT, RELOAD, SHOW DATABASES, REPLICATION SLAVE, REPLICATION CLIENT ON *.* TO '${DEBEZIUM_USER:-debezium}'@'%';

CREATE USER IF NOT EXISTS 'simulator'@'%' IDENTIFIED BY '${SIMULATOR_PASSWORD}';
-- Simulator chỉ được ghi thêm dòng (INSERT) và đọc, không sửa/xóa
GRANT INSERT, SELECT ON firewall.* TO 'simulator'@'%';

FLUSH PRIVILEGES;
SQL
