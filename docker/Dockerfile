# Image Python dùng chung cho dịch vụ `init`, và sau này `api-simulator`, `etl-consumer`.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY docker/requirements-stream.txt /tmp/requirements-stream.txt
RUN pip install --default-timeout=100 --retries 10 --prefer-binary -r /tmp/requirements-stream.txt

COPY docker/init /app/docker/init
COPY src /app/src
COPY sql/mysql /app/sql/mysql
COPY config.yaml /app/config.yaml