FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends openssh-client ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 22022 18765 18080

ENV RELAY_DB_PATH=/data/relay.db \
    RELAY_HOST_KEY=/data/relay_host_key \
    RELAY_SSH_PORT=22022 \
    RELAY_WS_PORT=18765 \
    RELAY_HTTP_PORT=18080

CMD ["python", "-m", "app.main"]
