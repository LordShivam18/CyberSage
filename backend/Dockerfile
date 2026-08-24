FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV API_BIND_HOST=127.0.0.1
ENV API_PORT=8000

COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

COPY backend /app/backend
COPY shared /app/shared
COPY guardian /app/guardian
COPY README.md /app/README.md
COPY VERSION /app/VERSION

RUN python -c "from shared.report_contract import verify_checksum"

CMD ["sh", "-c", "exec uvicorn backend.main:app --host \"$API_BIND_HOST\" --port \"$API_PORT\""]
