FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

COPY backend /app/backend
COPY shared /app/shared
COPY README.md /app/README.md

RUN python -c "from shared.report_contract import verify_checksum"

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
