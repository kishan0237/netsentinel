FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY pytest.ini ./

EXPOSE 8000

# PORT is provided by the platform (Render/Docker); default 8000 locally
CMD ["sh", "-c", "uvicorn app.backend.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
