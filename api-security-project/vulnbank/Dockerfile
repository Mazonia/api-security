FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8002
# Gunicorn for a slightly more realistic server; single worker keeps the in-memory
# state consistent for the lab. debug behaviour is driven by the app, not the server.
CMD ["gunicorn", "--bind", "0.0.0.0:8002", "--workers", "1", "app:app"]
