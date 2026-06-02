FROM python:3.11-slim
WORKDIR /app

# System deps for Playwright's Chromium
RUN apt-get update && apt-get install -y --no-install-recommends \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
    libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 \
    libgbm1 libasound2 libpango-1.0-0 libcairo2 libatspi2.0-0 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Install Chromium browser for Playwright (headless capture feature)
RUN playwright install chromium

COPY . .
RUN mkdir -p /data
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "9000"]
