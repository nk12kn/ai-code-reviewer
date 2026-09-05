# Lightweight Python 3.12 container for cloud deployment
FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose web service port
EXPOSE 8000

# Start FastAPI application with dynamic cloud port binding
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT}"]
