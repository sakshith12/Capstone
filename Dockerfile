FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY backend/ .

# Expose port
EXPOSE 8080

# Run with gunicorn
CMD ["gunicorn", "api:app", "--bind", "0.0.0.0:8080", "--workers", "2", "--threads", "2", "--timeout", "300"]
