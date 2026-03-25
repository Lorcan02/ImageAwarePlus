FROM python:3.11-slim

# Install system dependencies including Tesseract and ZBar
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-eng \
    libzbar0 \
    libgl1 \
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libxrender-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy and install Python dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create required runtime directories
RUN mkdir -p uploads outputs

# Expose port
EXPOSE 10000

# Start gunicorn
CMD gunicorn web.app:app --bind 0.0.0.0:${PORT:-10000} --workers 1 --timeout 120
