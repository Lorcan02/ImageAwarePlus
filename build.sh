#!/usr/bin/env bash
# Render build script — installs system dependencies then Python packages

set -e  # Exit on any error

echo "=== Installing system dependencies ==="
apt-get update -qq
apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-eng \
    libzbar0 \
    libgl1 \
    libglib2.0-0

echo "=== Tesseract version ==="
tesseract --version

echo "=== Installing Python dependencies ==="
pip install -r requirements.txt

echo "=== Build complete ==="
