# ImageAware+ — Phishing Detection & Educational Platform

A hybrid phishing detection system and educational platform built as a Final Year Project at SETU Waterford.

## What it does

ImageAware+ analyses image files and `.eml` email files to detect phishing indicators using a combination of:

- **OCR** (Tesseract) to extract text from phishing images and email screenshots
- **29-indicator rule-based scoring engine** covering credential harvesting, brand impersonation, BEC, sextortion, delivery scams, legal threats, and display name spoofing
- **Threat intelligence integration** with VirusTotal, URLScan.io, and PhishTank
- **Email header analysis** — SPF, DKIM, DMARC, display name spoofing detection
- **QR code detection** and URL extraction from embedded HTML
- **PDF forensic report generation** with full indicator evidence

## Evaluation Results

| Pipeline | Threshold | Precision | Recall | F1 | FPR |
|----------|-----------|-----------|--------|----|-----|
| Email (.eml) | Medium (≥35) | 80.95% | 11.33% | 0.199 | 2.67% |
| Image (.png) | Medium (≥35) | 100% | 58.33% | 0.737 | 0.00% |

Evaluated on 300 labelled samples: 150 phishing emails (Nazario 2025 corpus) and 150 legitimate emails (TREC 2007 ham corpus).

## Tech Stack

- Python 3.11
- Flask
- Tesseract OCR
- OpenCV
- ReportLab
- VirusTotal / URLScan.io / PhishTank APIs

## Local Setup

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/ImageAwarePlus.git
cd ImageAwarePlus

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Mac/Linux

# Install dependencies
pip install -r requirements.txt

# Copy environment variables
cp .env.example .env
# Edit .env and add your API keys

# Run locally
python web/app.py
```

## Environment Variables

Create a `.env` file with the following keys (never commit this file):

```
VT_API_KEY=your_virustotal_api_key
URLSCAN_API_KEY=your_urlscan_api_key
PHISHTANK_API_KEY=your_phishtank_api_key
```

## Project Structure

```
ImageAwarePlus/
├── modules/          # Core detection pipeline
│   ├── scoring.py    # 29-indicator scoring engine
│   ├── email_analysis.py
│   ├── email_parser.py
│   ├── ocr_enhanced.py
│   ├── report.py
│   └── ...
├── web/              # Flask web application
│   ├── app.py
│   └── templates/
├── dataset/          # Evaluation dataset (not committed)
├── requirements.txt
└── render.yaml       # Render deployment config
```

## Author

Lorcan Kelly — Final Year BSc Computer Forensics & Security, SETU Waterford, 2026
