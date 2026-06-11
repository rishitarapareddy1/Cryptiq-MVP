# Cryptiq PQC Scanner

A post-quantum cryptography readiness scanner.

## Setup
pip install -r requirements.txt

## Run the scanner
python scan_tls.py google.com
python scan_tls.py domains.csv

## Run the API
python -m uvicorn api:app --reload

## API endpoints
POST /scan — scan a single domain
POST /scan/bulk — scan multiple domains
GET /health — health check