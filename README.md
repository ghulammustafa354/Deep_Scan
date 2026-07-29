# 🛡️ Deep_Scan: Hybrid Real-Time Phishing URL & Email Detection System

[![Python Version](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.13-blue.svg)](https://www.python.org/)
[![Flask API](https://img.shields.io/badge/backend-Flask%20REST%20API-green.svg)](https://flask.palletsprojects.com/)
[![Machine Learning](https://img.shields.io/badge/ML-Random%20Forest%20%7C%20Scikit--Learn-orange.svg)](https://scikit-learn.org/)
[![Deep Learning NLP](https://img.shields.io/badge/NLP-DistilBERT%20%7C%20Transformers-red.svg)](https://huggingface.co/docs/transformers/)
[![Chrome Extension](https://img.shields.io/badge/extension-Manifest%20V3-yellow.svg)](https://developer.chrome.com/docs/extensions/)

`Deep_Scan` is an enterprise-grade, hybrid real-time phishing detection system designed to combat zero-day phishing attacks across both **web URLs** and **email communications**. It combines machine learning feature extraction, deep learning NLP transformers, DNS-over-HTTPS (DoH) cryptographic verification, and an automated Chrome extension for client-side protection.

---

## 🚀 Key System Features

### 1. 🌐 Hybrid URL Detection Engine (`backend/predict.py`)
- **50 Total Extracted Features**: Analyzes 22 structural URL features (length, digit ratio, special character density, obfuscation ratio, TLD probability) and 28 live web content HTML features (iFrames, form actions, hidden password fields, brand keyword matches).
- **Dual-Model Fallback**:
  - **Full Model (50 Features)**: Evaluates live web content using Random Forest (`accuracy: 95.2%`).
  - **URL-Only Fallback Model (22 Features)**: Automatically triggers in **<180ms** if a target website is offline or blocks scraping (`accuracy: 92.4%`).
- **Brand Protection & Typosquatting Detection**: Uses edit-distance algorithms and official domain maps to catch brand spoofing attempts (e.g., `paypal-update.tk`).
- **OpenDNS Top 10,000 Filtering**: Hashes and caches legitimate global domains for instant **<2ms** whitelisting.

### 2. 📧 Multi-Tiered Email Detection Engine (`email_analysis/`)
- **Tier-1 Deep Learning Transformer**: Powered by HuggingFace **DistilBERT** (`cybersectony/phishing-email-detection-distilbert_v2.1`) to evaluate semantic context, deceptive tone, and urgency (`accuracy: 94.8%`).
- **Tier-2 TF-IDF ML Fallback**: Lightweight TF-IDF + Logistic Regression fallback model for low-resource execution environments.
- **Cryptographic DNS-over-HTTPS (DoH) Verification (`dns_verifier.py`)**:
  - Queries `MX`, `SPF` (`v=spf1`), and `DMARC` (`v=dmarc1`) policies via Cloudflare DoH (`https://cloudflare-dns.com/dns-query`) and Google DoH JSON APIs.
  - Detects email sender domain spoofing and domain unreachability.
- **Heuristic Overrides**: Prevents false positive alerts for emails originating from verified platforms without suspicious links or urgency.

### 3. 🔒 SSL/TLS Certificate Validator (`/check_certificate`)
- Establishes a raw TLS connection via `ssl` and `socket` on port 443.
- Inspects certificate expiration (`notAfter`), calculates remaining days, and extracts subject/issuer identity to flag self-signed or untrusted certificates.

### 4. 🧩 Real-Time Chrome Extension (`chrome_extension/`)
- Built on **Manifest V3**.
- Listens to active tab navigation events (`chrome.tabs.onUpdated`) and runs background URL checks against the Flask API.
- Updates extension badges dynamically (**`SAFE`** / **`RISK`**) and triggers OS notifications on high-risk detections.

### 5. 💻 Cyberpunk Web Dashboard (`frontend/cyber_interface.html`)
- Interactive, responsive web interface for single URL scanning, batch URL processing, email verification, certificate inspection, and live threat logs.

---

## 📊 Model Performance & Benchmarks

All models were trained and validated on the **PhiUSIIL Phishing URL Dataset** (235,000+ URLs) and the **CEAS Email Dataset**.

| Model Pipeline | Target Analyzed | Features / Input | Accuracy | Precision | Recall | F1-Score | Inference Time |
|---|---|---|---|---|---|---|---|
| **Random Forest (Full Model)** | Web URLs & HTML DOM | 50 Features (22 URL + 28 Web) | **95.2%** | **95.8%** | **94.5%** | **95.1%** | ~1.2s (Scraped) |
| **Random Forest (URL Fallback)** | URL String Only | 22 Structural Features | **92.4%** | **92.1%** | **92.6%** | **92.3%** | **<180ms** |
| **DistilBERT Transformer** | Email Subject & Body | Deep Contextual NLP Tokens | **94.8%** | **95.1%** | **94.3%** | **94.7%** | ~350ms |

---

## 🏗️ System Architecture & Data Flow

```
+-----------------------------------------------------------------------------------+
|                                 CLIENT LAYER                                      |
|   +-----------------------+                         +-------------------------+   |
|   |  Chrome Extension     |                         |  Web Frontend Dashboard |   |
|   | (background.js/popup) |                         |  (index.html/script.js) |   |
|   +-----------+-----------+                         +------------+------------+   |
+---------------+--------------------------------------------------+----------------+
                |                                                  |
                +------------------------+-------------------------+
                                         | HTTP POST (JSON)
                                         v
+-----------------------------------------------------------------------------------+
|                                 BACKEND LAYER                                     |
|                         Flask REST API (backend/app.py)                           |
+----------------------------------------+------------------------------------------+
                                         |
               +-------------------------+-------------------------+
               | /predict                                          | /predict/email
               v                                                   v
+----------------------------------------+   +--------------------------------------+
|        HYBRID URL ENGINE               |   |        MULTI-TIER EMAIL ENGINE       |
|       (backend/predict.py)             |   |   (email_analysis/email_detector.py) |
|                                        |   |                                      |
| 1. Brand Impersonation Rules           |   | 1. Whitelist & Reputation DB Check   |
| 2. OpenDNS Top 10k Check               |   | 2. Cryptographic DNS/MX/SPF/DMARC    |
| 3. Live Web Scraping (requests + BS4)  |   | 3. Tier-1: DistilBERT Transformer    |
| 4. Random Forest Model (Full / URL)    |   | 4. Tier-2: TF-IDF ML Model           |
| 5. SSL/TLS Certificate Validator       |   | 5. Heuristic Safety Overrides        |
+----------------------------------------+   +--------------------------------------+
```

---

## 📁 Project Directory Structure

```
Deep_Scan/
├── backend/
│   ├── app.py                  # Main Flask REST API server & endpoints
│   ├── predict.py              # 3-Phase Hybrid URL Prediction Engine
│   ├── whois_helper.py          # Domain registration & WHOIS analysis helper
│   ├── requirements.txt        # Python backend dependencies
│   └── scans_db.json           # Persistent scan threat log storage
├── email_analysis/
│   ├── email_detector.py       # Multi-tiered DistilBERT & TF-IDF Email Detector
│   ├── dns_verifier.py         # Cloudflare & Google DoH MX/SPF/DMARC verifier
│   └── requirements.txt
├── frontend/
│   ├── cyber_interface.html    # Modern Cyberpunk dashboard UI
│   ├── index.html              # Standard web interface
│   ├── script.js               # Frontend API integration & DOM controller
│   └── style.css               # Design system styling & CSS tokens
├── chrome_extension/
│   ├── manifest.json           # Extension Manifest V3 configuration
│   ├── background.js           # Real-time background service worker
│   ├── popup.html / popup.js   # Extension popup interface & controller
│   └── content.js              # Active tab DOM content scanner
├── models/
│   ├── train_model.py          # Random Forest URL model training pipeline
│   ├── train_email_model.py    # Email TF-IDF training pipeline
│   ├── top_domains.txt         # OpenDNS Top 10,000 domain cache
│   └── saved_models/           # Pre-trained .pkl and .bin model binaries
├── EVALUATION_CONCEPTUAL_GUIDE.md # Conceptual & viva defense guide
├── EVALUATION_CODE_LOGIC_GUIDE.md  # Detailed code walkthrough & line-by-line guide
└── README.md
```

---

## ⚙️ Quick Start & Setup Guide

### 1. Prerequisites
- Python 3.9+ (Python 3.10 - 3.13 supported)
- Google Chrome or Chromium-based browser

### 2. Installation & Running the Backend
```bash
# 1. Clone the repository
git clone https://github.com/MirBalach/Deep-Scan.git
cd Deep-Scan

# 2. Install dependencies
pip install -r backend/requirements.txt

# 3. Start the Flask REST API server
python backend/app.py
```
The server will start at `http://localhost:5000`.

### 3. Running the Web Interface
Simply open `frontend/cyber_interface.html` or `frontend/index.html` in your web browser.

### 4. Installing the Chrome Extension
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** (toggle switch in the top right corner).
3. Click **Load unpacked**.
4. Select the `chrome_extension/` directory from this project.

---

## 📡 API Endpoint Reference

### 1. URL Analysis (`POST /predict`)
```json
// Request: POST http://localhost:5000/predict
{
  "url": "https://example.com"
}

// Response (200 OK):
{
  "url": "https://example.com",
  "prediction": "Legitimate",
  "confidence": 0.98,
  "risk_level": "Very Low",
  "probabilities": {
    "phishing": 0.02,
    "legitimate": 0.98
  },
  "features_extracted": 50,
  "method": "full_model"
}
```

### 2. Email Analysis (`POST /predict/email`)
```json
// Request: POST http://localhost:5000/predict/email
{
  "sender": "security@fake-bank.com",
  "subject": "Urgent: Account Suspended",
  "content": "Please click here immediately to verify your credentials."
}

// Response (200 OK):
{
  "prediction": "Phishing",
  "confidence": 0.99,
  "risk_level": "High",
  "method": "distilbert",
  "dns_verification": {
    "has_mx": false,
    "has_spf": false,
    "has_dmarc": false,
    "is_authentic": false
  }
}
```

### 3. SSL Certificate Inspection (`POST /check_certificate`)
```json
// Request: POST http://localhost:5000/check_certificate
{
  "url": "https://google.com"
}

// Response (200 OK):
{
  "has_certificate": true,
  "is_valid": true,
  "status": "Valid",
  "expires": "2026-09-15",
  "days_remaining": 56,
  "issued_to": "www.google.com",
  "issued_by": "GTS CA 1C3"
}
```

---

## 📜 License & Credits

Distributed under the MIT License. Developed for Academic Final Year Project (FYP) Evaluation & Defense.