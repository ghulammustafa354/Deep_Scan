# Deep_Scan: Comprehensive Code Logic & Line-by-Line Technical Guide

> **Prepared for Final Year Project (FYP) Evaluation & Defense**  
> **Target Audience:** Technical Evaluators, Examiners, and Code Reviewers  
> **Workspace Path:** `c:\Users\srt\OneDrive\Desktop\balach(Last working)`

---

## Table of Contents
1. [Backend API Architecture (`backend/app.py`)](#1-backend-api-architecture-backendapppy)
2. [Hybrid URL Prediction Engine (`backend/predict.py`)](#2-hybrid-url-prediction-engine-backendpredictpy)
3. [Email Detection & Cryptographic Verification Engine](#3-email-detection--cryptographic-verification-engine)
   - 3.1 [`email_analysis/email_detector.py`](#31-email_analysisemail_detectorpy)
   - 3.2 [`email_analysis/dns_verifier.py`](#32-email_analysisdns_verifierpy)
4. [Chrome Extension Logic (`chrome_extension/`)](#4-chrome-extension-logic-chrome_extension)
5. [Frontend Dashboard Logic (`frontend/script.js`)](#5-frontend-dashboard-logic-frontendscriptjs)
6. [Machine Learning Training Pipeline (`models/train_model.py`)](#6-machine-learning-training-pipeline-modelstrain_modelpy)
7. [Code-Level Viva & Technical Evaluator Questions](#7-code-level-viva--technical-evaluator-questions)

---

## 1. Backend API Architecture (`backend/app.py`)

### File Purpose
`app.py` serves as the central Flask REST API server. It handles HTTP request parsing, input normalization, error handling, CORS headers, logging, and routing requests to the URL and Email detection engines.

### Endpoint Mapping & Logic Walkthrough

| Route | HTTP Method | Handler Function | Exact Purpose & Logic Walkthrough |
|---|---|---|---|
| `/` | GET | `home()` | **Health Check**: Returns JSON status indicating that the API server is online (`{'status': 'active', 'system': 'Deep_Scan API'}`). |
| `/predict` | POST | `predict_url()` | **Single URL Prediction**: <br>1. Receives JSON payload `{'url': '...'}`.<br>2. Validates non-empty input and adds `https://` prefix if missing.<br>3. Normalizes domain format.<br>4. Calls `url_predictor.predict_url(url)`.<br>5. Computes risk level (`Very Low`, `Low`, `Medium`, `High`) based on model confidence score.<br>6. Returns JSON response with prediction, probabilities, feature counts, and method used. |
| `/check_certificate` | POST | `check_certificate()` | **SSL/TLS Certificate Inspection**: <br>1. Extracts hostname from input URL.<br>2. Verifies URL starts with `https://`.<br>3. Establishes a TLS socket connection using `ssl.create_default_context()` and `socket.create_connection((hostname, 443), timeout=5)`.<br>4. Fetches peer certificate `s.getpeercert()`.<br>5. Parses expiration date string (`notAfter`) using `datetime.strptime()`.<br>6. Calculates days remaining (`expire_date - datetime.utcnow()`).<br>7. Extracts Issuer Organization and Subject Common Name.<br>8. Catches `ssl.SSLCertVerificationError` (self-signed/untrusted) and `socket.timeout`. |
| `/batch_predict` | POST | `batch_predict()` | **Batch URL Analysis**: Accepts JSON array `{'urls': ['url1', 'url2', ...]}` (max 100). Iterates through each URL, applies normalization, calls `predict_url()`, and returns an aggregated array of results. |
| `/predict/email` | POST | `predict_email_endpoint()` | **Email Content & Sender Analysis**: Receives `content`, `subject`, and `sender`. Calls `email_detector.predict_email()`. Returns JSON with phishing classification, confidence, risk score, method used, and DNS verification breakdown. |
| `/model_info` | GET | `get_model_info()` | **System Telemetry**: Returns information about loaded models, feature list length (50 features), model type (Random Forest Ensemble), and dataset details. |

### Key Code Snippet: SSL Certificate Verification (`backend/app.py`)
```python
# Create default SSL context with system CA certificates
ctx = ssl.create_default_context()
# Wrap socket with TLS handshake and 5-second timeout
with ctx.wrap_socket(socket.create_connection((hostname, 443), timeout=5), server_hostname=hostname) as s:
    cert = s.getpeercert()  # Retrieve X.509 certificate dictionary

# Parse expiration date string (e.g. 'Dec 31 23:59:59 2026 GMT')
expire_str = cert.get('notAfter', '')
expire_date = datetime.strptime(expire_str, '%b %d %H:%M:%S %Y %Z')
is_expired = expire_date < datetime.utcnow()
days_left = (expire_date - datetime.utcnow()).days

# Extract subject and issuer information
subject = dict(x[0] for x in cert.get('subject', []))
issuer = dict(x[0] for x in cert.get('issuer', []))
```

---

## 2. Hybrid URL Prediction Engine (`backend/predict.py`)

### Classes & Component Architecture
1. **`URLFeatureExtractor`**: Extracts 50 total features from URLs.
   - **22 Structural URL Features**: Computed directly from URL string using regex, URL parsing (`urllib.parse`), entropy analysis, and TLD lookups.
   - **28 HTML Web Content Features**: Extracted by scraping live web pages using `requests.get(url, timeout=2.5)` and parsing HTML DOM with `BeautifulSoup(response.content, 'html.parser')`.
2. **`URLPredictor`**: Manages model loading, whitelists, top domain checks, web scraping, Random Forest model inference, and fallback mechanisms.

### The 3-Phase Hybrid Detection Algorithm
```python
def predict_url(self, url):
    # PHASE 1: Rule-Based & Brand Impersonation Check
    # Check if domain is in OpenDNS Top 10,000 domains (top_domains.txt)
    # Check if URL contains brand string (e.g., "paypal") but domain is NOT official (e.g. paypal-verify.tk)
    if is_brand_impersonation:
        return {'prediction': 'Phishing', 'confidence': 0.99, 'method': 'rule_based'}

    # PHASE 2: Live Web Scraping & 50-Feature Full Model
    try:
        response = requests.get(url, timeout=2.5, headers=headers)
        if response.status_code == 200:
            web_features = extractor.extract_web_features_from_html(url, response)
            # Combine 22 URL features + 28 Web features = 50 features
            X_scaled = self.scaler_full.transform([full_features])
            prob = self.model_full.predict_proba(X_scaled)[0]
            return {'prediction': label, 'confidence': prob, 'method': 'full_model'}
    except Exception as e:
        # Scraping failed or timed out (e.g., site is offline)
        pass

    # PHASE 3: Fallback to 22-Feature URL-Only Model
    url_features = extractor.extract_url_features(url)
    X_scaled = self.scaler_url.transform([url_features])
    prob = self.model_url.predict_proba(X_scaled)[0]
    return {'prediction': label, 'confidence': prob, 'method': 'url_model'}
```

---

## 3. Email Detection & Cryptographic Verification Engine

### 3.1 `email_analysis/email_detector.py`
The email detection engine implements a **multi-tiered classification architecture**:

1. **Tier 1: DistilBERT Transformer Classifier**:
   - Model loaded: `cybersectony/phishing-email-detection-distilbert_v2.1` via HuggingFace `transformers` (`AutoTokenizer`, `AutoModelForSequenceClassification`).
   - Evaluates contextual semantics, deceptive tone, and urgency in email body text.
2. **Tier 2: TF-IDF Machine Learning Fallback**:
   - Model loaded: `models/saved_models/email_phishing_model.pkl` (TF-IDF Vectorizer + Logistic Regression / Naïve Bayes). Used when GPU/RAM constraints prevent loading Transformer models.
3. **Domain Whitelist & Reputation Database**:
   - Loads domain whitelist and compressed reputation database (`models/saved_models/reputation_db.bin`).
4. **Heuristic Safety Overrides**:
   - Prevents false positives. If DistilBERT classifies an email as phishing, but the email contains **no suspicious URLs, no urgency keywords, and comes from a whitelisted sender**, the system overrides the classification to **Legitimate**.

---

### 3.2 `email_analysis/dns_verifier.py`

#### Why DNS-over-HTTPS (DoH)?
Standard socket DNS queries (`dnspython` or native OS sockets) are frequently blocked on corporate networks, university Wi-Fi, or environments restricting UDP port 53. `dns_verifier.py` uses **DNS-over-HTTPS (DoH) JSON APIs** over port 443.

```python
def get_dns_records(domain, record_type='TXT'):
    # Memory cache lookup to prevent redundant DNS API requests
    cache_key = (domain.lower(), record_type)
    if cache_key in _dns_cache:
        return _dns_cache[cache_key]

    # Primary Query: Cloudflare DNS over HTTPS API
    try:
        url = f"https://cloudflare-dns.com/dns-query?name={domain}&type={record_type}"
        headers = {"Accept": "application/dns-json"}
        res = requests.get(url, headers=headers, timeout=2.5)
        if res.status_code == 200:
            records = [ans['data'] for ans in res.json().get('Answer', [])]
            _dns_cache[cache_key] = records
            return records
    except Exception:
        pass

    # Secondary Fallback: Google DNS over HTTPS API
    try:
        url = f"https://dns.google/resolve?name={domain}&type={record_type}"
        res = requests.get(url, timeout=2.5)
        if res.status_code == 200:
            records = [ans['data'] for ans in res.json().get('Answer', [])]
            _dns_cache[cache_key] = records
            return records
    except Exception:
        pass

    return []
```

#### Cryptographic Verification Logic (`verify_sender_domain`):
1. **MX Record Check**: Queries `MX` records. If a domain has no MX records, it cannot receive email replies (a common indicator of spoofing).
2. **SPF Record Check**: Queries `TXT` records looking for string starting with `v=spf1`. Validates authorized sending IP blocks.
3. **DMARC Record Check**: Queries `TXT` records at `_dmarc.domain` looking for `v=dmarc1`. Parses enforcement policy (`p=none`, `p=quarantine`, `p=reject`).

---

## 4. Chrome Extension Logic (`chrome_extension/`)

### File Responsibilities
- **`manifest.json`**: Manifest V3 extension configuration defining permissions (`activeTab`, `tabs`, `storage`, `notifications`) and background service worker script.
- **`background.js`**: Background service worker that listens to navigation events (`chrome.tabs.onUpdated`).
- **`popup.js`**: UI controller for the extension popup window when the user clicks the extension icon.
- **`content.js`**: Content script injected into active web pages to scan links in the DOM.

### Real-Time Tab Monitoring (`background.js`)
```javascript
// Listen to tab URL change events
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
        // Send async POST request to local Flask backend
        fetch('http://localhost:5000/predict', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: tab.url })
        })
        .then(response => response.json())
        .then(data => {
            if (data.prediction === 'Phishing') {
                // Set red badge icon on extension button
                chrome.action.setBadgeText({ text: 'RISK', tabId: tabId });
                chrome.action.setBadgeBackgroundColor({ color: '#FF0000', tabId: tabId });
                
                // Trigger native Windows/Chrome notification
                chrome.notifications.create({
                    type: 'basic',
                    iconUrl: 'icons/icon48.png',
                    title: '⚠️ Phishing Warning!',
                    message: `Deep_Scan flagged this URL as High Risk: ${tab.url}`
                });
            } else {
                // Set green badge icon for safe sites
                chrome.action.setBadgeText({ text: 'SAFE', tabId: tabId });
                chrome.action.setBadgeBackgroundColor({ color: '#00FF00', tabId: tabId });
            }
        });
    }
});
```

---

## 5. Frontend Dashboard Logic (`frontend/script.js`)

### Key Functions
- **`scanURL()`**: Asynchronously posts URL string to `/predict`, toggles loading spinners, parses JSON, and updates DOM elements.
- **`displayResults(data)`**: Animates progress gauge, updates confidence percentage, dynamically applies color badges (`High` -> Red, `Medium` -> Orange, `Low` -> Yellow, `Very Low` -> Green), and renders probability distribution bars.
- **`checkCertificate(url)`**: Invokes `/check_certificate` endpoint and populates modal dialog showing SSL validity, remaining days, common name, and issuer.

---

## 6. Machine Learning Training Pipeline (`models/train_model.py`)

### Training Workflow
1. **Dataset Loading**: Reads `dataset/PhiUSIIL_Phishing_URL_Dataset.csv` using `pandas`.
2. **Feature Extraction Alignment**: Runs `URLFeatureExtractor.extract_url_features()` on raw URLs to ensure exact feature definitions match production inference.
3. **Data Splitting**: Uses `sklearn.model_selection.train_test_split` with 80% training / 20% testing split, stratified by label (`stratify=y`).
4. **Standardization**: Fits `StandardScaler` on training set (`scaler.fit_transform(X_train)`).
5. **Model Initialization & Training**:
   ```python
   rf_params = {
       'n_estimators': 30,       # Number of decision trees in forest
       'max_depth': 8,            # Max tree depth to prevent overfitting
       'min_samples_split': 50,   # Min samples required to split node
       'min_samples_leaf': 20,    # Min samples required in leaf node
       'max_features': 0.7,       # Percentage of features considered per split
       'random_state': 42,
       'n_jobs': -1               # Utilize all CPU cores for parallel training
   }
   self.model_url = RandomForestClassifier(**rf_params)
   self.model_url.fit(X_train_url_scaled, y_train)
   ```
6. **Serialization**: Serializes trained models, scalers, and feature lists into `models/saved_models/` using `joblib.dump()`.

---

## 7. Code-Level Viva & Technical Evaluator Questions

### Q1. In `app.py`, how do you handle CORS issues when the Chrome extension connects to Flask?
**Answer:**  
We import `from flask_cors import CORS` and initialize it with `CORS(app)`. This attaches the `Access-Control-Allow-Origin: *` header to all HTTP responses, allowing cross-origin requests from the Chrome Extension background script (`chrome-extension://...`) and external web dashboards.

---

### Q2. How is the HTML web content scraping timeout handled in `backend/predict.py`?
**Answer:**  
In `predict.py`, we execute `requests.get(url, timeout=2.5)`. The `timeout=2.5` parameter ensures that if a server is unresponsive or slow, the request raises a `requests.exceptions.Timeout` exception within 2.5 seconds. The exception is caught in a `try...except` block, and execution falls back to the 22-feature URL-only model (`model_url`).

---

### Q3. Why do you use `joblib` instead of standard `pickle` for model serialization in `predict.py`?
**Answer:**  
`joblib` is optimized for serializing large NumPy arrays and Scikit-Learn models. It uses memory mapping and efficient binary compression, resulting in faster disk I/O loading times during Flask server startup compared to standard Python `pickle`.

---

### Q4. How do you prevent your feature extractor from throwing key errors when web features are missing?
**Answer:**  
In `URLFeatureExtractor.extract_web_features_from_html()`, all features are assigned fallback default values (e.g., `0` for missing tags, `0.0` for missing match scores). Additionally, during dataset alignment in `train_model.py`, missing values are imputed using `.fillna(median)`.

---

### Q5. What is the role of `BeautifulSoup` in your feature extraction script?
**Answer:**  
`BeautifulSoup` parses raw HTML string responses into a navigable DOM tree. We use it to extract structural indicators such as `soup.find_all('iframe')`, `soup.find_all('form')`, title text `soup.find('title')`, favicon links `soup.find('link', rel='icon')`, and input types `soup.find_all('input', {'type': 'password'})`.

---

### Q6. How does `dns_verifier.py` handle temporary network failures during DNS resolution?
**Answer:**  
`dns_verifier.py` uses a dual-redundancy DoH approach. It first attempts to resolve records via Cloudflare DoH (`cloudflare-dns.com`). If Cloudflare fails or times out, it catches the exception and falls back to Google DoH (`dns.google`). If both fail, it sets `query_failed = True` so the downstream email engine avoids incorrectly flagging a legitimate email due to temporary network outage.
