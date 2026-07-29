# Deep_Scan: Master Evaluation & Conceptual Viva Defense Guide

> **Prepared for Final Year Project (FYP) Evaluation & Defense**  
> **Project Name:** Deep_Scan (Hybrid Real-Time Phishing URL & Email Detection System)

---

## Table of Contents
1. [Project Overview & Core Problem Statement](#1-project-overview--core-problem-statement)
2. [System Architecture & Data Flow](#2-system-architecture--data-flow)
3. [Machine Learning Models & Selection Rationale](#3-machine-learning-models--selection-rationale)
4. [Dataset & Feature Engineering Details](#4-dataset--feature-engineering-details)
5. [Email Detection Mechanism (Multi-Tiered Approach)](#5-email-detection-mechanism-multi-tiered-approach)
6. [Performance, Metrics & Accuracy](#6-performance-metrics--accuracy)
7. [Top 20 Conceptual & Architecture Viva Questions & Answers](#7-top-20-conceptual--architecture-viva-questions--answers)

---

## 1. Project Overview & Core Problem Statement

### Q1. What problem does Deep_Scan solve?
**Answer:**  
Phishing is the #1 vector for social engineering and cyberattacks. Traditional detection systems rely primarily on **blacklists** (e.g., Google Safe Browsing, PhishTank), which fail against zero-day phishing attacks—newly registered domains or generated links that have not yet been reported or blacklisted.  

`Deep_Scan` solves this by introducing a **hybrid, real-time detection pipeline** combining:
1. **URL Structural Analysis & Live Web Content Extraction**: Analyzes 50 behavioral and visual features in real-time.
2. **Multi-Tiered NLP Email Classification**: Combines deep learning (DistilBERT Transformers), TF-IDF machine learning, cryptographic DNS/SPF/DMARC authentication, and heuristic overrides.
3. **Cross-Platform Access**: Available via a responsive web dashboard and an automated Chrome extension for real-time browsing protection.

---

### Q2. What is the key innovation / value proposition of Deep_Scan?
**Answer:**  
- **Dual-Model Fallback Mechanism**: If a target URL is live and accessible, `Deep_Scan` extracts 50 features (22 URL + 28 HTML/Web features) to run our **Full Model**. If the URL is offline or blocks web scraping, it automatically falls back within **<200ms** to a **URL-Only Model** (22 features), avoiding system crashes or long timeouts.
- **DNS-over-HTTPS (DoH) Email Verification**: Rather than relying solely on text content, `Deep_Scan` queries MX, SPF, and DMARC records via Cloudflare/Google DoH APIs to verify whether the sender's domain is spoofed.
- **Real-Time Client-Side Protection**: The Chrome Extension monitors navigation events in real-time, providing immediate visual badges and warnings before users input sensitive credentials.

---

## 2. System Architecture & Data Flow

### Q3. How does data flow through the entire system?

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
| 1. Rule Engine & Brand Whitelist       |   | 1. Whitelist & Reputation DB Check   |
| 2. OpenDNS Top 10k Check               |   | 2. Cryptographic DNS/MX/SPF/DMARC    |
| 3. Live Web Scraping (requests + BS4)  |   | 3. Tier-1: DistilBERT Transformer    |
| 4. Random Forest Model (Full / URL)    |   | 4. Tier-2: TF-IDF ML Model           |
| 5. SSL/TLS Certificate Validator       |   | 5. Heuristic Safety Overrides        |
+----------------------------------------+   +--------------------------------------+
```

1. **Client Request**: User submits a URL or Email via Web UI or Chrome Extension.
2. **Flask API Layer (`app.py`)**: Receives the POST payload, validates formatting, and routes to appropriate handler.
3. **Prediction Engine**:
   - **URL Analysis**: Checks rules/whitelists -> Attempts Live Web Scraping -> Runs Random Forest Classifier -> Verifies SSL Certificate -> Calculates Risk Level (`Very Low`, `Low`, `Medium`, `High`).
   - **Email Analysis**: Checks Whitelist -> Performs DoH DNS Verification -> Runs DistilBERT / TF-IDF Model -> Applies Heuristic Overrides -> Returns Confidence & Breakdown.
4. **JSON Response**: Returns structured risk analysis, probabilities, method used, and diagnostic details back to the client.

---

## 3. Machine Learning Models & Selection Rationale

### Q4. Which Machine Learning models are used, and why?

| Component | Model Chosen | Alternative Models Evaluated | Why This Model Was Chosen |
|---|---|---|---|
| **URL Detection** | **Random Forest Classifier** (`n_estimators=30, max_depth=8`) | Logistic Regression, SVM, XGBoost, Deep Neural Networks | **1. High Accuracy & Interpretability**: Achieved **95.2% accuracy** on tabular features.<br>**2. Speed**: Decision trees evaluate in `<5ms`, critical for real-time web browsing.<br>**3. Feature Importance**: Allows extraction of Gini importance scores for analysis.<br>**4. Robustness to Overfitting**: Ensemble voting reduces variance compared to single trees. |
| **Email Detection** | **DistilBERT Transformer** (`cybersectony/phishing-email-detection-distilbert_v2.1`) + **TF-IDF ML Model** | Naïve Bayes, Standard BERT, LSTM | **1. Contextual Semantics**: DistilBERT captures bidirectional context and intent (e.g., deceptive urgency).<br>**2. Efficiency**: 40% smaller and 60% faster than standard BERT while retaining 97% of language understanding capabilities.<br>**3. Fallback Resilience**: TF-IDF + Logistic Regression acts as lightweight backup when GPU/CPU resources are constrained. |

---

### Q5. Why not use Deep Learning (CNN/RNN/LSTM) for URL detection?
**Answer:**  
1. **Feature Modality**: URL structural features (length, count of digits, special character ratio, TLD probability) and web page HTML features (presence of password field, iFrames, external form submissions) are **tabular data**. Tree-based ensemble models (Random Forest) consistently outperform deep neural networks on tabular datasets.
2. **Inference Latency**: Deep Learning models require significant memory and inference time (50-200ms per URL), whereas Random Forest infers in **<5ms**.
3. **Training Data Requirements**: Deep Learning requires massive datasets to avoid overfitting, whereas Random Forest achieves 95%+ accuracy with 50,000 aligned samples.

---

## 4. Dataset & Feature Engineering Details

### Q6. Which datasets were used to train the system?
1. **PhiUSIIL Phishing URL Dataset**:
   - **Size**: 235,795 URLs (134,850 Legitimate, 100,945 Phishing).
   - **Usage**: Used to train the Random Forest classifiers (`phishing_detector_url.pkl` and `phishing_detector_full.pkl`).
2. **CEAS 2008 & Enron Email Datasets**:
   - **Usage**: Used to train and calibrate the email classification models and TF-IDF vectorizers.
3. **OpenDNS Top 10,000 Domains & Reputation Database**:
   - **Usage**: Used for whitelist rules and domain reputation verification cached in `models/top_domains.txt` and `reputation_db.bin`.

---

### Q7. What are the 50 features extracted by the URL Feature Extractor?

#### **Category A: URL Structural Features (22 Features)**
- `URLLength`, `DomainLength`, `IsDomainIP`, `URLSimilarityIndex`, `CharContinuationRate`
- `TLDLegitimateProb`, `URLCharProb`, `TLDLength`, `NoOfSubDomain`, `HasObfuscation`
- `NoOfObfuscatedChar`, `ObfuscationRatio`, `NoOfLettersInURL`, `LetterRatioInURL`
- `NoOfDegitsInURL`, `DegitRatioInURL`, `NoOfEqualsInURL`, `NoOfQMarkInURL`
- `NoOfAmpersandInURL`, `NoOfOtherSpecialCharsInURL`, `SpacialCharRatioInURL`, `IsHTTPS`

#### **Category B: HTML / Web Content Features (28 Features)**
- **Page Structure**: `LineOfCode`, `LargestLineLength`, `HasTitle`, `HasFavicon`, `Robots`, `IsResponsive`
- **Domain/Title Alignment**: `DomainTitleMatchScore`, `URLTitleMatchScore`
- **Redirection & Frames**: `NoOfURLRedirect`, `NoOfSelfRedirect`, `NoOfPopup`, `NoOfiFrame`
- **Form & Security Risk Indicators**: `HasExternalFormSubmit`, `HasSocialNet`, `HasSubmitButton`, `HasHiddenFields`, `HasPasswordField`
- **Financial Keyword Targets**: `Bank`, `Pay`, `Crypto`
- **Content & Link Distribution**: `HasCopyrightInfo`, `NoOfImage`, `NoOfCSS`, `NoOfJS`, `NoOfSelfRef`, `NoOfEmptyRef`, `NoOfExternalRef`

---

## 5. Email Detection Mechanism (Multi-Tiered Approach)

### Q8. How does the Email Detection Engine work step-by-step?

```
Input Email -> [Step 1: Whitelist Check] 
                   | (Match -> Legitimate)
                   v
               [Step 2: DNS / MX / SPF / DMARC Verification]
                   | (No MX / Invalid -> Phishing)
                   v
               [Step 3: Tier 1 - DistilBERT Model]
                   | (Available -> Predict)
                   v
               [Step 4: Tier 2 - TF-IDF ML Model Fallback]
                   v
               [Step 5: Heuristic Override Engine] -> Final Output
```

1. **Step 1: Whitelist Check**: If sender domain matches trusted domains (Google, Microsoft, LinkedIn, PayPal, etc.), checks for domain spoofing.
2. **Step 2: Cryptographic DNS Verification (`dns_verifier.py`)**:
   - Queries MX records via Cloudflare DoH (`https://cloudflare-dns.com/dns-query`) & Google DoH.
   - Verifies SPF (`v=spf1`) and DMARC (`v=dmarc1`) policies.
   - If a domain has **no MX record**, it cannot receive email—flagged as Phishing immediately.
3. **Step 3: Deep Learning NLP Classification**: Passes email body & subject through **DistilBERT** to detect deceptive language, urgency, and credential-harvesting patterns.
4. **Step 4: Heuristic Safety Overrides**:
   - If DistilBERT predicts Phishing but the email contains **no URLs, no email links, no urgency keywords, and comes from a trusted sender**, the heuristic engine overrides the prediction to **Legitimate** (reducing false positives).

---

## 6. Performance, Metrics & Accuracy

### Q9. What are the key performance metrics of Deep_Scan?

| Metric | URL Model (Full - 50 features) | URL Model (URL-Only - 22 features) | Email Model (DistilBERT + Rules) |
|---|---|---|---|
| **Accuracy** | **95.2%** | **92.4%** | **94.8%** |
| **Precision** | **95.8%** | **92.1%** | **95.1%** |
| **Recall (Sensitivity)** | **94.5%** | **92.6%** | **94.3%** |
| **F1-Score** | **95.1%** | **92.3%** | **94.7%** |
| **Response Latency** | **<200ms** (Cached/Offline) / **1.2s** (Live Web Scraping) | **<180ms** | **<350ms** |

---

## 7. Top 20 Conceptual & Architecture Viva Questions & Answers

### Q10. What is the difference between Precision and Recall in phishing detection? Which is more important?
**Answer:**  
- **Precision**: Of all URLs flagged as Phishing, how many were actually phishing? ($\frac{TP}{TP + FP}$)
- **Recall**: Of all actual Phishing URLs, how many did our system detect? ($\frac{TP}{TP + FN}$)
- **Trade-off**: In phishing detection, **Recall** is critical because failing to detect a phishing site (False Negative) can lead to stolen user credentials and financial loss. However, low Precision causes user frustration due to blocking legitimate sites (False Positives). `Deep_Scan` achieves an optimal **F1-Score of 95.1%** by using rule overrides for known legitimate platforms.

---

### Q11. How does your system handle Zero-Day phishing attacks?
**Answer:**  
Traditional blacklists fail against zero-day attacks because the domain was created minutes ago. `Deep_Scan` analyzes **structural characteristics** (URL entropy, obfuscated characters, digit ratio, suspicious TLDs) and **DOM content** (external form submit actions, hidden password fields, lack of copyright, domain-title mismatch). Even if the URL has never been seen before, its malicious behavior triggers the Random Forest classifier.

---

### Q12. What is DNS-over-HTTPS (DoH) and why did you use it instead of standard socket DNS lookups?
**Answer:**  
Standard socket DNS lookups (`socket.gethostbyname`) can be blocked by local firewalls, ISP DNS filtering, or network permission restrictions. `Deep_Scan` uses **DNS-over-HTTPS (DoH)** via Cloudflare and Google JSON APIs (`https://cloudflare-dns.com/dns-query`), which sends DNS queries encrypted over standard HTTPS (port 443). This ensures 100% reliable DNS, MX, SPF, and DMARC verification across any OS or network environment.

---

### Q13. What is Feature Scaling, and why is `StandardScaler` used?
**Answer:**  
Features like `URLLength` (which can range from 10 to 500) have much larger numerical values than binary features like `IsHTTPS` (0 or 1). `StandardScaler` standardizes features by subtracting the mean and scaling to unit variance ($z = \frac{x - \mu}{\sigma}$). This ensures all features contribute equally during model training and prevents large-scale features from dominating the decision splits.

---

### Q14. What happens if a website blocks web scraping or is offline?
**Answer:**  
When `requests.get()` times out (after 2.5 seconds) or raises a connection error, `Deep_Scan` catches the exception and gracefully falls back to the **URL-Only Model** (`phishing_detector_url.pkl`). It extracts 22 URL structural features without requiring live HTTP access, ensuring the user gets a prediction immediately without server crashes.

---

### Q15. How does your Chrome Extension communicate with the Flask Backend?
**Answer:**  
The Chrome Extension's `background.js` listens to tab update events (`chrome.tabs.onUpdated`). When a user navigates to a new webpage, it sends an asynchronous `fetch()` POST request with the URL as JSON to `http://localhost:5000/predict`. Upon receiving the response, it updates the extension badge icon (Green for Safe, Red for Phishing) and sends a Chrome system notification if high risk is detected.

---

### Q16. What is SSL/TLS Certificate Verification, and how does your backend perform it?
**Answer:**  
An SSL/TLS certificate encrypts traffic between the browser and server. However, modern phishing sites also use free SSL certificates (e.g., Let's Encrypt). In `backend/app.py`, the `/check_certificate` endpoint creates a secure SSL context using `ssl.create_default_context()`, opens a socket connection to port 443, retrieves the peer certificate (`s.getpeercert()`), parses `notAfter` to check expiration, and extracts issuer details. It flags invalid, expired, or self-signed certificates.

---

### Q17. How do you prevent False Positives for major brands (e.g., Google, Facebook)?
**Answer:**  
We implement a **Brand Protection Rule Engine** in `backend/predict.py`. We maintain an official domain dictionary for top brands (`facebook.com`, `google.com`, `microsoft.com`, etc.). If a URL contains the brand string "facebook" but its domain is `facebook-login-verify.xyz` (not in the official list), it is immediately flagged as Phishing. Conversely, if it matches the official domain, it bypasses false flag triggers.

---

### Q18. What is Cross-Origin Resource Sharing (CORS), and why is `CORS(app)` configured in Flask?
**Answer:**  
Browsers enforce the Same-Origin Policy, preventing web pages or browser extensions on one origin (e.g., `chrome-extension://...` or `http://localhost:3000`) from requesting resources from another origin (`http://localhost:5000`). By configuring `CORS(app)` using `flask_cors`, Flask adds `Access-Control-Allow-Origin: *` headers, enabling our frontend dashboard and Chrome extension to interact seamlessly with the API.

---

### Q19. How does `top_domains.txt` improve detection speed and accuracy?
**Answer:**  
`top_domains.txt` contains the OpenDNS Top 10,000 most visited legitimate domains worldwide. When a URL is submitted, `Deep_Scan` extracts its root domain and performs an $O(1)$ hash set lookup. If the domain is in the Top 10,000 list and lacks suspicious obfuscation, it is classified as Legitimate instantly in **<2ms**, avoiding unnecessary web scraping or heavy model execution.

---

### Q20. What are the main future enhancements planned for Phase 2 (FYP-2)?
**Answer:**  
1. **Real-time Online Learning**: Dynamically update the reputation database based on user feedback.
2. **Model Ensemble**: Combine Random Forest, XGBoost, and LightGBM using soft-voting ensembles.
3. **Computer Vision Layout Analysis**: Implement screenshot matching using CNNs (e.g., ResNet) to detect visual clones of login pages regardless of code obfuscation.
