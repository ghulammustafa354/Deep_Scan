# Deep_Scan: A Multi-Modal Phishing Detection System Using Hybrid Machine Learning, Transformer Models, and QR Code Analysis

**[IEEE Format — Final Year Project Research Paper]**

---

**Authors:** [Author Names]  
**Department:** [Department Name]  
**Institution:** [University Name]  
**Email:** [email@university.edu.pk]  
**Date:** July 2026

---

## Abstract

Phishing attacks remain one of the top threats to internet users and organizations every year. Attackers keep finding new ways to steal information, including fake websites, fake emails, and now even fake QR codes. This paper presents **Deep_Scan**, a phishing detection system that works on three types of threats at the same time: malicious URLs, phishing emails, and QR code-based attacks (called "quishing"). The system uses a three-phase approach for URL checking, which goes from fast rule-based checks to machine learning models trained on the PhiUSIIL dataset (235,795 URLs). For email analysis, it uses a DistilBERT transformer model as the primary detector, backed by a TF-IDF logistic regression model, and a rule-based fallback. It also checks sender domain authenticity through real-time DNS verification of MX, SPF, and DMARC records. QR code images are decoded using OpenCV, and the extracted URL is then analyzed by the same URL pipeline. Domain WHOIS age checks and Levenshtein distance typosquatting detection further reduce false negatives. Testing shows the URL model achieves around 95% accuracy on the PhiUSIIL dataset, and the email model achieves strong performance on the CEAS_08 and Enron combined corpus. A Google Chrome extension provides real-time protection in the browser. All components are connected through a Flask REST API backend.

**Keywords:** phishing detection, machine learning, DistilBERT, Random Forest, QR code analysis, DNS verification, typosquatting, WHOIS, Chrome extension

---

## I. Introduction

The internet has become central to daily life. People use it for banking, shopping, communication, and work. But this also makes it a target for criminals who want to steal personal data, passwords, or money. One of the most common methods attackers use is **phishing** — creating fake versions of real websites or emails to trick users into giving away their information.

According to various reports, billions of phishing attempts happen every year. No single detection method works against all of them. Older systems that only check URLs are fooled by attackers who move to email campaigns. Email-only systems miss dangerous links embedded in QR codes. This fragmented protection leaves users exposed.

Deep_Scan was built to solve this problem by creating a single unified system that can handle three types of phishing attacks:

1. **URL phishing** — detecting dangerous websites before the user visits them
2. **Email phishing** — analyzing email content, sender authenticity, and embedded links
3. **QR code phishing (quishing)** — scanning QR codes to find hidden malicious URLs

This paper describes how the system works, the technologies used, the datasets, the evaluation results, and the design decisions made throughout development.

---

## II. Background and Related Work

### A. URL-Based Phishing Detection

Early phishing URL detection relied on blacklists and simple keyword rules. Over time, researchers moved toward machine learning. Studies showed that Random Forest classifiers work well for URL classification because they handle many different feature types at once and resist overfitting [1]. The PhiUSIIL Phishing URL Dataset is a modern, large-scale benchmark with over 235,000 labeled URLs and both structural URL features and web content features.

### B. Email Phishing Detection

Traditional email spam filters use keyword matching and sender blacklists. More recent work applies NLP techniques. Research using BERT-based models on email corpora showed better accuracy than TF-IDF or bag-of-words methods [2]. The CEAS_08 dataset is a well-known benchmark for phishing email classification. The Enron email corpus is a large public collection of legitimate corporate emails.

### C. QR Code-Based Attacks

QR code usage grew sharply after 2020. Attackers now embed malicious URLs inside QR codes on posters, in emails, or in messages. This is called "quishing." Few existing systems include QR code scanning as part of their phishing detection pipeline.

### D. Gap This Work Fills

Most existing systems focus on one threat type. Deep_Scan fills this gap by building a single integrated system covering URL, email, and QR code threats, with multiple detection layers rather than one approach.

---

## III. System Architecture

Deep_Scan follows a client-server architecture. The user interacts through a web interface or Chrome extension. Requests go to a Flask REST API backend, which routes them to the correct detection module. Results are returned as JSON and displayed to the user.

### A. Overall Component Overview

```
User (Browser or Chrome Extension)
        |
        | HTTP Request (JSON)
        v
Flask REST API (app.py — Python)
        |
    ┌───┴──────────────────────────┐
    |                              |
URL Detection Module         Email Detection Module
(predict.py)                 (email_detector.py)
    |                              |
Phase 1: Rule-Based          Tier 1: DistilBERT
  - Typosquatting check      Tier 2: TF-IDF + Logistic Regression
  - Domain whitelist         Tier 3: Rule-Based NLP
  - OpenDNS top domains            |
  - WHOIS domain age         DNS Verifier (dns_verifier.py)
  - Suspicious path check      - MX, SPF, DMARC via DoH APIs
Phase 2: Full 50-feature ML        |
  (URL features + HTML features)   |
Phase 3: URL-only 22-feature ML    |
    |                              |
    └──────────────┬───────────────┘
                   |
          QR Code Module
          (OpenCV decode → URL pipeline)
                   |
          JSON Response → Frontend
```

### B. Backend API Endpoints

The Flask API (app.py) exposes these REST endpoints:

| Endpoint | Method | Purpose |
|---|---|---|
| `/predict` | POST | Analyze a single URL |
| `/predict/email` | POST | Analyze email content, sender, and embedded links |
| `/predict/qr` | POST | Decode QR code image and analyze the embedded URL |
| `/batch_predict` | POST | Analyze up to 100 URLs at once |
| `/check_certificate` | POST | Verify SSL/TLS certificate of a domain |
| `/model_info` | GET | Return information about loaded ML models |

All endpoints return JSON with `prediction`, `confidence`, `risk_level`, and `probabilities` fields.

---

## IV. URL Phishing Detection

### A. Three-Phase Detection Pipeline

The core design idea in the URL module is a **three-phase hybrid approach**. Each phase is tried in sequence. If a phase gives a confident result, the pipeline stops early.

---

**Phase 1 — Rule-Based Fast Check**

The first phase runs deterministic checks before any machine learning model. This is fast and handles clear-cut cases with 100% confidence.

*Typosquatting Detection*: Domain segments are compared against a list of major brands including Facebook, Google, Microsoft, Apple, Amazon, PayPal, Netflix, LinkedIn, Snapchat, and Foodpanda. A Levenshtein edit-distance algorithm checks each domain segment. If any segment has an edit distance of 1 or 2 from a brand name and the domain is not in the brand's official domain list, the URL is flagged phishing at 99% confidence.

*Domain Whitelist*: Known legitimate domains are checked. This includes explicitly listed major websites and educational/government domains ending in `.edu`, `.gov`, `.edu.pk`, and country-code TLD academic domains like `.ac.uk`.

*OpenDNS Top 10,000 Domains*: The system downloads and caches the 10,000 most popular legitimate domains from OpenDNS. Domains matched in this list are marked legitimate — unless their subdomain prefix contains suspicious keywords like "login," "auth," "verify," "secure," or "billing."

*WHOIS Domain Age Check*: For domains not matched by the above checks, the system queries WHOIS (through IANA and the domain's registrar server) to get the domain creation date. Domains older than 365 days are trusted as legitimate. Results are cached in a local JSON file to avoid repeated slow lookups.

*Suspicious Path Check*: Even whitelisted domains are re-evaluated if their URL path contains keywords like `/login`, `/signin`, `/verify`, `/credential`, or `/account-update`. This catches phishing pages hosted on compromised legitimate servers.

---

**Phase 2 — Full 50-Feature Machine Learning Model**

If Phase 1 does not give a result, the system extracts features and uses machine learning.

When the system can successfully fetch the webpage HTML (within a 2.5-second timeout), it uses a **full 50-feature model** combining:
- **22 URL-structural features** computed only from the URL text
- **28 web content features** extracted from the live HTML page

The 22 URL features include: URL length, domain length, whether the domain is an IP address, TLD legitimacy probability, character continuation rate, alphabetic character probability, number of subdomains, obfuscation detection (percent-encoded characters, long random strings), digit/letter ratios, counts of `=`, `?`, `&`, special characters, and HTTPS usage.

The 28 HTML features include: lines of code, largest line length, page title presence, title-domain similarity score, favicon presence, viewport responsiveness, number of HTTP redirects, self-referencing links, meta description, popup scripts, iFrames, external form submissions, social network links, submit buttons, hidden form fields, password input fields, banking/payment/crypto keywords in page text, copyright notice, image count, CSS file count, JavaScript count, and counts of self/empty/external anchor links.

---

**Phase 3 — URL-Only 22-Feature Model (Fallback)**

If the webpage cannot be fetched (offline, blocks bots, or times out), the system falls back to a **URL-only 22-feature model** that works purely on the URL text itself. This is always available.

If both ML models are unavailable (e.g., model files not found), a heuristic scoring fallback runs. It evaluates the URL based on HTTPS usage, domain segment count, TLD quality, URL length, and special character count.

---

### B. Machine Learning Model Configuration

Both models are Random Forest classifiers trained with scikit-learn. Configuration used:

| Hyperparameter | Value | Reason |
|---|---|---|
| `n_estimators` | 30 | Balance of accuracy and speed |
| `max_depth` | 8 | Prevents overfitting |
| `min_samples_split` | 50 | Needs enough samples to split a node |
| `min_samples_leaf` | 20 | Needs enough samples in leaf nodes |
| `max_features` | 0.7 | Each tree uses 70% of features |
| `random_state` | 42 | Reproducible results |
| `n_jobs` | -1 | All CPU cores used for training |

Features are normalized with `StandardScaler` before training and inference. Models and scalers are saved as `.pkl` files using joblib.

### C. Training Dataset

Models were trained on the **PhiUSIIL Phishing URL Dataset**, which has 235,795 URLs — roughly 50% phishing and 50% legitimate. An 80/20 stratified train-test split was used. 5-fold cross-validation confirmed model consistency.

Training was done in two steps: first extracting the 22 URL features from each URL using the `URLFeatureExtractor` class, then combining them with the 28 web content features already in the CSV to form the full 50-feature dataset.

### D. Performance Results

| Model | Accuracy | Precision | Recall | F1-Score |
|---|---|---|---|---|
| URL-only (22 features) | ~95.0% | ~95% | ~95% | ~95% |
| Full model (50 features) | ~96.0% | ~96% | ~96% | ~96% |

Cross-validation mean accuracy: ~94.9% (URL-only), ~96.0% (Full)

---

## V. Email Phishing Detection

### A. Multi-Tier Detection

The email module uses a waterfall structure — from most powerful to simplest.

---

**Tier 1 — DistilBERT Transformer**

The primary detector is a pre-trained DistilBERT model fine-tuned for phishing emails: `cybersectony/phishing-email-detection-distilbert_v2.1` from HuggingFace [8]. Email subject and body are concatenated, tokenized to a maximum of 512 tokens, and passed through the model. It produces four probability outputs: `legitimate_email`, `phishing_url`, `legitimate_url`, and `phishing_url_alt`. The final phishing probability is the sum of the two phishing label probabilities.

A hybrid speedup mode is available: TF-IDF runs first, and if it gives a high-confidence legitimate result (≥0.90), DistilBERT is skipped. This reduces inference time for clearly legitimate emails.

---

**Tier 2 — TF-IDF + Logistic Regression**

If DistilBERT is unavailable, the system uses a trained TF-IDF vectorizer (10,000 features, unigrams and bigrams) combined with a Logistic Regression classifier. This was trained on the combined CEAS_08 and Enron corpus.

---

**Tier 3 — Rule-Based NLP Fallback**

If no ML model is loaded, keyword scoring is used. Phishing keywords (e.g., "urgent," "verify," "suspend," "click here," "account locked"), suspicious regex patterns for credit card numbers and password fields, urgency language, all-caps ratio, exclamation counts, and URL shortener presence all contribute to a risk score. A score above 50 out of 100 is classified as phishing.

---

### B. Training Dataset

Two datasets were combined:
- **CEAS_08.csv** — 67.9 MB phishing email benchmark from the 2008 CEAS challenge
- **Enron emails.csv** — 1.42 GB of corporate legitimate emails. The file is too large to load at once, so chunked reading (20,000 rows at a time) was used. Up to 15,000 ham emails were extracted, filtered for non-empty bodies.

Text was preprocessed with NLTK: HTML tags removed, URLs and email addresses replaced with placeholder tokens, stopwords filtered, words stemmed with Porter Stemmer. The processed text was split 80/20 for training and testing.

### C. Sender Domain Verification

After text-based prediction, the system performs three additional sender checks:

*Typosquatting check on sender domain*: The same Levenshtein algorithm used in URL detection is applied to the sender's email domain. If the domain appears to imitate a brand (e.g., `paypa1.com`), the result is overridden to phishing at 99% confidence.

*Whitelist trusted sender override*: If the sender domain matches a curated list of known legitimate senders — including Google, Microsoft, Apple, Amazon, PayPal, LinkedIn, GitHub, and Pakistani financial services like EasyPaisa and SadaPay — and the email content is not otherwise suspicious, the result is forced to Legitimate. This reduces false positives on real notifications.

*DNS MX/SPF/DMARC check*: The `dns_verifier.py` module queries the Cloudflare DNS over HTTPS API with a fallback to Google's DoH API. It checks:
- **MX records**: Does the sender domain have valid mail exchange records? A domain with no MX records cannot legitimately send mail — a strong phishing indicator.
- **SPF record**: Does the domain have a Sender Policy Framework record in its DNS TXT records?
- **DMARC record**: Does the domain have DMARC policy (`none`, `quarantine`, or `reject`)?

DNS query results are cached in memory within the session to avoid repeated lookups for the same domain.

### D. Link Scanning Within Emails

Any URLs found in the email body are extracted and sent as a list from the frontend. Each link passes through the full URL detection pipeline. The number of phishing links found and the highest confidence phishing link score are combined with the email body analysis to form the final verdict.

### E. Final Verdict Logic

Three signals are combined:
- Email body analysis (DistilBERT / TF-IDF / rules)
- Sender domain analysis (typosquatting / whitelist / DNS)
- Link analysis (phishing URLs found in email)

If the sender is confirmed as an official brand domain and no links were flagged, the overall result is forced to Legitimate regardless of text model output. This is key to avoiding false positives for legitimate marketing emails. Otherwise, if any signal returns Phishing, the result is Phishing. The final confidence is the maximum across all contributing signals.

---

## VI. QR Code (Quishing) Detection

### A. Why This Matters

QR code usage grew rapidly after 2020. Attackers began hiding phishing URLs inside QR codes placed on printed materials, emails, or social media. A user scanning a malicious QR code may be redirected to a phishing site without ever seeing the URL. Existing phishing tools do not address this threat.

### B. How It Works

The `/predict/qr` endpoint receives an uploaded image file:

1. The image bytes are decoded into an OpenCV matrix using `cv2.imdecode`
2. OpenCV's `QRCodeDetector` scans the matrix and extracts the embedded URL text
3. The URL is normalized (HTTPS prefix added if missing)
4. Educational and government domains (ending in `.edu`, `.gov`, `.edu.pk`, `.gov.pk`) are automatically trusted at this stage
5. All other URLs pass through the same three-phase URL detection pipeline
6. The result includes prediction, confidence, risk level, method used, and the decoded URL

The web interface includes two built-in test QR codes stored as base64-encoded PNG images — one linking to a legitimate site, one linking to a phishing URL — so users can test without uploading files.

---

## VII. SSL/TLS Certificate Verification

An additional endpoint (`/check_certificate`) checks the SSL certificate of a given domain. Python's `ssl` library opens a real TLS connection on port 443, reads the certificate, and returns:
- Whether the site uses HTTPS at all (HTTP sites have no certificate)
- Whether the certificate is valid or expired
- Days remaining until expiry
- Who the certificate was issued to (common name)
- Which certificate authority issued it

This helps users verify that a site has a properly trusted certificate, since phishing sites often use self-signed certificates or recently issued certificates from free CAs.

---

## VIII. Chrome Extension

A Google Chrome extension (Manifest Version 3) provides real-time browser-level protection:

- **`content.js`** — A content script running on every webpage. It monitors URL changes and can inject warning overlays when a phishing threat is detected.
- **`background.js`** — A service worker managing communication between content scripts, the popup, and the Flask backend.
- **`popup.html` / `popup.js`** — The popup displayed when the user clicks the extension icon. It shows the current page's phishing status, confidence score, risk level, and allows manual URL input for checking.

The extension sends the active tab's URL to `http://localhost:5000/predict` and shows the result. Required permissions: `activeTab`, `tabs`, `storage`, `notifications`.

---

## IX. Web Interface

The frontend is a single HTML file (`cyber_interface.html`) served directly by Flask at the root URL. It contains four tabs:

- **URL Tab** — Enter a URL and scan it. Results show prediction, confidence, risk level, and probability bars for phishing/legitimate.
- **Email Tab** — Enter email content, subject line, and sender address. Analysis returns body prediction, sender analysis with DNS verification details, and link analysis.
- **QR Code Tab** — Upload a QR image or click built-in test examples. Shows decoded URL and full analysis result.
- **Batch URL Tab** — Enter multiple URLs (one per line) and scan them all at once. Results appear in a table.

The design uses a dark cyber-theme with glassmorphism, gradient colors, and animated elements.

---

## X. Experimental Results

### A. URL Detection

| Model | Accuracy | Precision (Phishing) | Recall (Phishing) | F1-Score |
|---|---|---|---|---|
| URL-only (22 features) | ~95.0% | ~94.8% | ~95.6% | ~95.2% |
| Full model (50 features) | ~96.0% | ~95.9% | ~96.1% | ~96.0% |

5-fold cross-validation mean: ~94.9% (URL-only), ~96.0% (Full)

One-time training time: approximately 5–10 minutes on a standard CPU.

### B. Email Detection

The TF-IDF + Logistic Regression model showed solid accuracy on the combined CEAS_08 and Enron test split. The DistilBERT model, fine-tuned specifically on phishing email pairs, shows stronger generalization to unseen phishing language patterns.

### C. Response Times

| Operation | Typical Time |
|---|---|
| URL — rule-based hit | <50ms |
| URL — URL-only model | <200ms |
| URL — full model with scraping | 2–4 seconds |
| Email — DistilBERT | 1–3 seconds |
| Email — TF-IDF | <300ms |
| QR decode + URL prediction | <500ms + URL time |
| DNS lookup (cached) | <10ms |
| DNS lookup (live) | 200–400ms |

### D. False Positive Reduction

Multiple mechanisms reduce false positives:
- OpenDNS top domain whitelist with subdomain keyword filtering
- WHOIS domain age verification for established domains
- Official sender domain override for confirmed brand domains
- Heuristic correction: if the text model flags an email as phishing but the email has no links, no urgency language, no suspicious patterns, and no suspicious sender — the prediction is corrected to Legitimate
- URL path keyword filtering that only applies when the domain is borderline and the path contains credential-harvesting patterns

---

## XI. Design Decisions

### A. Why Random Forest for URLs?

Random Forest handles the mix of numerical and binary features naturally. It gives feature importance scores that explain predictions. It resists overfitting through ensemble averaging. For 22–50 structured features, it achieves ~95% accuracy without needing a GPU. Adding deep learning would require much more computational resources with minimal accuracy gain for structured feature classification.

### B. Why DistilBERT for Emails?

Keywords and TF-IDF fail when attackers change their wording slightly. DistilBERT understands sentence context rather than just word frequencies. The `cybersectony/phishing-email-detection-distilbert_v2.1` model is specifically fine-tuned on phishing and legitimate email pairs, making it more robust than a general-purpose classifier trained on the same data.

### C. Why DNS over HTTPS?

Traditional DNS lookups can be blocked by firewalls or fail behind corporate NAT. DNS over HTTPS uses port 443, which is almost never blocked. Using Cloudflare and Google DoH APIs gives accurate, globally consistent results. Memory caching avoids redundant network calls for repeated domain checks.

### D. Why Flask?

Flask is lightweight and fast for a REST API. It does not force any project structure and gives full control over routing. Django would add unnecessary components (ORM, admin panel, template engine) that are not needed for a pure API backend.

---

## XII. Limitations

1. **Image-based phishing** — The system cannot analyze phishing text embedded as images in emails (e.g., screenshots of fake invoices).
2. **Language coverage** — Detection is primarily designed for English. Non-English phishing may score lower on DistilBERT.
3. **Static models** — The models do not update automatically. New phishing patterns require manual retraining.
4. **QR code quality** — Very small, damaged, or artistic QR codes may fail OpenCV's built-in detector.
5. **DistilBERT resource use** — DistilBERT requires the `transformers` and `torch` libraries, which need several hundred MB of disk space and RAM. On resource-limited devices, only TF-IDF or rule-based analysis runs.

---

## XIII. Future Work

1. **OCR integration** — Add optical character recognition to extract text from image attachments and scan for phishing content.
2. **Online retraining** — Build a feedback loop using user-reported false positives/negatives to periodically retrain the models.
3. **Multi-language support** — Expand keyword lists and add multilingual transformer models.
4. **Better QR scanning** — Integrate ZXing or similar libraries for more robust QR and barcode decoding.
5. **Graph-based domain analysis** — Use domain-to-domain link graphs to identify coordinated phishing campaigns.
6. **Mobile app** — Port the Chrome extension logic to an Android or iOS application.

---

## XIV. Conclusion

This paper presented Deep_Scan, a multi-modal phishing detection system that goes beyond single-threat approaches. By combining three-phase URL detection, multi-tier email analysis using DistilBERT and TF-IDF, real-time DNS sender verification, WHOIS domain age checks, Levenshtein typosquatting detection, and QR code quishing analysis — all connected through a Flask REST API — the system provides a broad defense against modern phishing attacks.

The URL model achieves approximately 95–96% accuracy on the PhiUSIIL benchmark. The email system's multi-tier fallback ensures reliable detection even when heavyweight models are unavailable. The QR code module extends coverage to a growing and underserved threat vector.

The core finding is that combining fast deterministic rules with trained machine learning models is more effective than either alone. Rule-based checks catch known brand impersonation with certainty. ML models generalize to unseen patterns. DNS verification adds a ground-truth signal that no text model can replicate. Together, these layers reduce both false positives and false negatives across all three threat types.

---

## References

[1] A. Khade and S. Shah, "Phishing website detection using machine learning algorithms," *International Journal of Computer Applications*, vol. 182, no. 34, 2019.

[2] J. Devlin, M. Chang, K. Lee, and K. Toutanova, "BERT: Pre-training of deep bidirectional transformers for language understanding," in *Proc. NAACL-HLT*, 2019.

[3] S. Hannousse and S. Yahiouche, "PhiUSIIL phishing URL dataset," UCI Machine Learning Repository, 2023. [Online]. Available: https://www.kaggle.com/datasets/harisudhan411/phishing-and-legitimate-urls

[4] CEAS 2008 Email Spam Filtering Challenge Dataset. [Online]. Available: https://plg.uwaterloo.ca/~gvcormac/ceascorpus/

[5] W. Cohen, "Enron email dataset," Carnegie Mellon University, 2004. [Online]. Available: https://www.cs.cmu.edu/~enron/

[6] OpenDNS, "Public Domain Lists — Top Domains," GitHub. [Online]. Available: https://github.com/opendns/public-domain-lists

[7] Cloudflare, "DNS over HTTPS," Developer Documentation. [Online]. Available: https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/

[8] HuggingFace, "cybersectony/phishing-email-detection-distilbert_v2.1," HuggingFace Hub. [Online]. Available: https://huggingface.co/cybersectony/phishing-email-detection-distilbert_v2.1

[9] L. Breiman, "Random forests," *Machine Learning*, vol. 45, pp. 5–32, 2001.

[10] V. Sanh, L. Debut, J. Chaumond, and T. Wolf, "DistilBERT, a distilled version of BERT: smaller, faster, cheaper and lighter," *arXiv preprint arXiv:1910.01108*, 2019.

---

## Appendix: Project File Structure

```
Deep_Scan/
├── backend/
│   ├── app.py                    Flask REST API — 7 endpoints
│   ├── predict.py                URL feature extractor + 3-phase predictor
│   └── whois_helper.py           WHOIS domain age lookup with local cache
├── email_analysis/
│   ├── email_detector.py         Multi-tier email detector (DistilBERT/TF-IDF/Rules)
│   └── dns_verifier.py           DNS MX/SPF/DMARC verification via DoH APIs
├── models/
│   ├── train_model.py            URL model training script (PhiUSIIL dataset)
│   ├── train_email_model.py      Email model training (CEAS_08 + Enron)
│   ├── model_evaluation.py       Evaluation metrics, confusion matrix, ROC curves
│   ├── top_domains.txt           Cached OpenDNS top 10,000 domains
│   ├── whois_cache.json          Cached WHOIS domain creation dates
│   └── saved_models/
│       ├── phishing_detector_url.pkl    URL-only Random Forest model
│       ├── phishing_detector_full.pkl   Full 50-feature Random Forest model
│       ├── scaler_url.pkl               StandardScaler for URL features
│       ├── scaler_full.pkl              StandardScaler for full features
│       ├── email_phishing_model.pkl     TF-IDF + Logistic Regression email model
│       └── reputation_db.bin            Compressed domain reputation data
├── dataset/
│   ├── PhiUSIIL_Phishing_URL_Dataset.csv   235,795 URL samples
│   ├── CEAS_08.csv                          Phishing email benchmark
│   └── emails.csv                           Enron corporate ham emails (1.42 GB)
├── frontend/
│   ├── cyber_interface.html      Single-page web app (4 tabs)
│   ├── legitimate_qr.png         Built-in test QR — legitimate
│   └── phishing_qr.png           Built-in test QR — phishing
└── chrome_extension/
    ├── manifest.json             Manifest V3 extension config
    ├── background.js             Service worker — API communication
    ├── content.js                Content script — in-page monitoring
    ├── popup.html                Extension popup UI
    └── popup.js                  Popup logic and result display
```

---

*End of Report*
