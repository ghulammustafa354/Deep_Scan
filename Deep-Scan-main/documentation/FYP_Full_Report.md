# DEEP SCAN: MULTI-MODAL PHISHING DETECTION SYSTEM
## Final Year Project Report (P23F25)

**Department of Computer Science**
**DHA Suffa University, Karachi**

**Project Members:**
* Mir Balach Kamal (CS221213)
* Abdul Wahab Imran (CS211178)
* Ghulam Mustafa (CS221201)
* Prince Laksh (CS211054)

**Supervisor:** Mr. Wajahat
**Year:** 2026

---
# CHAPTER 1: INTRODUCTION

## Description of the Project
Deep Scan is an intelligent, multi-channel system designed to identify and block phishing attacks. It protects users from three major vectors: malicious URLs, fake emails, and QR code-based phishing (known as "quishing"). The project uses Machine Learning (Random Forest) for classifying URLs and Natural Language Processing (DistilBERT transformer) for analyzing email content. 

The system was developed in two phases:
1. **FYP Phase I:** Focused on the primary URL detection model, basic URL feature extraction, a simple rule-based email filter, and a basic REST API using Flask.
2. **FYP Phase II:** Added the hybrid three-phase URL pipeline (incorporating typosquatting distance checks, whitelist matching, OpenDNS rankings, and WHOIS domain age lookups), a transformer-based (DistilBERT) email body analyzer, a real-time DNS verifier (MX, SPF, DMARC), a QR code scanner using OpenCV, and a browser extension for active tab scanning.

Deep Scan integrates all these components into a single responsive web interface that allows users to verify safety in real-time.

## Details about the Domain
The domain of this project is cybersecurity, specifically focus on phishing detection. Phishing is a form of social engineering where attackers impersonate trusted brands or organizations. The goal is to deceive users into providing credentials, financial details, or personal data. 
Phishing is divided into sub-challenges:
* **URL Impersonation:** Attackers create domains that look like legitimate ones (e.g., paypa1.com instead of paypal.com) to capture user credentials.
* **Email Deception:** Attackers craft emails mimicking official communications (bank alerts, service updates) with high-urgency language.
* **Quishing (QR Phishing):** Hidden URLs inside physical or digital QR codes bypass traditional email link parsers, directing mobile or desktop users to malicious pages.

## Relevant Background
Phishing detection traditionally relied on static lists of blocked domains (blacklists). While fast, blacklists fail to detect new, unregistered phishing domains (zero-day attacks). This led to heuristic methods checking basic URL rules (e.g., URL length, character ratios). 

In recent years, Machine Learning replaced hand-crafted rules. Random Forest classifiers proved highly successful for URL detection due to their ability to process complex feature tables with high accuracy. For text-heavy inputs like emails, NLP models like TF-IDF with Logistic Regression provided a baseline, but struggled with context. The introduction of pre-trained Transformer models like BERT and DistilBERT allowed systems to evaluate semantics and the tone of an email (e.g., urgency, threats), significantly improving detection rates. Deep Scan combines these developments into a unified defensive system.

---
# CHAPTER 2: RELEVANT BACKGROUND & DEFINITIONS

This section defines key concepts and technologies used in the Deep Scan system:

* **Phishing:** An attack vector where actors impersonate authentic brands to steal user credentials, financial tokens, or personal identifiers.
* **Quishing:** QR-code-based phishing where malicious links are encoded inside a QR graphic to bypass traditional text-based filters.
* **Machine Learning (ML):** Computational models that automatically learn patterns from training data to classify new, unseen inputs.
* **Random Forest:** An ensemble learning algorithm that constructs multiple decision trees during training and outputs the mode of the classes for classification.
* **DistilBERT:** A small, fast, and light Transformer model trained by distilling BERT. It retains high language understanding for classifying text.
* **Natural Language Processing (NLP):** Computational techniques used to parse, clean, and interpret human languages.
* **Feature Extraction:** The process of converting raw unstructured data (like a web page or URL string) into a structured numerical vector.
* **Levenshtein Distance:** An algorithm measuring the minimum single-character edits required to turn one string into another. Used to flag typosquatting.
* **Typosquatting:** Registering domains close in spelling to popular brand names to catch typing mistakes or deceive visual inspection.
* **WHOIS Domain Age:** Querying public domain registrars to find domain registration dates. Young domains (e.g., < 30 days old) are treated as higher risk.
* **DNS Verification:** Querying Domain Name System records (MX, SPF, DMARC) to verify the sending server's authority and identity.
* **MX Record:** Mail Exchange record specifying the mail server responsible for accepting emails for a domain.
* **SPF (Sender Policy Framework):** A DNS record listing the authorized IP addresses allowed to send emails from a specific domain.
* **DMARC:** A protocol using SPF and DKIM to determine how receivers handle emails failing authorization checks (none, quarantine, reject).
* **DNS over HTTPS (DoH):** Executing DNS queries over an encrypted HTTPS connection to prevent tampering and eavesdropping.
* **OpenCV:** Open-source Computer Vision library, used in this project to parse uploaded images, locate QR coordinates, and decode URL payloads.
* **SSL/TLS Certificate:** Cryptographic files proving the identity of a web server. Deep Scan checks validity, CA issuer, and days until expiration.
* **CORS (Cross-Origin Resource Sharing):** Browser security mechanism allowing the web client and Chrome extension to query the local Flask backend.
* **False Positive:** A safe site or email flagged by the system as malicious.
* **False Negative:** A dangerous site or email missed by the system and classified as safe.

---
# CHAPTER 3: LITERATURE REVIEW & RELATED WORK

## Literature Review
Phishing detection research has evolved from static pattern matching to dynamic machine learning analysis:
* **URL Analysis:** Early works focused on blacklists (like Google Safe Browsing or PhishTank). While high precision, they lacked zero-day detection. In 2014, Mohammad et al. introduced URL-based feature sets for machine learning models. Sahingoz et al. (2019) demonstrated that Random Forest classifiers trained on lexical and structural features achieved accuracy rates above 94% with low processing overhead.
* **Content Scraping:** Recent models incorporate HTML features. Extracting anchor links, form action destinations, and script counts increases detection rates but requires active web page rendering and scraping.
* **Email Parsing:** NLP systems migrated from keyword counts to semantic classifiers. While TF-IDF models with Logistic Regression are fast and accurate for clean corpora, pre-trained transformers like BERT or DistilBERT offer superior generalizability because they evaluate contextual tone (urgency, panic, threat triggers) rather than simple word presence.
* **Cryptographic Signatures:** Research confirms that checking DNS records (SPF, DMARC) and SSL certificates is vital. Many phishing sites use valid SSL certificates from free authorities (like Let's Encrypt), meaning SSL validity alone is not proof of safety, but must be paired with other features.

## Related Work
Deep Scan bridges functional gaps present in standalone security systems:
* **PhishTank / Google Safe Browsing:** Provide lookup APIs for malicious links. However, they do not scan raw emails, analyze DNS authorization, or decode QR codes.
* **SpamAssassin:** Evaluates emails using static keyword rules and basic heuristics. It does not employ deep learning language models like DistilBERT, making it prone to bypasses.
* **VirusTotal:** Aggregates checks from multiple scanning engines. It is highly accurate but slow and rate-limited, making it unsuitable for instant, real-time in-browser extension scanning.

## Gap Analysis
The existing solutions have several key limitations:
1. **Lack of Integration:** Most systems check either URLs or emails. A user must use multiple utilities to check a single phishing package.
2. **Missing QR Vector:** None of the major lookup tools scan QR code images (quishing) within their primary user portals.
3. **No Domain Age Context:** Many systems ignore the registration age of a domain, which is a powerful signal for zero-day attacks.
4. **Poor Contextual Email Analysis:** Standard filters rely on static word lists, failing to identify sophisticated spear-phishing emails that use clean vocabularies.

Deep Scan covers all these gaps by providing an integrated URL, email, and QR scanner powered by machine learning, transformer models, and real-time DNS verifications.

---
# CHAPTER 4: METHODOLOGY

## Software Engineering Methodology
The project used the **Agile software development methodology**, dividing development into iterative sprints:
* **Requirements Gathering:** Defined system use cases, API structure, and feature scopes.
* **Component Design:** Built separate independent modules for URL extraction, DNS verifications, model inference, and the browser extension.
* **Sprint Development:** In each sprint, one module was developed and unit-tested before integration.
* **Continuous Integration:** Flask endpoints were progressively updated to link all modules together.

## Project Methodology

```
[Raw URL/Email/QR Input]
          |
     ┌────┴──────────────────────────┐
     v                               v
[URL Pipeline]               [Email Pipeline]
  |- Phase 1: Checks           |- Tier 1: DistilBERT Model
  |    |- Typosquatting        |- Tier 2: TF-IDF LogReg
  |    |- Whitelist            |- Tier 3: Heuristics
  |    |- WHOIS age check      |
  |- Phase 2: Full RF          |- DNS Check (MX, SPF, DMARC)
  |- Phase 3: URL-only RF      |- Link Scan (via URL Pipeline)
     (22 / 50 Features)        |
          |                    v
          v            [Verdict Engine] -> [JSON Output]
```

### URL Detection Pipeline
The URL predictor follows a three-phase cascade:
1. **Phase 1: Deterministic Heuristics & Reputation Checks**
   * *Typosquatting Check:* Computes Levenshtein edit distance against a predefined dictionary of target brands. If a domain is one or two characters away from a brand and not official, it is instantly flagged as phishing (99% confidence).
   * *Whitelist Check:* Matches domains against trusted platforms, government domains, and academic extensions (`.edu`, `.gov`, `.edu.pk`).
   * *OpenDNS Top 10k:* Checks if the domain is on the global top 10,000 domains. Subdomain prefixes are scanned for keywords (`login`, `secure`, `verify`). If clean, the domain is trusted.
   * *WHOIS Check:* Queries registry servers for the domain creation date. Domains older than 365 days are marked legitimate. Results are cached locally in `whois_cache.json`.
   * *Suspicious Path Check:* Overrides whitelists if the path contains keywords like `/login`, `/signin`, `/verify`, or `/credential`.
2. **Phase 2: Full 50-Feature Random Forest Classifier**
   * If Phase 1 is inconclusive, the system tries to fetch the target HTML (2.5s timeout).
   * If successful, it extracts 22 structural URL features and 28 content features (iFrames, external form submissions, password inputs, hidden fields, etc.).
   * The feature vector is scaled and classified by the full model.
3. **Phase 3: URL-only 22-Feature Random Forest Classifier**
   * If HTML fetching fails (timeout or site offline), the system classifies the URL using only the 22 structural features.

### Email Detection Pipeline
The email detector follows a multi-tier waterfall:
1. **Tier 1 (DistilBERT):** Classifies text using the fine-tuned HuggingFace transformer model. If RAM is low or dependencies are missing, it proceeds to Tier 2.
2. **Tier 2 (TF-IDF LogReg):** Transforms the text using a cached TF-IDF vectorizer and predicts classification using Logistic Regression.
3. **Tier 3 (Heuristic Rules):** Evaluates threat scores based on keyword presence, regex matching for card patterns, and structural ratios (all-caps ratio, exclamation count).
4. **DNS verification:** Simultaneously queries Cloudflare or Google DoH APIs to verify if the sending domain has MX records, SPF records, and a DMARC policy. If MX records are missing, the email is flagged phishing.
5. **Link Scan:** Extracts all URLs in the email body and runs them through the URL pipeline.

### QR Code Scanning Pipeline
* Uploaded image bytes are converted using OpenCV (`cv2.imdecode`).
* OpenCV's `QRCodeDetector` extracts the embedded URL string.
* The extracted URL is sent directly through the URL detection pipeline.

---
# CHAPTER 5: EXPERIMENTAL EVALUATIONS & RESULTS

## Evaluation Testbed
* **Datasets:**
  * *URL Model:* Trained on the PhiUSIIL Phishing URL Dataset (235,795 records). An 80/20 train-test split was used.
  * *Email Model:* Trained on a merged dataset of CEAS_08 (phishing) and Enron corpus (15,000 legitimate corporate emails).
* **Models Used:** Random Forest (n_estimators=30, max_depth=8, min_samples_split=50, min_samples_leaf=20) and DistilBERT (`cybersectony/phishing-email-detection-distilbert_v2.1`).

## Results and Discussion

### URL Model Accuracy

| Model Configuration | Features | Accuracy | Precision | Recall | F1-Score |
|---|---|---|---|---|---|
| URL-only RF Model | 22 | ~95.0% | ~94.8% | ~95.6% | ~95.2% |
| Full RF Model (with HTML) | 50 | ~96.0% | ~95.9% | ~96.1% | ~96.0% |

The full model achieves a 1% gain by evaluating page-level structural properties (like form actions and script counts), which helps identify malicious pages hosted on arbitrary domains.

### System Performance & Processing Times

| Processing Phase | Method / Target | Average Execution Time |
|---|---|---|
| URL Analysis | Phase 1 (Heuristic / Whitelist) | < 50 ms |
| URL Analysis | Phase 3 (URL-only RF model) | < 200 ms |
| URL Analysis | Phase 2 (Scraping + Full RF) | 2.0 – 4.0 seconds |
| Email Analysis | Tier 1 (DistilBERT inference) | 1.0 – 3.0 seconds |
| Email Analysis | Tier 2 (TF-IDF LogReg model) | < 300 ms |
| QR Code Processing | OpenCV Decode + URL scan | < 500 ms + URL pipeline time |
| DNS Verification | Live DoH query (Cloudflare) | 200 – 400 ms |
| DNS Verification | Cache hit | < 10 ms |

### False Positive Mitigation
Layered overrides prevent trusted sites from being flagged:
1. **Academic/Gov Trust:** Automatic legitimacy for `.edu.pk` and `.gov.pk` domains.
2. **Reputation Database:** Pre-trusted domains bypass ML unless suspicious path directories are matched.
3. **Email Heuristic Adjustment:** Emails flagged by DistilBERT are overridden to legitimate if they contain no links, no urgency words, no credit-card matching patterns, and no suspicious sender domains.

---
# CHAPTER 6: CONCLUSION AND DISCUSSION

## Limitations and Future Work
* **Limitations:**
  1. *Resource Constraints:* Running DistilBERT requires ~2GB RAM and PyTorch, which is resource-intensive for standard server hosting without GPU.
  2. *Image-based Phishing:* The email scanner cannot process text embedded within image attachments (requires OCR).
  3. *Static ML Models:* The Random Forest models are static; they require periodic manual retraining to adapt to new phishing tactics.
  4. *Language Support:* Deep Scan is configured only for English language URLs and email texts.
* **Future Work:**
  1. *Optical Character Recognition (OCR):* Integrate OCR engines (like Tesseract) to parse text in email attachment screenshots.
  2. *Continuous Learning:* Implement a feedback system allowing users to report misclassifications, saving new URLs to a pipeline for auto-retraining.
  3. *Multilingual Support:* Expand the NLP tokenizers to check regional languages.
  4. *Advanced QR Decoding:* Use ZXing to handle skewed, blurry, or low-resolution QR codes.

## Reasons for Failure – If Any
The project completed all core objectives without major structural failures. The team encountered minor integration challenges:
* *HTML Scraping Blocking:* Many target pages block automated scraping requests or return HTTP 403 errors. The system mitigates this by catching scraper exceptions and falling back to Phase 3 (URL-only ML).
* *WHOIS Timeout:* WHOIS servers sometimes limit request rates or timeout. This is handled by caching query results in `whois_cache.json` and skipping domain age checks if the query fails.

---
# REFERENCES

* [1] Kalla, D., & Kuraku, S. (2023). Phishing website URL's detection using NLP and machine learning techniques. *Journal on Artificial Intelligence*, 5(1), 145–162.
* [2] Lingaiah, G., & Pandey, R. K. (2023). Comparative performance study of machine learning algorithms for phishing URL detection in cyber security systems. *Journal of Computational Analysis and Applications*, 31(4), 1865–1873.
* [3] Sahingoz, O. K., Buber, E., Demir, O., & Diri, B. (2019). Machine learning based phishing detection from URLs. *Expert Systems with Applications*, 117, 345-357.
* [4] Tsai, E., Kumar, D., Raman, R. S., Li, G., Eiger, Y., & Ensafi, R. (2023). CERTainty: Detecting DNS manipulation at scale using TLS/SSL certificates. *Proceedings on Privacy Enhancing Technologies*, 2023(3), 122–137.
* [5] Devlin, J., Chang, M., Lee, K., & Toutanova, K. (2019). BERT: Pre-training of deep bidirectional transformers for language understanding. *Proceedings of NAACL-HLT*, 4171–4186.
* [6] Sanh, V., Debut, L., Chaumond, J., & Wolf, T. (2019). DistilBERT, a distilled version of BERT: smaller, faster, cheaper and lighter. *arXiv preprint arXiv:1910.01108*.
* [7] Breiman, L. (2001). Random forests. *Machine Learning*, 45, 5–32.
* [8] PhiUSIIL URL Dataset. Kaggle. Available: https://www.kaggle.com/datasets/harisudhan411/phishing-and-legitimate-urls
* [9] CEAS 2008 Email Spam Filtering Challenge Corpus. Available: https://plg.uwaterloo.ca/~gvcormac/ceascorpus/
* [10] Enron Email Dataset. Carnegie Mellon University. Available: https://www.cs.cmu.edu/~enron/

---
# A1A. PROJECT PROPOSAL AND VISION DOCUMENT

## 1. Introduction
Phishing attacks are simple but highly destructive. Attackers continually adapt their vectors, using email phishing, typosquatted URLs, and QR codes (quishing). Deep Scan provides a single, unified, open platform that validates all three channels using machine learning, transformer models, and real-time DNS audits.

### 1.1 Problem Statement
1. Security tools are fragmented: users must switch between multiple scanning portals.
2. Rule-based word lists are easily bypassed by rephrasing email texts.
3. QR codes bypass basic text parsers entirely, hiding malicious links.
4. Many detection models generate high false alarms, frustrating users.
5. Systems ignore domain infrastructure indicators (like missing MX records or brand typosquatting).

### 1.2 Project Motivation
The motivation was to build a multi-channel phishing scanner that addresses modern phishing channels (like quishing) while maintaining low false-alarm rates through multi-layer verification (ML, DNS, whitelists, WHOIS).

### 1.3 Objectives
* Create a single, responsive portal for URL, Email, and QR scanning.
* Achieve 95%+ accuracy using Random Forest classifiers on the PhiUSIIL dataset.
* Deploy DistilBERT to capture the contextual tone of suspicious emails.
* Decode and analyze QR codes in real-time.
* Integrate live DNS MX, SPF, and DMARC verification.
* Deliver browser-level protection via a Manifest V3 Chrome extension.

### 1.4 Literature Review
Refer to Chapter 3 for a comprehensive Literature Review.

---

## 2. Project Vision

### 2.1 Business Case and SWOT Analysis
Deep Scan addresses a global problem. Phishing is responsible for massive corporate and personal losses. Deep Scan offers an accessible, free portal for unified cyber-defense.

**SWOT Analysis:**

* **Strengths:** Multi-channel scanning, DistilBERT context parsing, DNS record audits, low false positive overrides.
* **Weaknesses:** Model training requires manual updates, scraping requires active network connection.
* **Opportunities:** Potential extension to mobile apps (Android/iOS), integration into email gateways.
* **Threats:** Attackers changing techniques, large browser vendors rolling out native scanning engines.

### 2.2 Background, Business Opportunity, and Customer Needs
Phishing is the entry point for most ransomware and data breaches. Businesses need a quick tool for employees to verify links and files. Customers require a fast, clean scanner that works on links, emails, and QR graphics without requiring technical expertise.

### 2.3 Business Objectives and Success Criteria
* **Accuracy:** Random Forest models meeting ~95% classification accuracy on test sets.
* **Speed:** URL check times under 200ms for URL-only evaluations.
* **In-Browser Scan:** Chrome extension actively intercepting tabs and alerting on threats.

### 2.4 Project Risks and Risk Mitigation Plan
* *Scraper Failure:* Mitigation: Catch scraping exceptions and fall back to the 22-feature URL-only classifier.
* *Resource Starvation:* Mitigation: Build three-tier email waterfall (DistilBERT → TF-IDF LogReg → Rule heuristics) so the app runs even on low-RAM servers.
* *API Timeout:* Mitigation: Implement a strict 2.5s timeout on network scrapes and a 3s socket limit on WHOIS queries.

### 2.5 Assumptions and Dependencies
* The client machine has internet access to execute live WHOIS and DoH requests.
* The local Flask API server is accessible on port 5000.
* Chrome extension loaded with unpacked developer permissions.

---

## 3. Project Scope

### 3.1 In Scope
* 3-Phase URL predictor (Lexical distance, Whitelist, ML Models, WHOIS).
* Email body text analysis using DistilBERT and TF-IDF.
* Real-time DNS MX, SPF, DMARC verifications.
* OpenCV QR code extraction.
* SSL certificate verification.
* Batch URL check (up to 100 URLs).
* Chrome extension and 4-tab dashboard UI.

### 3.2 Out of Scope
* Automatic retraining from live user logs.
* Scanning other attachments (like PDFs, EXE binaries).
* Support for non-Chrome browsers.
* Multilingual mail translation.

---

## 4. Proposed Methodology

### 4.1 SDLC Approach
Agile methodology using 2-week sprints. Deliverables were tested, audited, and merged into the main branch iteratively.

### 4.2 Team Role & Responsibilities
* **Mir Balach Kamal (Team Lead):** URL classification pipeline, model training, Flask integration.
* **Abdul Wahab Imran:** Flask API, QR code scanning, SSL certificate checking.
* **Ghulam Mustafa:** NLP model development, email scanner, DNS verifier.
* **Prince Laksh:** Chrome extension, HTML/CSS frontend dashboard.

### 4.3 Requirement Development
System requirements were mapped from functional expectations and user feedback during sprints.

### 4.4 High-Level Architecture / Design
Refer to Chapter 4 for architectural diagrams and pipeline states.

### 4.6 Application Testing
Conducted unit testing on feature extraction, validation testing on test datasets, and manual verification using active phishing links.

---

## 5. Project Planning

### 5.1 Gantt Chart
* **Phase I (FYP-1):** Research, URL model training, simple API, baseline HTML page.
* **Phase II (FYP-2):** DistilBERT training, DNS audits, WHOIS caching, QR scanning, Chrome extension, UI update.

---

## 6. Project Requirements

### 6.1 Software Tools Requirements
Python, Flask, scikit-learn, PyTorch, Transformers (HuggingFace), OpenCV, pandas, NLTK, BeautifulSoup, requests, Chrome Developer Tools.

### 6.2 Hardware Requirements
* CPU: Dual Core 2.0 GHz or higher.
* RAM: 4 GB minimum (8 GB recommended for DistilBERT).
* Disk Space: 5 GB for libraries and pre-trained weights.

---

## 7. Budget / Costing

### 7.1 Budget Items
All system dependencies, datasets, and frameworks are open-source.
* Datasets (PhiUSIIL, CEAS_08, Enron): Free.
* Model Weights (DistilBERT): Free.
* IDE & Libraries: Free.

### 7.2 Estimated Budgeted Cost
* **Total Cost: PKR 0** (No licensing or hardware procurement required).

---

## 8. Project Deliverables

* **Phase I:** Alpha prototype containing a single URL classifier and basic HTML interface.
* **Phase II:** Beta prototype with email TF-IDF classification and a Chrome extension popup.
* **Phase III:** Integrated Release Candidate with DistilBERT, DNS verification, and WHOIS caching.
* **Phase IV:** Final Product containing QR code decoding, batch processing, and complete responsive UI.

---

## 9. Proposed GUI (Disposable Prototype)
The interface is a dark-theme, grid-based dashboard with:
* Tab 1: Single URL scan input.
* Tab 2: Email text inputs (subject, sender, body) and result logs.
* Tab 3: QR Image Drag-and-Drop and Example triggers.
* Tab 4: Batch URL scanning text area.

---

## 10. Meetings Held with Supervisor and/or Client
Weekly progress reviews with Mr. Wajahat, discussing accuracy improvements, false-positive override rules, and extension integration.

---

## 11. References
See main References section.

---
# A2. REQUIREMENT SPECIFICATIONS

## 1. Introduction

### 1.1 Purpose of Document
This document lists the official functional, non-functional, and interface requirements for Deep Scan.

### 1.2 Intended Audience
Developers, supervisors, and evaluation jury members.

### 1.3 Abbreviations
* **DoH:** DNS over HTTPS.
* **MX:** Mail Exchange.
* **SPF:** Sender Policy Framework.
* **DMARC:** Domain-based Message Authentication.
* **CORS:** Cross-Origin Resource Sharing.

---

## 2. Overall System Description

### 2.1 Project Background
Deep Scan was initiated to protect end-users from social engineering campaigns (URL, email, QR codes) through a responsive web app and browser extension.

### 2.2 Project Scope
Includes the backend REST API, model files, DNS querying scripts, OpenCV scanner, and Chrome extension.

### 2.3 Not In Scope
Database storage for user inputs, automated model retraining, and non-English text support.

### 2.4 Project Objectives
* URL accuracy of ~95% or higher.
* Under 5-second response time for live page analysis.
* Automatic fallback layers to ensure continuous service.

### 2.5 Stakeholders
* End-users, developers, supervisor, university coordinators.

### 2.6 Operating Environment
Python 3.8+ runtime on host OS. Chrome version 88+ for the browser extension.

### 2.7 System Constraints
* Live checks (DoH, WHOIS, scraping) require an active internet connection.
* DistilBERT is CPU/RAM intensive.

### 2.8 Assumptions & Dependencies
* Host system has standard security configurations.
* HuggingFace Hub is accessible during first startup to pull model weights.

---

## 3. External Interface Requirements

### 3.1 Hardware Interfaces
Standard PC with network access interface (Ethernet/WiFi).

### 3.2 Software Interfaces
* Python runtime libraries (Flask, scikit-learn, OpenCV).
* Cloudflare and Google DoH JSON APIs.

### 3.3 Communications Interfaces
* HTTP REST API endpoints communicating via JSON format.

---

## 4. Functional Requirements

### 4.1 Functional Hierarchy
Refer to Chapter 4 (Hierarchy Section).

### 4.2 Use Cases

#### 4.2.1 URL Prediction
* **Input:** URL String.
* **Process:** Checks Whitelist → Checks Typosquatting → Checks WHOIS cache → If unknown, extracts features → Feeds to ML classifier.
* **Output:** JSON body containing classification verdict and confidence percentage.

#### 4.2.2 Email Prediction
* **Input:** Sender, Subject, Body text, Links.
* **Process:** Text passed to DistilBERT. Sender verified via typosquatting, whitelist, and DoH (MX, SPF, DMARC). Links verified via URL pipeline.
* **Output:** Integrated report detailing body threat, sender integrity, and link safety.

#### 4.2.3 QR Code Analysis
* **Input:** QR Image.
* **Process:** Imagedecoded using OpenCV. Extracted URL sent through URL pipeline.
* **Output:** Decoded link and URL prediction details.

---

## 5. Non-Functional Requirements

### 5.1 Performance Requirements
* URL-only prediction time: < 200ms.
* API response under network timeouts: < 5.0 seconds.

### 5.2 Safety Requirements
* The system does not save user data, inputs, or decoded graphics to disk.

### 5.3 Security Requirements
* Backend controls traffic origins via Flask CORS permissions.

### 5.4 User Documentation
* Dashboard features tooltips and instructions for all scanning tabs.

---

## 6. References
See main References section.

---
# A3. DESIGN SPECIFICATIONS

## 1. Introduction

### 1.1 Purpose of Document
This document defines the system-level design, software architecture, data structures, and sequence behaviors.

### 1.2 Intended Audience
System architects, backend developers, and reviewers.

### 1.3 Project Overview
Deep Scan is a multi-modal security platform. It uses a Python Flask backend serving ML/NLP predictions to a web client and a Chrome extension.

### 1.4 Scope
Covers software structure, data layout, and process state flows.

---

## 2. Design Considerations

### 2.1 Assumptions and Dependencies
* Pre-trained ML classifiers are saved as pickeled `.pkl` structures and loaded on startup.
* The API runs locally on localhost.

### 2.2 Risks and Volatile Areas
* Scraping target sites can trigger IP bans. The system uses a short request timeout and falls back to URL-only checks.

---

## 3. System Architecture

### 3.1 System Level Architecture
The application runs as a three-tier system:
1. **Presentation (Client):** Single-page web dashboard and Chrome browser extension popup.
2. **Controller (Flask API):** Receives HTTP requests, validates syntax, schedules checks.
3. **Engine (Models & Scripts):** Predicts classification via Random Forest, DistilBERT, DNS checks, and OpenCV.

### 3.2 Software Architecture
Refer to Chapter 3 (Software Architecture Structure).

---

## 4. Design Strategy
The design strategy prioritizes **high speed, reliability, and modularity**:
* **Waterfall Fallbacks:** If heavy deep-learning dependencies are missing, the system uses TF-IDF or rule-based heuristics.
* **Early Stops:** Clear-cut targets (typosquatted brands, educational domains) are processed instantly in Phase 1, saving compute cycles.

---

## 5. Detailed System Design

### 5.1 Database Design (Flat File Cache)
Deep Scan uses structured files instead of a relational database:
* **whois_cache.json:** Key-value store of registered domains and creation dates.
* **top_domains.txt:** Cached popular domains.
* **Model Files (`.pkl`):** Serialized StandardScaler and Random Forest estimators.

#### 5.1.2 Data Dictionary

##### Data 1: `whois_cache.json`
* `domain` (String): The registered domain name.
* `creation_date` (String): YYYY-MM-DD registration timestamp.
* `success` (Boolean): True if registrar query was parsed successfully.

##### Data 2: `reputation_db.bin`
* Gzip-compressed list of known safe domains.

---

### 5.2 Application Design

#### 5.2.1 Sequence Diagrams

##### URL Inspection Flow
1. Client submits URL string.
2. API validates schema (adds https if needed).
3. predictor matches domain against whitelist and brand typosquatting checks.
4. If clean, returns legitimate (confidence 98%).
5. If unknown, checks WHOIS cache.
6. If cache miss, queries WHOIS server.
7. System extracts 22 URL features.
8. Scraper tries to fetch HTML.
9. If successful, extracts 28 page features and runs 50-feature Random Forest.
10. If failed, runs 22-feature URL-only Random Forest.
11. API parses confidence and returns JSON response.

##### Email Audit Flow
1. Client submits email fields (sender, subject, body, links).
2. API runs text classifier (DistilBERT or TF-IDF LogReg).
3. Sender domain extracted from email address.
4. Typosquatting checks match domain against brand database.
5. DNS Verifier queries Cloudflare/Google DoH for MX, SPF, DMARC records.
6. If MX records are missing, sender is marked suspicious.
7. Body links processed through URL pipeline.
8. Verdict engine evaluates combined risks and returns JSON response.

##### QR Code Extraction Flow
1. User uploads image file.
2. Flask reads raw bytes into memory buffer.
3. cv2.imdecode decodes buffer into image.
4. cv2.QRCodeDetector scans and extracts text.
5. Normalized URL passed directly to URL inspection flow.

---

#### 5.2.2 State Diagrams

##### URL Pipeline States
```
[Start Check] -> [Phase 1: Brand Typosquatting Match?]
                      |
                      +- Yes -> [Phishing (99%)]
                      +- No  -> [Domain Whitelist Check?]
                                    |
                                    +- Yes -> [Legitimate (98%)]
                                    +- No  -> [WHOIS age > 1 year?]
                                                  |
                                                  +- Yes -> [Legitimate (95%)]
                                                  +- No  -> [HTML Scrape Success?]
                                                                |
                                                                +- Yes -> [50-Feature Model]
                                                                +- No  -> [22-Feature Model]
```

---

## 6. References
See main References section.

---
# A4. OTHER TECHNICAL DETAIL DOCUMENTS

## Test Cases Document
Refer to Chapter 5 (Test Cases Section) for a full test case catalog.

## UI/UX Detail Document
* Cyber-punk dark palette with contrasting alerts.
* Interactive progress bars displaying threat confidence.
* Instant test templates for quick evaluation.

## Coding Standards Document
* Variable naming matches functional properties.
* Docstrings on all classes, methods, and endpoints.
* Graceful try-except wrap for all remote network calls.

## Project Policy Document
* User inputs are scanned strictly in memory and never logged to disk.
* Privacy-safe DoH calls prevent ISP tracking.

---
---

# A10. RESEARCH PAPER

The complete IEEE-format Research Paper is located in the project's documentation folder as a standalone file at `documentation/FYP_Research_Paper_IEEE.md`.

---
