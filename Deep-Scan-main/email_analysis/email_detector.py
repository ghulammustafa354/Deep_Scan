import re
import os
import sys
import pickle
import logging
import nltk
import numpy as np
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer
from textblob import TextBlob

try:
    nltk.data.find('tokenizers/punkt')
except Exception:
    try:
        nltk.download('punkt', quiet=True)
    except Exception:
        pass

try:
    nltk.data.find('corpora/stopwords')
except Exception:
    try:
        nltk.download('stopwords', quiet=True)
    except Exception:
        pass

try:
    nltk.data.find('tokenizers/punkt_tab')
except Exception:
    try:
        nltk.download('punkt_tab', quiet=True)
    except Exception:
        pass

logging.basicConfig(level=logging.INFO)

MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'saved_models', 'email_phishing_model.pkl')


class EmailPhishingDetector:
    # DistilBERT label mapping
    _PHISHING_LABELS = {'phishing_url', 'phishing_url_alt'}
    _LEGIT_LABELS    = {'legitimate_email', 'legitimate_url'}

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.stemmer = PorterStemmer()
        self.stop_words = set(stopwords.words('english'))
        self.ml_model = None
        self.distilbert = None
        self.distilbert_tokenizer = None
        self.trusted_domain_whitelist = {
            'google.com', 'gmail.com', 'googlemail.com', 'myaccount.google.com',
            'linkedin.com', 'snapchat.com', 'canva.com', 'foodpanda.pk', 'foodpanda.com',
            'easypaisa.com.pk', 'easypaisa.com', 'sadapay.pk', 'sadapay.com', 'sadapay.com.pk',
            'outfitters.com.pk', 'outfitters.com', 'quora.com', 'datacamp.com',
            'github.com', 'microsoft.com', 'outlook.com', 'hotmail.com', 'live.com',
            'apple.com', 'icloud.com', 'facebook.com', 'instagram.com', 'netflix.com',
            'spotify.com', 'zoom.us', 'slack.com', 'paypal.com', 'amazon.com',
            'use.ai', 'coursera.org', 'supercell.com'
        }
        try:
            root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            db_path = os.path.join(root_dir, 'models', 'saved_models', 'reputation_db.bin')
            if os.path.exists(db_path):
                import gzip
                import json
                with gzip.open(db_path, 'rt', encoding='utf-8') as f:
                    loaded_domains = json.load(f)
                    for d in loaded_domains:
                        self.trusted_domain_whitelist.add(d)
        except Exception as e:
            self.logger.warning(f"Could not load reputation database: {e}")

        # Tier 1: DistilBERT
        try:
            from transformers import AutoTokenizer, AutoModelForSequenceClassification
            import torch
            _MODEL = 'cybersectony/phishing-email-detection-distilbert_v2.1'
            self.distilbert_tokenizer = AutoTokenizer.from_pretrained(_MODEL)
            self.distilbert_model     = AutoModelForSequenceClassification.from_pretrained(_MODEL)
            self.distilbert_model.eval()
            self.distilbert = True
            self.logger.info("DistilBERT phishing model loaded")
        except Exception as e:
            self.logger.warning(f"DistilBERT not available, falling back: {e}")

        # Tier 2: TF-IDF ML model
        if os.path.exists(MODEL_PATH):
            try:
                with open(MODEL_PATH, 'rb') as f:
                    self.ml_model = pickle.load(f)
                self.logger.info("ML email model loaded successfully")
            except Exception as e:
                self.logger.warning(f"Could not load ML model, falling back to rule-based: {e}")

        # Rule-based fallback config
        self.phishing_keywords = [
            'urgent', 'immediate', 'verify', 'suspend', 'click here', 'act now',
            'limited time', 'expire', 'confirm', 'update', 'security alert',
            'account locked', 'unauthorized', 'winner', 'congratulations',
            'free', 'prize', 'lottery', 'inheritance', 'million', 'dollars'
        ]
        self.suspicious_patterns = [
            r'\b\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}\b',
            r'\b\d{3}[-\s]\d{2}[-\s]\d{4}\b',
            r'password\s*[:=]\s*\w+',
            r'pin\s*[:=]\s*\d+',
        ]
        self.top_domains = set()
        self._load_top_domains()

    def _clean_text(self, text):
        if not isinstance(text, str):
            return ''
        text = re.sub(r'<[^>]+>', ' ', text)
        text = re.sub(r'http\S+', ' URL ', text)
        text = re.sub(r'\S+@\S+', ' EMAIL ', text)
        text = re.sub(r'[^a-zA-Z\s]', ' ', text)
        text = re.sub(r'\s+', ' ', text).strip().lower()
        return text

    def _distilbert_predict(self, content, subject):
        import torch
        text = f"{subject} {content}".strip()
        inputs = self.distilbert_tokenizer(
            text, return_tensors='pt', truncation=True, max_length=512
        )
        with torch.no_grad():
            logits = self.distilbert_model(**inputs).logits
            probs  = torch.nn.functional.softmax(logits, dim=-1)[0].tolist()

        labels = {
            'legitimate_email': probs[0],
            'phishing_url':     probs[1],
            'legitimate_url':   probs[2],
            'phishing_url_alt': probs[3]
        }
        top_label = max(labels, key=labels.get)
        is_phishing = top_label in self._PHISHING_LABELS

        phishing_prob = round(probs[1] + probs[3], 3)          # sum of phishing labels
        legit_prob    = round(1 - phishing_prob, 3)
        confidence    = round(labels[top_label], 3)

        return {
            'prediction': 'Phishing' if is_phishing else 'Legitimate',
            'confidence': confidence,
            'probabilities': {'phishing': phishing_prob, 'legitimate': legit_prob},
            'risk_score': round(phishing_prob * 100),
            'method': 'distilbert'
        }

    def _ml_predict(self, content, subject):
        combined = self._clean_text(subject) + ' ' + self._clean_text(content)
        if isinstance(self.ml_model, dict):
            vectorizer = self.ml_model['vectorizer']
            classifier = self.ml_model['model']
            features = vectorizer.transform([combined])
            proba = classifier.predict_proba(features)[0]
        else:
            proba = self.ml_model.predict_proba([combined])[0]
        # pipeline label order: 0=Legitimate, 1=Phishing
        phishing_prob = float(proba[1])
        legit_prob = float(proba[0])
        prediction = 'Phishing' if phishing_prob > 0.5 else 'Legitimate'
        confidence = phishing_prob if prediction == 'Phishing' else legit_prob
        return {
            'prediction': prediction,
            'confidence': round(confidence, 3),
            'probabilities': {
                'phishing': round(phishing_prob, 3),
                'legitimate': round(legit_prob, 3)
            },
            'risk_score': round(phishing_prob * 100),
            'method': 'ml_tfidf_logreg'
        }

    def _rule_based_predict(self, content, subject):
        score = 0
        content_lower = content.lower()

        keyword_hits = sum(1 for kw in self.phishing_keywords if kw in content_lower)
        pattern_hits = sum(1 for p in self.suspicious_patterns if re.search(p, content))
        urgency_hits = sum(1 for w in ['urgent', 'immediate', 'asap', 'quickly', 'hurry', 'deadline'] if w in content_lower)
        caps_ratio = sum(1 for c in content if c.isupper()) / max(len(content), 1)
        url_count = len(re.findall(r'http[s]?://', content))
        has_short_url = int(any(d in content_lower for d in ['bit.ly', 'tinyurl', 't.co']))
        excl_count = content.count('!')

        if keyword_hits >= 2: score += 40
        elif keyword_hits >= 1: score += 20
        if pattern_hits > 0: score += 30
        if urgency_hits >= 1: score += 25
        if caps_ratio > 0.2: score += 20
        if excl_count >= 2: score += 15
        if has_short_url: score += 20
        if url_count >= 1: score += 15

        phishing_prob = min(score / 100.0, 1.0)
        legit_prob = 1 - phishing_prob
        prediction = 'Phishing' if phishing_prob > 0.5 else 'Legitimate'
        confidence = phishing_prob if prediction == 'Phishing' else legit_prob

        return {
            'prediction': prediction,
            'confidence': round(confidence, 3),
            'probabilities': {
                'phishing': round(phishing_prob, 3),
                'legitimate': round(legit_prob, 3)
            },
            'risk_score': score,
            'method': 'rule_based_nlp'
        }

    def analyze_email(self, email_content, subject="", sender="", skip_dns=False, use_hybrid_speedup=False):
        # Convert subject and sender to strings in case they are Header objects from mailbox parsing
        subject = str(subject) if subject is not None else ""
        sender = str(sender) if sender is not None else ""
        try:
            if self.distilbert:
                if use_hybrid_speedup and self.ml_model is not None:
                    # Run fast TF-IDF model first
                    ml_res = self._ml_predict(email_content, subject)
                    # If high-confidence legitimate, skip the heavy DistilBERT model
                    if ml_res['prediction'] == 'Legitimate' and ml_res['probabilities']['legitimate'] >= 0.9:
                        result = ml_res
                        result['method'] = 'ml_tfidf_logreg_fast'
                    else:
                        result = self._distilbert_predict(email_content, subject)
                        result['method'] = 'distilbert_verified'
                else:
                    result = self._distilbert_predict(email_content, subject)
            elif self.ml_model is not None:
                result = self._ml_predict(email_content, subject)
            else:
                result = self._rule_based_predict(email_content, subject)

            # Heuristic adjustment to avoid false positives for purely transactional/informational emails
            if result['prediction'] == 'Phishing':
                combined_lower = f"{subject} {email_content}".lower()
                has_links = bool(re.search(r'https?://|www\.', combined_lower))
                has_email_link = bool(re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', combined_lower))
                
                # Check for urgency words or common call-to-actions
                urgency_words = ['urgent', 'immediate', 'asap', 'quickly', 'hurry', 'deadline', 'suspend', 'lock', 'unauthorized', 'verify', 'confirm', 'update', 'action required']
                has_urgency = any(w in combined_lower for w in urgency_words)
                
                # Check for suspicious patterns
                pattern_hits = sum(1 for p in self.suspicious_patterns if re.search(p, email_content))
                
                # If there are no links, no emails, no urgency, and no suspicious patterns, override to Legitimate
                if not has_links and not has_email_link and not has_urgency and pattern_hits == 0:
                    self.logger.info("Heuristic adjustment: No links, email links, urgency, or suspicious patterns detected. Overriding prediction to Legitimate.")
                    result['prediction'] = 'Legitimate'
                    result['confidence'] = 0.95
                    result['probabilities'] = {'phishing': 0.05, 'legitimate': 0.95}
                    result['risk_score'] = 5
                    result['method'] = f"{result['method']}_with_heuristic_override"

            # Parse sender email and check domain typosquatting
            sender_analysis = {
                'is_suspicious': False,
                'matched_brand': None,
                'reason': None,
                'is_official_brand': False
            }
            
            email_addr = sender.strip()
            # Extract email if format is Name <email@domain.com>
            email_match = re.search(r'<([^>]+)>', sender)
            if email_match:
                email_addr = email_match.group(1).strip()
            
            if email_addr and '@' in email_addr:
                sender_analysis['is_official_brand'] = self._is_official_brand_domain(email_addr)
                is_susp, matched_brand, reason = self._check_domain_typosquatting(email_addr)
                if is_susp:
                    sender_analysis['is_suspicious'] = True
                    sender_analysis['matched_brand'] = matched_brand
                    sender_analysis['reason'] = reason
                    
                    # Override to Phishing if sender is suspicious
                    result['prediction'] = 'Phishing'
                    result['confidence'] = 0.99
                    result['probabilities'] = {'phishing': 0.99, 'legitimate': 0.01}
                    result['risk_score'] = 100
                    result['method'] = 'domain_typosquatting_check'
                else:
                    # NOT typosquatting. Let's check if the domain is on the trusted whitelist!
                    if self._is_whitelisted_trusted_domain(email_addr):
                        sender_analysis['is_official_brand'] = True
                        if result['prediction'] == 'Phishing':
                            self.logger.info(f"Trusted Sender Override: email from {email_addr} is whitelisted. Overriding prediction from Phishing to Legitimate.")
                            result['prediction'] = 'Legitimate'
                            result['confidence'] = 0.98
                            result['probabilities'] = {'phishing': 0.02, 'legitimate': 0.98}
                            result['risk_score'] = 2
                            result['method'] = f"{result['method']}_with_trusted_sender_override"
                    sender_analysis['dns_verification'] = None
                    if not skip_dns:
                        # Run dynamic DNS verification check
                        try:
                            domain = email_addr.split('@')[-1].lower().strip()
                            sys.path.append(os.path.dirname(__file__))
                            from dns_verifier import verify_sender_domain
                            dns_res = verify_sender_domain(domain)
                            sender_analysis['dns_verification'] = {
                                'has_mx': dns_res['has_mx'],
                                'has_spf': dns_res['has_spf'],
                                'has_dmarc': dns_res['has_dmarc'],
                                'dmarc_policy': dns_res['dmarc_policy']
                            }
                            # If a domain has no MX records, it is highly likely a throwaway email spoofing channel
                            if not dns_res['has_mx'] and not dns_res.get('query_failed') and not sender_analysis.get('is_official_brand'):
                                sender_analysis['is_suspicious'] = True
                                sender_analysis['reason'] = f"Sender domain '{domain}' has no valid DNS MX records (cannot receive mail)."
                                result['prediction'] = 'Phishing'
                                result['confidence'] = 0.99
                                result['probabilities'] = {'phishing': 0.99, 'legitimate': 0.01}
                                result['risk_score'] = 100
                                result['method'] = 'dns_mx_check'
                        except Exception as e:
                            self.logger.error(f"DNS check exception occurred: {str(e)}", exc_info=True)
                            sender_analysis['dns_verification'] = None

            result['sender'] = sender
            result['subject'] = subject
            result['sender_analysis'] = sender_analysis
            self.logger.info(f"Email analysis: {result['prediction']} ({result['confidence']:.3f}) via {result['method']}")
            return result

        except Exception as e:
            self.logger.error(f"Error analyzing email: {str(e)}")
            return {
                'prediction': 'Error',
                'confidence': 0.0,
                'probabilities': {'phishing': 0.0, 'legitimate': 0.0},
                'risk_score': 0,
                'method': 'error',
                'error': str(e),
                'sender_analysis': {
                    'is_suspicious': False,
                    'matched_brand': None,
                    'reason': str(e)
                }
            }

    def _load_top_domains(self):
        """
        Load OpenDNS top 10k domains from local cache, or download it if missing.
        """
        cache_path = os.path.join(os.path.dirname(__file__), '..', 'models', 'top_domains.txt')
        self.top_domains = set()
        
        # Built-in auxiliary trusted platforms (gaming, developer tools, shorteners)
        aux_trusted = {
            'supercell.com', 'steampowered.com', 'steamcommunity.com', 'battle.net',
            'playstation.com', 'xbox.com', 'epicgames.com', 'ea.com', 'ubisoft.com',
            'riotgames.com', 'roblox.com', 'discordapp.com', 'zoom.us', 'slack.com',
            'openai.com', 'anthropic.com', 'huggingface.co', 'c.gle', 'amzn.to',
            'lnkd.in', 'fb.me', 't.co', 'bit.ly', 'github.com', 'githubusercontent.com',
            'gitlab.com', 'bitbucket.org', 'atlassian.com', 'salesforce.com',
            'adobe.com', 'oracle.com', 'ibm.com', 'zoom.com', 'dropbox.com',
            'box.com', 'wetransfer.com', 'sendspace.com', 'mediafire.com',
            'mega.nz', 'onedrive.com', 'boxcloud.com', 'scribd.com', 'slideshare.net',
            'snapchat.com', 'foodpanda.pk', 'foodpanda.com', 'forms.gle', 'docs.google.com'
        }
        self.top_domains.update(aux_trusted)
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        
        if not os.path.exists(cache_path):
            try:
                import urllib.request
                print("Downloading OpenDNS Top 10,000 legitimate domains list...")
                url = "https://raw.githubusercontent.com/opendns/public-domain-lists/master/opendns-top-domains.txt"
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=5) as response:
                    content = response.read().decode('utf-8')
                    with open(cache_path, 'w', encoding='utf-8') as f:
                        f.write(content)
            except Exception as e:
                pass
                
        if os.path.exists(cache_path):
            try:
                with open(cache_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        domain = line.strip().lower()
                        if domain:
                            self.top_domains.add(domain)
            except Exception as e:
                pass

    def _is_top_domain(self, domain):
        if not domain:
            return False
        domain = domain.lower().split(':')[0].strip()
        if domain in self.top_domains:
            return True
        domain_parts = domain.split('.')
        for i in range(len(domain_parts) - 1):
            parent = '.'.join(domain_parts[i:])
            if parent in self.top_domains:
                return True
        return False

    def _is_official_brand_domain(self, email_address):
        """
        Check if the sender's email domain is verified as an official brand domain.
        """
        if not email_address or '@' not in email_address:
            return False
            
        parts = email_address.split('@')
        domain = parts[-1].lower().strip()
        
        # Trust all global educational and government domains
        domain_parts = domain.split('.')
        if len(domain_parts) >= 2:
            if domain_parts[-1] in ('edu', 'gov'):
                return True
            elif len(domain_parts[-1]) == 2 and domain_parts[-2] in ('edu', 'gov', 'ac'):
                return True
                
        return self._is_top_domain(domain)

    def _is_whitelisted_trusted_domain(self, email_address):
        """
        Check if the sender's email domain is in our official trusted domains list.
        """
        if not email_address or '@' not in email_address:
            return False
        domain = email_address.split('@')[-1].lower().strip()
        
        # Check direct match or parent domain match in the whitelist
        if domain in self.trusted_domain_whitelist:
            return True
            
        domain_parts = domain.split('.')
        for i in range(len(domain_parts) - 1):
            parent = '.'.join(domain_parts[i:])
            if parent in self.trusted_domain_whitelist:
                return True
        return False

    def _check_domain_typosquatting(self, email_address):
        """
        Check if the sender's email domain is typosquatting a major brand.
        Returns: (is_suspicious, matched_brand, reason)
        """
        if not email_address or '@' not in email_address:
            return False, None, None
            
        parts = email_address.split('@')
        domain = parts[-1].lower().strip()
        
        # Official brand domains list
        brands = {
            'facebook': ['facebook.com', 'fb.com', 'facebookmail.com'],
            'instagram': ['instagram.com', 'mail.instagram.com'],
            'meta': ['meta.com', 'support.facebook.com'],
            'google': ['google.com', 'gmail.com', 'googlemail.com'],
            'microsoft': ['microsoft.com', 'outlook.com', 'hotmail.com', 'live.com', 'office.com', 'microsoftsupport.com'],
            'apple': ['apple.com', 'icloud.com'],
            'amazon': ['amazon.com', 'amazonmail.com'],
            'paypal': ['paypal.com', 'paypal-support.com', 'paypalmail.com'],
            'linkedin': ['linkedin.com'],
            'netflix': ['netflix.com'],
            'snapchat': ['snapchat.com'],
            'foodpanda': ['foodpanda.pk', 'foodpanda.com']
        }
        
        domain_parts = domain.split('.')
        if len(domain_parts) < 2:
            return False, None, None
            
        main_domain = domain_parts[-2] # e.g. "faceboook" in "faceboook.com" or "appple-support"
        
        # Helper to calculate Levenshtein distance
        def get_edit_distance(s1, s2):
            if len(s1) > len(s2):
                s1, s2 = s2, s1
            distances = range(len(s1) + 1)
            for i2, c2 in enumerate(s2):
                distances_ = [i2+1]
                for i1, c1 in enumerate(s1):
                    if c1 == c2:
                        distances_.append(distances[i1])
                    else:
                        distances_.append(1 + min((distances[i1], distances[i1 + 1], distances_[-1])))
                distances = distances_
            return distances[-1]

        # Check main domain and its hyphenated parts
        segments = [main_domain]
        if '-' in main_domain:
            segments.extend(main_domain.split('-'))
            
        # De-duplicate segments
        segments = list(set(segments))

        for segment in segments:
            # 1. Check for exact brand name inside segment but not matching official domain list
            for brand, officials in brands.items():
                if brand == segment or brand in segment:
                    is_official = False
                    for official in officials:
                        if domain == official or domain.endswith('.' + official):
                            is_official = True
                            break
                    if not is_official:
                        return True, brand, f"Sender domain '{domain}' contains '{brand}' but is not an official '{brand}' domain."

            # 2. Check for typosquatting (edit distance of segment is 1 or 2)
            for brand, officials in brands.items():
                dist = get_edit_distance(segment, brand)
                if 0 < dist <= 2:
                    is_official = False
                    for official in officials:
                        if domain == official or domain.endswith('.' + official):
                            is_official = True
                            break
                    if not is_official:
                        return True, brand, f"Sender domain '{domain}' segment '{segment}' appears to be a typo of '{brand}' (edit distance: {dist})."
                        
        return False, None, None

    def get_model_info(self):
        if self.distilbert:
            return {
                'model_type': 'DistilBERT (cybersectony/phishing-email-detection-distilbert_v2.1)',
                'version': '2.1.0',
                'accuracy': '97.72%',
                'f1_score': '97.72%',
                'method': 'distilbert'
            }
        if self.ml_model is not None:
            return {
                'model_type': 'TF-IDF + Logistic Regression (CEAS_08)',
                'version': '2.0.0',
                'accuracy': '~99.57%',
                'trained_on': 'CEAS_08 (39,154 emails)',
                'method': 'ml_tfidf_logreg'
            }
        return {
            'model_type': 'Rule-based NLP Email Detector',
            'version': '1.0.0',
            'accuracy': '~80-85%',
            'method': 'rule_based_nlp'
        }
