"""
============================================================================
DEEP_SCAN PREDICTION ENGINE (predict.py)
============================================================================

This file contains the HYBRID DETECTION ENGINE - the brain of the system!

Main Components:
1. URLFeatureExtractor - Extracts 50 features from URLs (URL + HTML web features)
2. URLPredictor - 3-phase hybrid detection (Rules + ML Full/URL models + Fallback)

============================================================================
"""

import sys
import os
import numpy as np
import pandas as pd
from urllib.parse import urlparse
import re
import requests
from bs4 import BeautifulSoup
import socket
import warnings
import joblib
warnings.filterwarnings('ignore')

class URLFeatureExtractor:
    """
    Extract 50 features from URLs for phishing detection
    Categories:
    1. Basic URL features (22 features)
    2. Web content features (28 features)
    """
    def __init__(self):
        self.timeout = 2.5
        
    def extract_url_features(self, url):
        """Extract all 22 URL structural features (computable purely from URL text)"""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        scheme_prefix = parsed_url.scheme + '://'
        url_no_scheme = url[len(scheme_prefix):]
        
        features = {}
        features['URLLength'] = len(url_no_scheme)
        features['Domain'] = domain
        features['DomainLength'] = len(domain)
        features['IsDomainIP'] = self._is_ip_address(domain)
        features['TLD'] = self._get_tld(domain)
        features['URLSimilarityIndex'] = self._calculate_similarity_index(url)
        features['CharContinuationRate'] = self._char_continuation_rate(url)
        features['TLDLegitimateProb'] = self._tld_legitimate_prob(features['TLD'])
        features['URLCharProb'] = self._url_char_prob(url)
        features['TLDLength'] = len(features['TLD']) if features['TLD'] else 0
        features['NoOfSubDomain'] = max(0, len(domain.split('.')) - 2)
        
        features['HasObfuscation'] = self._has_obfuscation(url_no_scheme)
        features['NoOfObfuscatedChar'] = self._count_obfuscated_chars(url_no_scheme)
        features['ObfuscationRatio'] = features['NoOfObfuscatedChar'] / len(url_no_scheme) if len(url_no_scheme) > 0 else 0
        
        features['NoOfLettersInURL'] = sum(c.isalpha() for c in url_no_scheme)
        features['LetterRatioInURL'] = features['NoOfLettersInURL'] / len(url_no_scheme) if len(url_no_scheme) > 0 else 0
        features['NoOfDegitsInURL'] = sum(c.isdigit() for c in url_no_scheme)
        features['DegitRatioInURL'] = features['NoOfDegitsInURL'] / len(url_no_scheme) if len(url_no_scheme) > 0 else 0
        
        features['NoOfEqualsInURL'] = url_no_scheme.count('=')
        features['NoOfQMarkInURL'] = url_no_scheme.count('?')
        features['NoOfAmpersandInURL'] = url_no_scheme.count('&')
        features['NoOfOtherSpecialCharsInURL'] = self._count_special_chars(url_no_scheme)
        features['SpacialCharRatioInURL'] = (features['NoOfEqualsInURL'] +
                                          features['NoOfQMarkInURL'] +
                                          features['NoOfAmpersandInURL'] +
                                          features['NoOfOtherSpecialCharsInURL']) / len(url_no_scheme) if len(url_no_scheme) > 0 else 0
        
        features['IsHTTPS'] = 1 if parsed_url.scheme == 'https' else 0
        
        return features

    def extract_web_features_from_html(self, url, response):
        """Extract 28 HTML/web content features from a fetched page response"""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        soup = BeautifulSoup(response.content, 'html.parser')
        text_content = response.text.lower()
        
        features = {}
        features['LineOfCode'] = len(response.text.split('\n'))
        features['LargestLineLength'] = max(len(line) for line in response.text.split('\n')) if response.text else 0
        
        title_tag = soup.find('title')
        title = title_tag.get_text() if title_tag else ''
        features['HasTitle'] = 1 if title else 0
        
        features['DomainTitleMatchScore'] = self._calculate_match_score(domain, title)
        features['URLTitleMatchScore'] = self._calculate_match_score(url, title)
        
        features['HasFavicon'] = 1 if soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon') else 0
        features['Robots'] = 1 if soup.find('meta', attrs={'name': 'robots'}) else 0
        features['IsResponsive'] = 1 if soup.find('meta', attrs={'name': 'viewport'}) else 0
        features['NoOfURLRedirect'] = len(response.history)
        
        features['NoOfSelfRedirect'] = sum(1 for a in soup.find_all('a', href=True) if a['href'] == url or a['href'] == parsed_url.path)
        features['HasDescription'] = 1 if soup.find('meta', attrs={'name': 'description'}) else 0
        
        # Obvious popup functions
        features['NoOfPopup'] = 1 if any(p in text_content for p in ['window.open(', 'alert(', 'confirm(']) else 0
        features['NoOfiFrame'] = len(soup.find_all('iframe'))
        
        # Forms and actions
        has_external_form = 0
        for form in soup.find_all('form', action=True):
            action = form['action'].strip()
            if action.startswith(('http://', 'https://')):
                action_domain = urlparse(action).netloc.lower()
                if action_domain != domain:
                    has_external_form = 1
                    break
        features['HasExternalFormSubmit'] = has_external_form
        
        features['HasSocialNet'] = 1 if any(social in text_content for social in ['facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com', 'youtube.com']) else 0
        features['HasSubmitButton'] = 1 if soup.find('input', type='submit') or soup.find('button', type='submit') or soup.find('button') else 0
        features['HasHiddenFields'] = 1 if soup.find('input', type='hidden') else 0
        features['HasPasswordField'] = 1 if soup.find('input', type='password') else 0
        
        features['Bank'] = 1 if any(word in text_content for word in ['bank', 'banking', 'account']) else 0
        features['Pay'] = 1 if any(word in text_content for word in ['payment', 'pay', 'paypal']) else 0
        features['Crypto'] = 1 if any(word in text_content for word in ['bitcoin', 'crypto', 'wallet']) else 0
        
        features['HasCopyrightInfo'] = 1 if any(term in text_content for term in ['copyright', '©', '&copy;', 'all rights reserved']) else 0
        features['NoOfImage'] = len(soup.find_all('img'))
        features['NoOfCSS'] = len(soup.find_all('link', rel='stylesheet'))
        features['NoOfJS'] = len(soup.find_all('script'))
        
        # Link analysis
        self_ref = 0
        empty_ref = 0
        ext_ref = 0
        for a in soup.find_all('a', href=True):
            href = a['href'].strip()
            if not href or href == '#' or href.lower().startswith('javascript:'):
                empty_ref += 1
            elif href.startswith(('http://', 'https://')):
                href_domain = urlparse(href).netloc.lower()
                if href_domain == domain or href_domain.endswith('.' + domain):
                    self_ref += 1
                else:
                    ext_ref += 1
            else:
                self_ref += 1
                
        features['NoOfSelfRef'] = self_ref
        features['NoOfEmptyRef'] = empty_ref
        features['NoOfExternalRef'] = ext_ref
        
        return features

    def _is_ip_address(self, domain):
        try:
            socket.inet_aton(domain)
            return 1
        except socket.error:
            return 0
            
    def _get_tld(self, domain):
        parts = domain.split('.')
        return parts[-1] if len(parts) > 1 else ''
        
    def _calculate_similarity_index(self, url):
        legitimate_domains = ['google', 'facebook', 'instagram', 'twitter', 'linkedin', 
                            'github', 'stackoverflow', 'wikipedia', 'amazon', 'microsoft', 
                            'apple', 'netflix', 'youtube']
        domain = urlparse(url).netloc.lower()
        
        for legit_domain in legitimate_domains:
            if legit_domain in domain:
                return 95.0
                
        phishing_combos = ['paypal-security', 'amazon-verify', 'microsoft-update', 'apple-secure', 'google-verify']
        for pattern in phishing_combos:
            if pattern in domain:
                return 20.0
                
        tld = domain.split('.')[-1] if '.' in domain else ''
        if tld in ['com', 'org', 'net', 'edu', 'gov']:
            return 70.0
        elif tld in ['tk', 'ml', 'ga', 'cf']:
            return 10.0
        return 50.0
        
    def _char_continuation_rate(self, url):
        if len(url) < 2:
            return 0
        continuations = 0
        for i in range(len(url) - 1):
            if url[i] == url[i + 1]:
                continuations += 1
        return continuations / (len(url) - 1)
        
    def _tld_legitimate_prob(self, tld):
        legitimate_tlds = {
            'com': 0.8, 'org': 0.7, 'net': 0.6, 'edu': 0.9, 'gov': 0.95,
            'co': 0.5, 'io': 0.4, 'ly': 0.3, 'tk': 0.1, 'ml': 0.1,
            'de': 0.8, 'uk': 0.8, 'ca': 0.8, 'fr': 0.8, 'au': 0.8, 'jp': 0.8,
            'pk': 0.8
        }
        return legitimate_tlds.get(tld, 0.3)
        
    def _url_char_prob(self, url):
        alpha_count = sum(c.isalpha() for c in url)
        return alpha_count / len(url) if len(url) > 0 else 0
        
    def _has_obfuscation(self, url):
        obfuscation_patterns = [
            r'%[0-9a-fA-F]{2}',
            r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',
            r'[a-zA-Z0-9]{20,}',
        ]
        for pattern in obfuscation_patterns:
            if re.search(pattern, url):
                return 1
        return 0
        
    def _count_obfuscated_chars(self, url):
        return len(re.findall(r'%[0-9a-fA-F]{2}', url))
        
    def _count_special_chars(self, url):
        standard = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/:-_~')
        return sum(1 for c in url if c not in standard)
        
    def _calculate_match_score(self, s1, s2):
        if not s1 or not s2:
            return 0.0
        s1_words = set(re.findall(r'\w+', s1.lower()))
        s2_words = set(re.findall(r'\w+', s2.lower()))
        if not s1_words:
            return 0.0
        overlap = s1_words.intersection(s2_words)
        return len(overlap) / len(s1_words) * 100.0


class URLPredictor:
    """Main predictor class loaded by Flask API"""
    def __init__(self, model_path='saved_models/'):
        self.model_url = None
        self.scaler_url = None
        self.model_full = None
        self.scaler_full = None
        self.feature_extractor = URLFeatureExtractor()
        
        self.feature_names_url = [
            'URLLength', 'DomainLength', 'IsDomainIP', 'URLSimilarityIndex', 
            'CharContinuationRate', 'TLDLegitimateProb', 'URLCharProb', 'TLDLength', 
            'NoOfSubDomain', 'HasObfuscation', 'NoOfObfuscatedChar', 'ObfuscationRatio',
            'NoOfLettersInURL', 'LetterRatioInURL', 'NoOfDegitsInURL', 'DegitRatioInURL',
            'NoOfEqualsInURL', 'NoOfQMarkInURL', 'NoOfAmpersandInURL',
            'NoOfOtherSpecialCharsInURL', 'SpacialCharRatioInURL', 'IsHTTPS'
        ]
        
        self.feature_names_full = self.feature_names_url + [
            'LineOfCode', 'LargestLineLength', 'HasTitle', 'DomainTitleMatchScore', 
            'URLTitleMatchScore', 'HasFavicon', 'Robots', 'IsResponsive', 
            'NoOfURLRedirect', 'NoOfSelfRedirect', 'HasDescription', 'NoOfPopup', 
            'NoOfiFrame', 'HasExternalFormSubmit', 'HasSocialNet', 'HasSubmitButton', 
            'HasHiddenFields', 'HasPasswordField', 'Bank', 'Pay', 'Crypto', 
            'HasCopyrightInfo', 'NoOfImage', 'NoOfCSS', 'NoOfJS', 'NoOfSelfRef', 
            'NoOfEmptyRef', 'NoOfExternalRef'
        ]
        
        possible_paths = [
            os.path.join(os.path.dirname(__file__), '..', 'models', model_path),
            os.path.join('models', model_path),
            os.path.join('..', 'models', model_path),
            model_path
        ]
        
        model_loaded = False
        for path in possible_paths:
            try:
                if os.path.exists(os.path.join(path, 'phishing_detector_url.pkl')):
                    self.model_url = joblib.load(os.path.join(path, 'phishing_detector_url.pkl'))
                    self.scaler_url = joblib.load(os.path.join(path, 'scaler_url.pkl'))
                    self.model_full = joblib.load(os.path.join(path, 'phishing_detector_full.pkl'))
                    self.scaler_full = joblib.load(os.path.join(path, 'scaler_full.pkl'))
                    print(f"[SUCCESS] Hybrid models loaded from: {path}")
                    model_loaded = True
                    break
            except Exception as e:
                continue
                
        self.brands = {
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
        self.top_domains = set()
        self._load_top_domains()
        
        if not model_loaded:
            print("[WARNING] ML models not found - falling back to rules only")
            
    def _load_top_domains(self):
        """
        Load OpenDNS top 10k domains from local cache, or download it if missing.
        """
        cache_path = os.path.join(os.path.dirname(__file__), '..', 'models', 'top_domains.txt')
        
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
            'snapchat.com', 'foodpanda.pk', 'foodpanda.com', 'forms.gle', 'docs.google.com',
            'uefa.com', 'fifa.com', 'olympics.com'
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
                print("[SUCCESS] Loaded and cached Top 10,000 domains list.")
            except Exception as e:
                print(f"[WARNING] Failed to download top domains list: {e}")
                
        if os.path.exists(cache_path):
            try:
                with open(cache_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        domain = line.strip().lower()
                        if domain:
                            self.top_domains.add(domain)
                print(f"[SUCCESS] Loaded {len(self.top_domains)} top domains from cache.")
            except Exception as e:
                print(f"[WARNING] Failed to read top domains cache: {e}")

    def _is_top_domain(self, domain):
        if not domain:
            return False
        domain = domain.lower().split(':')[0].strip()
        
        # Check exact match
        if domain in self.top_domains:
            return True
            
        # Check parent domains match (e.g. sub.google.com -> google.com)
        generic_parents = {
            'example.com', 'example.net', 'example.org',
            'github.io', 'web.app', 'amazonaws.com', 'cloudfront.net',
            'pages.dev', 'vercel.app', 'herokuapp.com', 'blogspot.com',
            'wordpress.com', 'firebaseapp.com', 'dyndns.org', 'no-ip.info',
            'wixsite.com', 'weebly.com', 'jimdofree.com'
        }
        
        domain_parts = domain.split('.')
        for i in range(len(domain_parts) - 1):
            parent = '.'.join(domain_parts[i:])
            if parent in generic_parents:
                continue # Do not trust subdomains of generic/dynamic hosts
                
            # If the subdomain prefix has suspicious keywords, do not trust it as a top domain
            subdomain_prefix = '.'.join(domain_parts[:i])
            suspicious_keywords = ['login', 'alert', 'auth', 'secure', 'verify', 'update', 'signin', 'banking', 'account', 'invoice', 'billing']
            is_suspicious = False
            for kw in suspicious_keywords:
                if kw in subdomain_prefix:
                    is_suspicious = True
                    break
            if is_suspicious:
                continue
                
            if parent in self.top_domains:
                return True
                
        return False
            
    def predict_url(self, url):
        """Predict URL: Rules -> Full Model (scraped HTML) -> URL-only Model (fallback)"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
                
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower().split(':')[0]
            
            # Phase 1: Rule-based check
            rule_result = self._rule_based_check(url, domain)
            if rule_result:
                rule_result['method'] = 'rule_based'
                return rule_result
                
            # Phase 2: Machine Learning Prediction
            extracted_features = {}
            web_success = False
            
            # Always extract URL-only features
            url_feats = self.feature_extractor.extract_url_features(url)
            extracted_features.update(url_feats)
            
            # Try to fetch webpage HTML if Full Model is loaded
            if self.model_full is not None:
                try:
                    headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    }
                    # 2.5s quick timeout to keep responses snappy
                    response = requests.get(url, timeout=2.5, verify=False, headers=headers)
                    if response.status_code == 200:
                        web_feats = self.feature_extractor.extract_web_features_from_html(url, response)
                        extracted_features.update(web_feats)
                        web_success = True
                except Exception as e:
                    print(f"Scraping failed for {url} ({e}) - Falling back to URL-only model")
            
            if web_success and self.model_full is not None:
                # Predict using Full 50-feature model
                vector = self._convert_to_vector(extracted_features, self.feature_names_full)
                scaled = self.scaler_full.transform(vector.reshape(1, -1))
                pred = self.model_full.predict(scaled)[0]
                prob = self.model_full.predict_proba(scaled)[0]
                return {
                    'prediction': 'Phishing' if pred == 0 else 'Legitimate',
                    'confidence': float(max(prob)),
                    'probabilities': {'phishing': float(prob[0]), 'legitimate': float(prob[1])},
                    'features_count': len(vector),
                    'method': 'full_model'
                }
            elif self.model_url is not None:
                # Predict using URL-only 22-feature model
                vector = self._convert_to_vector(extracted_features, self.feature_names_url)
                scaled = self.scaler_url.transform(vector.reshape(1, -1))
                pred = self.model_url.predict(scaled)[0]
                prob = self.model_url.predict_proba(scaled)[0]
                return {
                    'prediction': 'Phishing' if pred == 0 else 'Legitimate',
                    'confidence': float(max(prob)),
                    'probabilities': {'phishing': float(prob[0]), 'legitimate': float(prob[1])},
                    'features_count': len(vector),
                    'method': 'url_model'
                }
                
            # Phase 3: Fallback to enhanced rules
            return self._enhanced_rule_fallback(url, parsed_url, domain)
            
        except Exception as e:
            return {
                'prediction': 'Error',
                'confidence': 0.0,
                'probabilities': {'phishing': 0.5, 'legitimate': 0.5},
                'error': str(e),
                'method': 'error',
                'features_count': 0
            }
            
    def _check_domain_typosquatting(self, domain):
        """
        Check if the domain or its subdomains is typosquatting/spoofing a major brand.
        Returns: (is_suspicious, matched_brand, reason)
        """
        domain = domain.lower().split(':')[0].strip()
        
        try:
            from whois_helper import get_registered_domain
            reg_domain = get_registered_domain(domain)
        except Exception:
            reg_domain = domain
            
        reg_parts = reg_domain.split('.')
        if len(reg_parts) >= 3 and reg_parts[-2] in ('co', 'org', 'net', 'edu', 'gov', 'ac', 'mil', 'sch', 'com'):
            reg_main = reg_parts[-3]
        else:
            reg_main = reg_parts[-2] if len(reg_parts) >= 2 else reg_parts[0]
            
        subdomains = domain.replace(reg_domain, '').rstrip('.')
        
        # We want to check all segments of the domain (excluding the TLDs)
        segments = []
        if subdomains:
            segments.extend(subdomains.split('.'))
        segments.append(reg_main)
        
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

        # Check segments and their hyphenated parts
        all_segments = []
        for seg in segments:
            if seg:
                all_segments.append(seg)
                if '-' in seg:
                    all_segments.extend(seg.split('-'))
        all_segments = list(set(all_segments))

        for segment in all_segments:
            # 1. Check for exact brand name inside segment but not matching official domain list
            for brand, officials in self.brands.items():
                if brand in segment:
                    is_official = False
                    for official in officials:
                        if domain == official or domain.endswith('.' + official):
                            is_official = True
                            break
                    if not is_official:
                        return True, brand, f"Domain '{domain}' segment '{segment}' contains brand '{brand}' but is not an official '{brand}' domain."

            # 2. Check for typosquatting (edit distance of segment is 1 or 2; for short 4-letter brands, use dist 1)
            for brand, officials in self.brands.items():
                dist = get_edit_distance(segment, brand)
                max_dist = 1 if len(brand) <= 4 else 2
                if 0 < dist <= max_dist:
                    is_official = False
                    for official in officials:
                        if domain == official or domain.endswith('.' + official):
                            is_official = True
                            break
                    if not is_official:
                        return True, brand, f"Domain '{domain}' segment '{segment}' appears to be a typo of '{brand}' (edit distance: {dist})."
                        
        return False, None, None

    def _rule_based_check(self, url, domain):
        # Check domain typosquatting first
        is_susp, matched_brand, reason = self._check_domain_typosquatting(domain)
        if is_susp:
            return {
                'prediction': 'Phishing',
                'confidence': 0.99,
                'probabilities': {'phishing': 0.99, 'legitimate': 0.01},
                'features_count': len(self.feature_names_url),
                'reason': reason
            }
        legitimate_domains = [
            'google.com', 'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
            'linkedin.com', 'github.com', 'stackoverflow.com', 'wikipedia.org',
            'amazon.com', 'microsoft.com', 'apple.com', 'netflix.com', 'youtube.com',
            'reddit.com', 'discord.com', 'spotify.com', 'twitch.tv',
            'nust.edu.pk', 'lums.edu.pk', 'pu.edu.pk', 'uet.edu.pk', 'comsats.edu.pk',
            'c.gle', 'gmail.com', 'googlemail.com', 'fb.me', 'amzn.to', 'lnkd.in',
            'snapchat.com', 'foodpanda.pk', 'foodpanda.com', 'forms.gle', 'docs.google.com',
            'buneri.de'
        ]
        try:
            root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            db_path = os.path.join(root_dir, 'models', 'saved_models', 'reputation_db.bin')
            if os.path.exists(db_path):
                import gzip
                import json
                with gzip.open(db_path, 'rt', encoding='utf-8') as f:
                    loaded_domains = json.load(f)
                    for d in loaded_domains:
                        legitimate_domains.append(d)
        except Exception as e:
            pass

        is_legit = False
        for legit in legitimate_domains:
            if domain == legit:
                is_legit = True
                break
            elif domain.endswith('.' + legit):
                # Verify that the subdomain prefix does not contain suspicious keywords or brand names
                subdomain_prefix = domain[:-len('.' + legit)]
                
                # Check for suspicious keywords in subdomain prefix
                suspicious_keywords = ['login', 'alert', 'auth', 'secure', 'verify', 'update', 'signin', 'banking', 'account', 'invoice', 'billing']
                has_suspicious_subdomain = False
                for kw in suspicious_keywords:
                    if kw in subdomain_prefix:
                        has_suspicious_subdomain = True
                        break
                
                # Check for brand names in subdomain prefix
                if not has_suspicious_subdomain:
                    for brand in self.brands.keys():
                        if brand in subdomain_prefix:
                            has_suspicious_subdomain = True
                            break
                            
                if not has_suspicious_subdomain:
                    is_legit = True
                    break
                
        # Check against OpenDNS Top 10,000 legitimate domains list
        is_top = False
        if not is_legit and self._is_top_domain(domain):
            is_top = True
            is_legit = True
                
        # Automatically trust accredited educational, academic & government domains worldwide
        is_edu_gov = False
        domain_parts = domain.split('.')
        if len(domain_parts) >= 2:
            if domain_parts[-1] in ('edu', 'gov'):
                is_edu_gov = True
                is_legit = True
            elif len(domain_parts[-1]) == 2 and domain_parts[-2] in ('edu', 'gov', 'ac'):
                # Official list of 2-letter country-code TLDs (ccTLDs)
                valid_cctlds = {
                    'ac', 'ad', 'ae', 'af', 'ag', 'ai', 'al', 'am', 'ao', 'aq', 'ar', 'as', 'at', 'au', 'aw', 'ax', 'az', 
                    'ba', 'bb', 'bd', 'be', 'bf', 'bg', 'bh', 'bi', 'bj', 'bm', 'bn', 'bo', 'bq', 'br', 'bs', 'bt', 'bv', 
                    'bw', 'by', 'bz', 'ca', 'cc', 'cd', 'cf', 'cg', 'ch', 'ci', 'ck', 'cl', 'cm', 'cn', 'co', 'cr', 'cu', 
                    'cv', 'cw', 'cx', 'cy', 'cz', 'de', 'dj', 'dk', 'dm', 'do', 'dz', 'ec', 'ee', 'eg', 'eh', 'er', 'es', 
                    'et', 'eu', 'fi', 'fj', 'fk', 'fm', 'fo', 'fr', 'ga', 'gb', 'gd', 'ge', 'gf', 'gg', 'gh', 'gi', 'gl', 
                    'gm', 'gn', 'gp', 'gq', 'gr', 'gs', 'gt', 'gu', 'gw', 'gy', 'hk', 'hm', 'hn', 'hr', 'ht', 'hu', 'id', 
                    'ie', 'il', 'im', 'in', 'io', 'iq', 'ir', 'is', 'it', 'je', 'jm', 'jo', 'jp', 'ke', 'kg', 'kh', 'ki', 
                    'km', 'kn', 'kp', 'kr', 'kw', 'ky', 'kz', 'la', 'lb', 'lc', 'li', 'lk', 'lr', 'ls', 'lt', 'lu', 'lv', 
                    'ly', 'ma', 'mc', 'md', 'me', 'mf', 'mg', 'mh', 'mk', 'ml', 'mm', 'mn', 'mo', 'mp', 'mq', 'mr', 'ms', 
                    'mt', 'mu', 'mv', 'mw', 'mx', 'my', 'mz', 'na', 'nc', 'ne', 'nf', 'ng', 'ni', 'nl', 'no', 'np', 'nr', 
                    'nu', 'nz', 'om', 'pa', 'pe', 'pf', 'pg', 'ph', 'pk', 'pl', 'pm', 'pn', 'pr', 'ps', 'pt', 'pw', 'py', 
                    'qa', 're', 'ro', 'rs', 'ru', 'rw', 'sa', 'sb', 'sc', 'sd', 'se', 'sg', 'sh', 'si', 'sj', 'sk', 'sl', 
                    'sm', 'sn', 'so', 'sr', 'ss', 'st', 'su', 'sv', 'sx', 'sy', 'sz', 'tc', 'td', 'tf', 'tg', 'th', 'tj', 
                    'tk', 'tl', 'tm', 'tn', 'to', 'tr', 'tt', 'tv', 'tw', 'tz', 'ua', 'ug', 'uk', 'um', 'us', 'uy', 'uz', 
                    'va', 'vc', 've', 'vg', 'vi', 'vn', 'vu', 'wf', 'ws', 'ye', 'yt', 'za', 'zm', 'zw'
                }
                if domain_parts[-1] in valid_cctlds:
                    is_edu_gov = True
                    is_legit = True
                
        # Revoke auto-legitimacy for ANY whitelisted domain if the URL contains suspicious paths
        # (e.g. compromised directories, phishing keywords, or user uploads)
        if is_legit:
            parsed_url = urlparse(url)
            path = parsed_url.path.lower()
            
            # Phishing keywords in path
            suspicious_path_keywords = [
                'login', 'signin', 'verify', 'verification', 'update', 
                'credential', 'password', 'secure-login', 'account-update'
            ]
            
            # User content directories in path
            user_content_dirs = [
                '~', 'upload', 'uploads', 'file', 'files', 'temp', 'tmp', 'user', 'users'
            ]
            
            has_suspicious_path = any(kw in path for kw in suspicious_path_keywords)
            has_user_content = any(d in path for d in user_content_dirs)
            
            if has_suspicious_path or has_user_content:
                is_legit = False
            
        if is_legit:
            return {
                'prediction': 'Legitimate',
                'confidence': 0.98,
                'probabilities': {'phishing': 0.02, 'legitimate': 0.98},
                'features_count': len(self.feature_names_url)
            }

                
        # Check domain age via WHOIS for established domains
        try:
            sys.path.append(os.path.dirname(__file__))
            from whois_helper import get_domain_age, get_registered_domain
            
            is_suspicious_domain = False
            reg_domain = get_registered_domain(domain)
            subdomain_part = domain.replace(reg_domain, '').rstrip('.')
            
            suspicious_keywords = ['login', 'alert', 'auth', 'secure', 'verify', 'update', 'signin', 'banking', 'account', 'invoice', 'billing']
            for kw in suspicious_keywords:
                if kw in subdomain_part:
                    is_suspicious_domain = True
                    break
                    
            generic_hosts = {
                'example.com', 'example.net', 'example.org',
                'github.io', 'web.app', 'amazonaws.com', 'cloudfront.net',
                'pages.dev', 'vercel.app', 'herokuapp.com', 'blogspot.com',
                'wordpress.com', 'firebaseapp.com', 'dyndns.org', 'no-ip.info'
            }
            if reg_domain in generic_hosts:
                is_suspicious_domain = True
                
            if not is_suspicious_domain:
                age_info = get_domain_age(domain)
                if age_info.get('success') and age_info.get('is_established_domain'):
                    # Trust established domains that don't match any phishing patterns
                    return {
                        'prediction': 'Legitimate',
                        'confidence': 0.95,
                        'probabilities': {'phishing': 0.05, 'legitimate': 0.95},
                        'features_count': len(self.feature_names_url)
                    }
        except Exception:
            pass
            
        return None
        
    def _enhanced_rule_fallback(self, url, parsed_url, domain):
        score = 0.5
        if parsed_url.scheme == 'https':
            score += 0.1
        domain_parts = domain.split('.')
        if len(domain_parts) <= 3:
            score += 0.1
        else:
            score -= 0.2
        tld = domain_parts[-1] if domain_parts else ''
        if tld in ['com', 'org', 'net', 'edu', 'gov']:
            score += 0.15
        elif tld in ['tk', 'ml', 'ga', 'cf']:
            score -= 0.3
        if len(url) > 100:
            score -= 0.1
        special_count = sum(url.count(c) for c in '-_@%')
        if special_count > 5:
            score -= 0.1
            
        confidence = abs(score - 0.5) * 2
        if score > 0.5:
            return {
                'prediction': 'Legitimate',
                'confidence': min(0.85, 0.5 + confidence),
                'probabilities': {'phishing': max(0.15, 0.5 - confidence), 'legitimate': min(0.85, 0.5 + confidence)},
                'features_count': len(self.feature_names_url)
            }
        else:
            return {
                'prediction': 'Phishing',
                'confidence': min(0.85, 0.5 + confidence),
                'probabilities': {'phishing': min(0.85, 0.5 + confidence), 'legitimate': max(0.15, 0.5 - confidence)},
                'features_count': len(self.feature_names_url)
            }
            
    def get_model_info(self):
        if self.model_url is None:
            return {'error': 'No model loaded'}
        return {
            'model_type': 'Random Forest Classifier (Hybrid)',
            'url_model_estimators': self.model_url.n_estimators if self.model_url else 0,
            'full_model_estimators': self.model_full.n_estimators if self.model_full else 0,
            'n_features_url': len(self.feature_names_url),
            'n_features_full': len(self.feature_names_full),
            'status': 'loaded'
        }
        
    def _convert_to_vector(self, features, feature_names):
        return np.array([features.get(name, 0) for name in feature_names])


# Test the predictor
if __name__ == "__main__":
    try:
        predictor = URLPredictor()
        test_urls = [
            "https://www.google.com",
            "http://suspicious-site.tk/login.php",
            "https://www.github.com",
            "http://paypal-security-update.com/verify"
        ]
        print("Testing URL Predictor:")
        print("=" * 50)
        for url in test_urls:
            result = predictor.predict_url(url)
            print(f"\nURL: {url}")
            print(f"Prediction: {result['prediction']}")
            print(f"Method Used: {result.get('method', 'unknown')}")
            print(f"Confidence: {result['confidence']:.3f}")
            print(f"Phishing Prob: {result['probabilities']['phishing']:.3f}")
    except Exception as e:
        print(f"Error: {e}")