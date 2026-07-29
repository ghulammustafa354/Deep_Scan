import socket
import re
import os
import json
from datetime import datetime

# Local JSON cache path
CACHE_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'whois_cache.json')

def load_cache():
    if os.path.exists(CACHE_PATH):
        try:
            with open(CACHE_PATH, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_cache(cache):
    try:
        os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
        with open(CACHE_PATH, 'w', encoding='utf-8') as f:
            json.dump(cache, f, indent=4)
    except Exception:
        pass

def get_registered_domain(domain):
    domain = domain.lower().strip().split(':')[0]
    parts = domain.split('.')
    if len(parts) <= 2:
        return domain
    
    if len(parts[-1]) == 2 and parts[-2] in ('co', 'org', 'net', 'edu', 'gov', 'ac', 'mil', 'sch', 'com', 'net', 'org'):
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])

def query_whois_raw(domain, server="whois.iana.org"):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((server, 43))
        s.send((domain + "\r\n").encode("utf-8"))
        
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        s.close()
        return response.decode("utf-8", errors="ignore")
    except Exception:
        return ""

def parse_date(date_str):
    date_str = date_str.strip()
    # Match YYYY-MM-DD or YYYY/MM/DD
    match = re.search(r'(\d{4})[-/](\d{2})[-/](\d{2})', date_str)
    if match:
        try:
            return datetime(int(match.group(1)), int(match.group(2)), int(match.group(3)))
        except ValueError:
            pass
            
    # Match DD.MM.YYYY
    match = re.search(r'(\d{2})\.(\d{2})\.(\d{4})', date_str)
    if match:
        try:
            return datetime(int(match.group(3)), int(match.group(2)), int(match.group(1)))
        except ValueError:
            pass
            
    # Match DD-Month-YYYY
    months = {
        'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4, 'may': 5, 'jun': 6,
        'jul': 7, 'aug': 8, 'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12
    }
    match = re.search(r'(\d{1,2})[-/\s]([A-Za-z]{3})[-/\s](\d{4})', date_str)
    if match:
        day = int(match.group(1))
        mon_str = match.group(2).lower()[:3]
        year = int(match.group(3))
        if mon_str in months:
            try:
                return datetime(year, months[mon_str], day)
            except ValueError:
                pass

    # Match YYYYMMDD (8-digit compact, e.g. .br domains before 19950101)
    match = re.search(r'\b(\d{4})(\d{2})(\d{2})\b', date_str)
    if match:
        try:
            return datetime(int(match.group(1)), int(match.group(2)), int(match.group(3)))
        except ValueError:
            pass

    return None

def get_domain_age(domain):
    registered_domain = get_registered_domain(domain)
    
    # Load from cache first
    cache = load_cache()
    if registered_domain in cache:
        cached_info = cache[registered_domain]
        if cached_info.get('success'):
            try:
                created_date = datetime.strptime(cached_info['creation_date'], '%Y-%m-%d')
                age_days = (datetime.now() - created_date).days
                return {
                    'creation_date': cached_info['creation_date'],
                    'age_days': age_days,
                    'is_new_domain': age_days < 30,
                    'is_established_domain': age_days > 365,
                    'success': True
                }
            except Exception:
                pass

    # Query IANA first
    res = query_whois_raw(registered_domain)
    if not res:
        return {'success': False, 'reason': 'IANA query failed'}
        
    refer_match = re.search(r'refer:\s+(\S+)', res, re.IGNORECASE)
    whois_text = ""
    if refer_match:
        refer_server = refer_match.group(1)
        whois_text = query_whois_raw(registered_domain, refer_server)
    else:
        tld = registered_domain.split('.')[-1]
        whois_text = query_whois_raw(registered_domain, f"whois.nic.{tld}")
        if not whois_text:
            whois_text = res
            
    # Look for creation dates
    date_patterns = [
        r'(?:Creation Date|created|Created on|Registered Date|Registered|Registration Date|Date of Creation|Domain Name Commencement Date)\s*:\s*(.+)',
        r'created\s*\.+\s*:\s*(.+)',
        r'changed\s*:\s*(.+)'
    ]
    
    creation_date = None
    for pattern in date_patterns:
        match = re.search(pattern, whois_text, re.IGNORECASE)
        if match:
            parsed = parse_date(match.group(1))
            if parsed:
                creation_date = parsed
                break
                
    if creation_date:
        creation_date_str = creation_date.strftime('%Y-%m-%d')
        age_days = (datetime.now() - creation_date).days
        
        # Save to cache
        cache[registered_domain] = {
            'creation_date': creation_date_str,
            'success': True
        }
        save_cache(cache)
        
        return {
            'creation_date': creation_date_str,
            'age_days': age_days,
            'is_new_domain': age_days < 30,
            'is_established_domain': age_days > 365,
            'success': True
        }
    else:
        # Save failure in cache briefly to avoid repetitive lookup errors
        cache[registered_domain] = {
            'success': False,
            'creation_date': None
        }
        save_cache(cache)
        return {'success': False, 'reason': 'Could not parse creation date'}
