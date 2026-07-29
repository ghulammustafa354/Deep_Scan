import requests

# Memory cache for DNS lookups to optimize performance of large scans
_dns_cache = {}

def get_dns_records(domain, record_type='TXT'):
    """
    Query DNS records for a domain using Cloudflare DNS over HTTPS JSON API,
    with a fallback to Google DNS over HTTPS JSON API.
    Returns the list of records, or None if the query failed completely (network errors/timeouts).
    """
    domain = domain.lower().strip()
    cache_key = (domain, record_type)
    if cache_key in _dns_cache:
        return _dns_cache[cache_key]

    cloudflare_failed = False
    google_failed = False
    
    # 1. Try Cloudflare DoH API
    try:
        url = f"https://cloudflare-dns.com/dns-query?name={domain}&type={record_type}"
        headers = {"Accept": "application/dns-json"}
        res = requests.get(url, headers=headers, timeout=2.5)
        if res.status_code == 200:
            data = res.json()
            records = [answer['data'] for answer in data.get('Answer', []) if 'data' in answer]
            _dns_cache[cache_key] = records
            return records
        else:
            cloudflare_failed = True
    except Exception:
        cloudflare_failed = True
        
    # 2. Fallback to Google DoH API
    try:
        url = f"https://dns.google/resolve?name={domain}&type={record_type}"
        res = requests.get(url, timeout=2.5)
        if res.status_code == 200:
            data = res.json()
            records = [answer['data'] for answer in data.get('Answer', []) if 'data' in answer]
            _dns_cache[cache_key] = records
            return records
        else:
            google_failed = True
    except Exception:
        google_failed = True
        
    # If both queries failed, return None to indicate failure (rather than empty records)
    if cloudflare_failed and google_failed:
        _dns_cache[cache_key] = None
        return None
        
    _dns_cache[cache_key] = []
    return []

def verify_sender_domain(domain):
    """
    Verify the sender domain's cryptographic security state.
    Returns a dictionary of DNS status records.
    """
    domain = domain.lower().strip()
    
    # 1. Check MX records
    mx_records = get_dns_records(domain, 'MX')
    query_failed = (mx_records is None)
    has_mx = len(mx_records) > 0 if mx_records is not None else True
    
    # 2. Check SPF record (TXT record containing v=spf1)
    txt_records = get_dns_records(domain, 'TXT')
    if txt_records is None:
        query_failed = True
        txt_records = []
    has_spf = False
    spf_record = None
    for rec in txt_records:
        rec_clean = rec.strip('"').strip()
        if rec_clean.lower().startswith('v=spf1'):
            has_spf = True
            spf_record = rec_clean
            break
            
    # 3. Check DMARC record (TXT record at _dmarc.domain)
    dmarc_domain = f"_dmarc.{domain}"
    dmarc_records = get_dns_records(dmarc_domain, 'TXT')
    if dmarc_records is None:
        query_failed = True
        dmarc_records = []
    has_dmarc = False
    dmarc_policy = None
    dmarc_record = None
    for rec in dmarc_records:
        rec_clean = rec.strip('"').strip()
        if rec_clean.lower().startswith('v=dmarc1'):
            has_dmarc = True
            dmarc_record = rec_clean
            # Parse policy (e.g. p=none, p=quarantine, p=reject)
            parts = [p.strip() for p in rec_clean.split(';')]
            for part in parts:
                if part.lower().startswith('p='):
                    dmarc_policy = part.split('=')[-1].strip().lower()
                    break
            break
            
    return {
        'domain': domain,
        'has_mx': has_mx,
        'has_spf': has_spf,
        'spf_record': spf_record,
        'has_dmarc': has_dmarc,
        'dmarc_policy': dmarc_policy,
        'dmarc_record': dmarc_record,
        'is_authentic': has_mx and (has_spf or has_dmarc),
        'query_failed': query_failed
    }
