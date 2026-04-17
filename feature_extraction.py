import pandas as pd
from urllib.parse import urlsplit
import tldextract
import dns.resolver
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from collections import Counter
import math
import os
import whois
import requests
import tldextract
import pandas as pd
import time
import json
import concurrent
import zipfile
import io
df = pd.read_csv('url_dataset.csv')
df['url'] = df['url'].str.replace(r'^(https?://)?www\.', r'\1', regex=True)
legitimate_ip_url = [
    {'url':'http://192.168.0.1', 'type':'legitimate'},
    {'url':'http://192.168.1.1', 'type':'legitimate'},
    {'url':'http://192.168.1.254', 'type':'legitimate'},
    {'url':'http://10.0.0.1', 'type':'legitimate'},
    {'url':'http://10.0.1.1', 'type':'legitimate'},
    {'url':'http://172.16.0.1', 'type':'legitimate'},
    {'url':'http://172.16.1.1', 'type':'legitimate'},
    {'url':'http://1.1.1.1', 'type':'legitimate'},
    {'url':'http://8.8.8.8 ', 'type':'legitimate'},
    {'url':'http://127.0.0.1:8000', 'type':'legitimate'},
    {'url':'http://127.0.0.1:5000/login', 'type':'legitimate'},
    {'url':'http://127.0.0.1', 'type':'legitimate'},
]
new_df = pd.DataFrame(legitimate_ip_url)
df = pd.concat([df, new_df], ignore_index=True)
df['url_len'] = df['url'].str.len()
df['dot_count'] = df['url'].str.count(r'\.')
df['at_count'] = df['url'].str.count("@")
df['hyphen_count'] = df['url'].str.count("-")
df['undersc_count'] = df['url'].str.count("_")
df['slash_count'] = df['url'].str.count("/")
df['doubleslash_count'] = df['url'].str.count("//")
df['backslash_count'] = df['url'].str.count(r"\\")
df['quemark_count'] = df['url'].str.count(r"\?")
df['asterisk_count'] = df['url'].str.count(r"\*")
df['ampersand_count'] = df['url'].str.count("&")
df['equalto_count'] = df['url'].str.count("=")
df['percent_count'] = df['url'].str.count("%")
df['numeric_count'] = df['url'].str.count(r'\d')
df['letter_count'] = df['url'].str.count(r'[a-zA-Z]')
df['num_to_alpha'] = df['numeric_count'] / (df['letter_count'] + 1)
print("String features done")
def parse_url(url):
    try:
        res  = urlsplit(str(url))
        host = res.hostname or ""
        port = res.port
        return res.scheme, res.netloc, res.path, res.query, res.fragment, host, port
    except:
        return None, None, None, None, None, "", None
parsed = df['url'].apply(parse_url)
df[['scheme','netloc','path','query','fragment','domain','port']] = pd.DataFrame(parsed.tolist(), index=df.index)
df['domain'] = df['domain'].replace("", None)
def clean_domain(host):
    if pd.isna(host) or host is None:
        return None
    host = str(host).lower().strip()
    if host.startswith("www."):
        host = host[4:]
    return host
df['domain'] = df['domain'].apply(clean_domain)
df['domain_length'] = df['domain'].str.len()
df['is_https'] = df['scheme'].apply(lambda x: -1 if x == "https" else 1)
df['has_digit'] = df['domain'].str.contains(r'\d', na=False).astype(int)
df["HTTPSDomainURL"] = df.apply(lambda x: 1 if "https" in (str(x["domain"]) + str(x["path"])).lower() else -1, axis=1)
print("URL parsing done")
def extract_tld_info(url):
    try:
        ext = tldextract.extract(str(url))
        tld = ext.suffix
        subd = ext.subdomain
        subd_count = len(subd.split('.')) if subd else 0
        return tld, subd_count
    except:
        return "", 0
tld_results = df['url'].apply(extract_tld_info)
df[['tld', 'subd_count']] = pd.DataFrame(tld_results.tolist(), index=df.index)
print("TLD extraction done")
tld_cache  = {}
cache_lock = threading.Lock()
def check_dns(tld):
    if not tld:
        return 0
    with cache_lock:
        if tld in tld_cache:
            return tld_cache[tld]
    try:
        dns.resolver.resolve(tld + '.', 'SOA', lifetime=3)
        result = 1
    except:
        result = 0
    with cache_lock:
        tld_cache[tld] = result
    return result
unique_tlds = df['tld'].dropna().unique()
with ThreadPoolExecutor(max_workers=50) as executor:
    results = list(executor.map(check_dns, unique_tlds))
tld_dns_map = dict(zip(unique_tlds, results))
df['tld_exists'] = df['tld'].map(tld_dns_map).fillna(0).astype(int)
print("DNS check done")
shortener_domains = {'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly','adf.ly','short.io','rebrand.ly','tiny.cc','lnkd.in','db.tt','qr.ae','cur.lv'}
def is_short(domain):
    if pd.isna(domain) or domain is None:
        return 0
    domain = str(domain)
    return int(any(sd in domain for sd in shortener_domains))
df['is_shortened'] = df['domain'].apply(is_short)
def is_ipbased(hostn):
    try:
        ipaddress.ip_address(str(hostn))
        return 1
    except:
        return 0
print("IP check done")
df['scheme'] = df['scheme'].str.replace('httpss', 'https', regex=False)
def ip_typ(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            return 0
        elif ip_obj.is_global:
            return 1
        else:
            return 2
    except:
        return -1
df['ip_type'] = df['domain'].apply(ip_typ)
df['path_depth'] = df['path'].apply(lambda x: x.count('/') if pd.notna(x) else 0)
df['dot>3'] = df['dot_count'].apply(lambda x: 1 if x > 3 else 0)
df["redirecting//"] = df["url"].apply(lambda x: 1 if str(x).replace("://", "").count("//") > 0 else -1)
df["prefsuff"] = df["domain"].apply(lambda x: 1 if "-" in str(x) else -1)
df["nonStdPort"] = df["port"].apply(lambda x: 1 if x and (x not in [80, 443]) else -1)
def entropy(s):
    if not isinstance(s, str) or len(s) == 0:
        return 0
    probs = [c/len(s) for c in Counter(s).values()]
    return -sum(p * math.log2(p) for p in probs)
df['domain_entropy'] = df['domain'].apply(entropy)
WHOIS_CACHE_FILE = "whois_cache.json"
if os.path.exists(WHOIS_CACHE_FILE):
    with open(WHOIS_CACHE_FILE) as f:
        whois_cache = json.load(f)
else:
    whois_cache = {}
def _whois_query(domain):
    """Raw whois call — run inside a thread with an external timeout."""
    import socket
    socket.setdefaulttimeout(8)
    w       = whois.whois(domain)
    created = w.creation_date
    expires = w.expiration_date
    created = created[0] if isinstance(created, list) else created
    expires = expires[0] if isinstance(expires, list) else expires
    return (
        created.isoformat() if created else None,
        expires.isoformat() if expires else None,
    )
def get_whois(domain):
    if domain in whois_cache:
        return tuple(whois_cache[domain])
    result = (None, None)
    for attempt in range(2):
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(_whois_query, domain)
            try:
                result = future.result(timeout=10)
                break
            except concurrent.futures.TimeoutError:
                print(f"  Timeout: {domain}")
                break
            except Exception:
                if attempt == 0:
                    time.sleep(1)
    whois_cache[domain] = result
    return result
def fetch_whois_in_batches(domains, batch_size=200, max_workers=10):
    results = {}
    total_batches = (len(domains) + batch_size - 1) // batch_size
    for i in range(total_batches):
        batch = [d for d in domains[i * batch_size:(i + 1) * batch_size]
                 if d not in whois_cache]
        print(f"Batch {i+1}/{total_batches} — {len(batch)} to fetch...")
        if not batch:
            print("  All cached, skipping.")
            continue
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_domain = {executor.submit(get_whois, d): d for d in batch}
            for future in concurrent.futures.as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    results[domain] = future.result()
                except Exception:
                    results[domain] = (None, None)
        with open(WHOIS_CACHE_FILE, "w") as f:
            json.dump(whois_cache, f)
        print(f"  Saved ({len(whois_cache)} domains cached so far)")
        time.sleep(0.5)
    return results
unique_domains = df['domain'].dropna().unique()
whois_results  = fetch_whois_in_batches(unique_domains)
def domain_age_days(domain):
    entry = whois_results.get(domain) or whois_cache.get(domain)
    created_str = entry[0] if entry else None
    if not created_str:
        return -1
    try:
        created = datetime.fromisoformat(created_str.replace("+00:00", "").replace("Z", ""))
        age_days = (datetime.now() - created).days
        return 1 if age_days >= 365 else -1
    except Exception:
        return -1
def domain_end_period(domain):
    entry = whois_results.get(domain) or whois_cache.get(domain)
    if not entry or not entry[1]:
        return -1
    try:
        expires = datetime.fromisoformat(entry[1].replace("+00:00", "").replace("Z", ""))
        remaining_days = (expires - datetime.now()).days
        return -1 if remaining_days <= 180 else 1
    except Exception:
        return -1
df['DomainAge']       = df['domain'].apply(domain_age_days)
df['DomainEndPeriod'] = df['domain'].apply(domain_end_period)
def download_tranco():
    if not os.path.exists('tranco.csv'):
        print("Downloading Tranco list...")
        r = requests.get("https://tranco-list.eu/top-1m.csv.zip")
        z = zipfile.ZipFile(io.BytesIO(r.content))
        z.extractall('.')
        os.rename('top-1m.csv', 'tranco.csv')
        print("Done.")
download_tranco()
tranco_df = pd.read_csv('tranco.csv', names=['rank', 'domain'])
tranco_rank = dict(zip(tranco_df['domain'], tranco_df['rank']))
def web_traffic(domain):
    if not domain:
        return -1
    rank = tranco_rank.get(domain)
    if rank is None:
        return -1
    if rank <= 10_000:
        return 1
    if rank <= 500_000:
        return 0
    return -1
df['web_traffic'] = df['domain'].apply(web_traffic)
df.drop(columns=['scheme', 'netloc', 'path', 'query', 'fragment'], inplace=True)
df.to_csv('Features_extracted_final_final.csv', index=False)
