import pandas as pd
from urllib.parse import urlsplit, urlparse
import tldextract
import dns.resolver
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor
import socket
import ssl
from datetime import datetime,UTC
import OpenSSL

df = pd.read_csv('url_dataset.csv')

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

df = pd.concat([df,new_df],ignore_index=True)

df['url_len']        = df['url'].str.len()
df['dot_count']      = df['url'].str.count(r'\.')
df['at_count']       = df['url'].str.count("@")
df['hyphen_count']   = df['url'].str.count("-")
df['undersc_count']  = df['url'].str.count("_")
df['slash_count']    = df['url'].str.count("/")

df['doubleslash_count']= df['url'].str.count("//")
df['backslash_count']= df['url'].str.count(r"\\")
df['quemark_count']  = df['url'].str.count(r"\?")
df['asterisk_count'] = df['url'].str.count(r"\*")
df['ampersand_count']= df['url'].str.count("&")
df['equalto_count']  = df['url'].str.count("=")
df['percent_count']  = df['url'].str.count("%")

df['numeric_count'] = df['url'].str.count(r'\d')
df['letter_count']  = df['url'].str.count(r'[a-zA-Z]')
df['num_to_alpha']  = df['numeric_count'] / (df['letter_count'] + 1)

print("String features done")

def parse_url(url):
    try:
        res  = urlsplit(str(url))
        host = res.hostname or ""
        return res.scheme, res.netloc, res.path, res.query, res.fragment, host
    except:
        return None, None, None, None, None, ""

parsed = df['url'].apply(parse_url)
df[['scheme','netloc','path','query','fragment','domain']] = pd.DataFrame(
    parsed.tolist(), index=df.index
)
df['domain']        = df['domain'].replace("", None)
df['domain_length'] = df['domain'].str.len()
df['is_https']      = (df['scheme'] == "https").astype(int)
df['has_digit']     = df['domain'].str.contains(r'\d', na=False).astype(int)


print("URL parsing done")

def extract_tld_info(url):
    try:
        ext  = tldextract.extract(str(url))
        tld  = ext.suffix
        subd = ext.subdomain
        subd_count = len(subd.split('.')) if subd else 0
        return tld, subd_count
    except:
        return "", 0

tld_results = df['url'].apply(extract_tld_info)
df[['tld', 'subd_count']] = pd.DataFrame(tld_results.tolist(), index=df.index)


print("TLD extraction done")

tld_cache = {}
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

shortener_domains = {
    'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly',
    'is.gd','buff.ly','adf.ly','short.io','rebrand.ly',
    'tiny.cc','lnkd.in','db.tt','qr.ae','cur.lv'
}
suspicious_tlds = {
    'tk','ml','ga','cf','gq','xyz','top','club',
    'online','site','work','info','buzz','vip'
}
brand_names = [
    'paypal','google','apple','amazon','microsoft',
    'facebook','netflix','instagram','linkedin','ebay',
    'whatsapp','twitter','youtube','dropbox','wordpress'
]
suspicious_keywords = [
    'login','signin','secure','update','verify','confirm',
    'account','banking','password','credential','webscr',
    'submit','unlimited','freedom','lucky','bonus','alert'
]

df['is_shortened'] = df['domain'].apply(lambda x: 1 if x in shortener_domains else 0)

def is_ipbased(hostn):
    try:
        ipaddress.ip_address(str(hostn))
        return 1
    except:
        return 0

# df['http_and_ip'] = df['domain'].apply(lambda x: x['scheme']=='http')

print("IP check done")

df['scheme'] = df['scheme'].str.replace('httpss','https',regex=False)


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
df['dot>3'] = df['dot_count'].apply(lambda x: 1 if x>3 else 0)



df.drop(columns=['scheme','netloc','path','query','fragment'], inplace=True)

df.to_csv('Features_extracted.csv', index=False)