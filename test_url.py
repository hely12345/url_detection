from urllib.parse import urlsplit, urlparse
import tldextract
import dns.resolver
import ipaddress
import joblib
import pandas as pd
import streamlit as st
import warnings
from collections import Counter
import math
import socket
import whois
from datetime import datetime
import requests

warnings.filterwarnings("ignore", category=UserWarning)

rf = joblib.load('random_forest.joblib')

st.set_page_config(page_title="Phishing Detector", layout="centered")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap');

html, body, [class*="css"] { font-family: 'Inter', sans-serif; }

#MainMenu, footer, header { visibility: hidden; }

.block-container { max-width: 600px; padding-top: 4rem; }

h1 { font-size: 1.6rem; font-weight: 600; color: #111; margin-bottom: 0.2rem; }
.subtitle { color: #888; font-size: 0.9rem; margin-bottom: 2rem; }

.stTextArea textarea {
    border: 1px solid #ddd !important;
    border-radius: 8px !important;
    font-size: 0.9rem !important;
    font-family: 'Inter', sans-serif !important;
    padding: 0.6rem 0.8rem !important;
    resize: none !important;
}
.stTextArea textarea:focus { border-color: #999 !important; box-shadow: none !important; }
.stTextArea label { display: none; }

.stButton > button {
    background: #111 !important;
    color: #fff !important;
    border: none !important;
    border-radius: 8px !important;
    padding: 0.5rem 1.4rem !important;
    font-size: 0.88rem !important;
    font-family: 'Inter', sans-serif !important;
    font-weight: 500 !important;
    transition: background 0.15s !important;
}
.stButton > button:hover { background: #333 !important; }

.result-item {
    border: 1px solid #e8e8e8;
    border-radius: 10px;
    padding: 1rem 1.1rem;
    margin-bottom: 0.75rem;
    background: #fff;
}
.result-url { font-size: 0.78rem; color: #888; word-break: break-all; margin-bottom: 0.45rem; }
.result-verdict { font-size: 1rem; font-weight: 600; margin-bottom: 0.6rem; }
.verdict-legit   { color: #1a9e5c; }
.verdict-phish   { color: #d63c3c; }
.verdict-invalid { color: #999; }

.bar-row { display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.3rem; }
.bar-label { font-size: 0.75rem; color: #999; width: 65px; flex-shrink: 0; }
.bar-bg { flex: 1; height: 5px; background: #f0f0f0; border-radius: 3px; overflow: hidden; }
.bar-fill-legit { height: 100%; background: #1a9e5c; border-radius: 3px; }
.bar-fill-phish { height: 100%; background: #d63c3c; border-radius: 3px; }
.bar-pct { font-size: 0.75rem; color: #aaa; width: 38px; text-align: right; }
</style>
""", unsafe_allow_html=True)


def check(inp):
    inp = inp.strip()
    leng      = len(inp)
    dots      = inp.count('.')
    ats       = inp.count('@')
    hyp       = inp.count('-')
    undsc     = inp.count('_')
    slsh      = inp.count('/')
    dbslsh    = inp.count('//')
    bcksl     = inp.count('\\')
    quem      = inp.count('?')
    ast       = inp.count('*')
    amp       = inp.count('&')
    eq        = inp.count('=')
    perc      = inp.count('%')
    digits    = sum(c.isdigit() for c in inp)
    char      = sum(c.isalpha() for c in inp)
    digtochar = digits / char if char != 0 else 0

    def split_url_safe(url):
        try:
            res = urlsplit(str(url))
            return res.scheme, res.path, res.port
        except Exception:
            return None, None, None

    sch, path, port = split_url_safe(inp)

    def hostn(url):
        try:
            return urlparse(url).hostname
        except Exception:
            return None
        
    def clean_domain(host):
        if pd.isna(host) or host is None:
            return None
        host = str(host).lower().strip()
        if host.startswith("www."):
            host = host[4:]
        return host

    domain      = hostn(inp) or ""
    domain = clean_domain(domain)
    domain_leng = len(domain)
    tld         = tldextract.extract(inp).suffix

    has_dig  = int(any(c.isdigit() for c in domain))
    is_https = int(sch == 'https')

    def count_subd(url):
        try:
            subd = tldextract.extract(url).subdomain
            if subd.lower() == "www":
                return 0
            return 0 if not subd else len(subd.split('.'))
        except Exception:
            return 0

    subd_count = count_subd(inp)

    def check_dns(t):
        try:
            dns.resolver.resolve(t + '.', 'SOA')
            return 1
        except Exception:
            return 0

    tld_exist = check_dns(tld)

    shorteners = {
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
        'is.gd', 'buff.ly', 'adf.ly', 'short.io', 'rebrand.ly',
        'tiny.cc', 'lnkd.in', 'db.tt', 'qr.ae', 'cur.lv',
    }
    is_shortened = int(any(s in domain for s in shorteners)) if domain else 0

    def ip_typ(ip):
        try:
            obj = ipaddress.ip_address(ip)
            return 0 if obj.is_private else (1 if obj.is_global else 2)
        except Exception:
            return -1

    ip_type = ip_typ(domain) if domain else -1
    depth   = path.count('/') if path and pd.notna(path) else 0
    dot3    = 1 if dots > 3 else 0
    redir = 1 if str(port).replace("://", "").count("//") > 0 else -1
    prefsuff = 1 if "-" in str(domain) else -1
    nonStdPort = 1 if port and (port not in [80, 443]) else -1
    def entropy(s):
        if not isinstance(s, str) or len(s) == 0:
            return 0
        probs = [c/len(s) for c in Counter(s).values()]
        return -sum(p * math.log2(p) for p in probs)

    d_entropy = entropy(domain)
    HTTPSDomainURL = 1 if "https" in (str(domain) + str(path)).lower() else -1
        
    def domain_age(domain):
        try:
            w = whois.whois(domain)
            created = w.creation_date
            created = created[0] if isinstance(created, list) else created
            if not created:
                return 0
            created_str = created.isoformat().replace("+00:00", "").replace("Z", "")
            age_days = (datetime.now() - datetime.fromisoformat(created_str)).days
            return 1 if age_days >= 365 else -1
        except Exception:
            return 0

    def domain_end_period(domain):
        try:
            w = whois.whois(domain)
            expires = w.expiration_date
            expires = expires[0] if isinstance(expires, list) else expires
            if not expires:
                return 0
            expires_str = expires.isoformat().replace("+00:00", "").replace("Z", "")
            remaining_days = (datetime.fromisoformat(expires_str) - datetime.now()).days
            return -1 if remaining_days <= 180 else 1
        except Exception:
            return 0

    dom_age = domain_age(domain)
    dom_end = domain_end_period(domain)

    def web_traffic_single(domain):
        try:
            r = requests.get(
                f"https://tranco-list.eu/api/ranks/domain/{domain}",
                timeout=5
            )
            ranks = r.json().get("ranks", [])
            rank = ranks[0].get("rank", 0) if ranks else 0
            if rank <= 100_000:
                return 1
            if rank <= 500_000:
                return 0
            return -1
        except Exception:
            return -1
    
    web_traf = web_traffic_single(domain)

    url_info = [[
        leng, dots, ats, hyp, undsc, slsh, dbslsh, bcksl,
        quem, ast, amp, eq, perc, digits, char, digtochar,port,
        domain_leng, has_dig, HTTPSDomainURL, subd_count,
        tld_exist, is_shortened, ip_type, depth, dot3,redir,prefsuff,nonStdPort,d_entropy, dom_age, dom_end, web_traf
    ]]

    st.write(dict(zip(['leng','dots','ats','hyp','undsc','slsh','dbslsh','bcksl',
     'quem','ast','amp','eq','perc','digits','char','digtochar','port',
     'domain_leng','has_dig','HTTPSDomainURL','subd_count',
     'tld_exist','is_shortened','ip_type','depth','dot3','redir',
     'prefsuff','nonStdPort','d_entropy','dom_age','dom_end','web_traf'],
    url_info[0])))
    st.write(f"dom_age={dom_age}, dom_end={dom_end}, web_traf={web_traf}, is_https={is_https}")
    verdict = rf.predict(url_info)[0].capitalize()
    proba   = rf.predict_proba(url_info)
    return verdict, proba


def render_result(url, verdict, prob):
    is_legit = verdict.lower() == "legitimate"
    css = "verdict-legit" if is_legit else "verdict-phish"
    lp  = round(prob[0][0] * 100, 1)
    pp  = round(prob[0][1] * 100, 1)

    st.markdown(f"""
    <div class="result-item">
        <div class="result-url">{url}</div>
        <div class="result-verdict {css}">{"✓ Legitimate" if is_legit else "✗ Phishing"}</div>
        <div class="bar-row">
            <span class="bar-label">Legitimate</span>
            <div class="bar-bg"><div class="bar-fill-legit" style="width:{lp}%"></div></div>
            <span class="bar-pct">{lp}%</span>
        </div>
        <div class="bar-row">
            <span class="bar-label">Phishing</span>
            <div class="bar-bg"><div class="bar-fill-phish" style="width:{pp}%"></div></div>
            <span class="bar-pct">{pp}%</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

def is_reachable(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        host = urlparse(url).hostname
        if not host:
            return False
        socket.setdefaulttimeout(4)
        socket.gethostbyname(host)
        return True
    except Exception:
        return False

def render_invalid(url, reason="Not a valid URL"):
    st.markdown(f"""
    <div class="result-item">
        <div class="result-url">{url or "(empty)"}</div>
        <div class="result-verdict verdict-invalid">{reason}</div>
    </div>
    """, unsafe_allow_html=True)

def main():
    st.markdown("<h1>Phishing or Legitimate?</h1>", unsafe_allow_html=True)
    st.markdown('<p class="subtitle">Paste one or more URLs, separated by commas</p>', unsafe_allow_html=True)

    textt = st.text_area("", placeholder="https://example.com, https://another.com", height=90)

    if st.button("Check"):
        urls = [u.strip() for u in textt.split(",") if u.strip()]
        if not urls:
            st.warning("Please enter at least one URL.")
            return
        for url in urls:
            if '.' not in url:
                render_invalid(url)
                continue

            verdict, prob = check(url)
            render_result(url, verdict, prob)


if __name__ == "__main__":
    main()
