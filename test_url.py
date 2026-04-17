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
import numpy as np
import concurrent.futures
import time
import re
warnings.filterwarnings("ignore", category=UserWarning)
rf = joblib.load('random_forest.joblib')
FEATURE_COLS = [
    'url_len', 'dot_count', 'at_count', 'hyphen_count', 'undersc_count',
    'slash_count', 'doubleslash_count', 'backslash_count', 'quemark_count',
    'asterisk_count', 'ampersand_count', 'equalto_count', 'percent_count',
    'numeric_count', 'letter_count', 'num_to_alpha', 'port',
    'domain_length', 'has_digit', 'HTTPSDomainURL', 'subd_count',
    'tld_exists', 'is_shortened', 'ip_type', 'path_depth', 'dot>3',
    'redirecting//', 'prefsuff', 'nonStdPort', 'domain_entropy',
    'web_traffic',
]
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
    border: 1px solid #ddd !important; border-radius: 8px !important;
    font-size: 0.9rem !important; font-family: 'Inter', sans-serif !important;
    padding: 0.6rem 0.8rem !important; resize: none !important;
}
.stTextArea textarea:focus { border-color: #999 !important; box-shadow: none !important; }
.stTextArea label { display: none; }
.stButton > button {
    background: #111 !important; color: #fff !important; border: none !important;
    border-radius: 8px !important; padding: 0.5rem 1.4rem !important;
    font-size: 0.88rem !important; font-family: 'Inter', sans-serif !important;
    font-weight: 500 !important; transition: background 0.15s !important;
}
.stButton > button:hover { background: #333 !important; }
.result-item {
    border: 1px solid #e8e8e8; border-radius: 10px;
    padding: 1rem 1.1rem; margin-bottom: 0.75rem; background: #fff;
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
def _raw_whois(domain):
    """Runs inside a thread so we can enforce a hard timeout."""
    w = whois.whois(domain)
    created = w.creation_date
    expires = w.expiration_date
    created = created[0] if isinstance(created, list) else created
    expires = expires[0] if isinstance(expires, list) else expires
    return created, expires
@st.cache_data(ttl=86400, show_spinner=False)
def safe_whois(domain: str, timeout: int = 10):
    """
    Returns (created_datetime | None, expires_datetime | None).
    Never raises — always returns a 2-tuple.
    """
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(_raw_whois, domain)
            created, expires = future.result(timeout=timeout)
            return created, expires
    except Exception:
        pass
    try:
        r = requests.get(
            f"https://rdap.org/domain/{domain}", timeout=8
        )
        events = r.json().get("events", [])
        created_str = next(
            (e["eventDate"] for e in events if e.get("eventAction") == "registration"),
            None,
        )
        expires_str = next(
            (e["eventDate"] for e in events if e.get("eventAction") == "expiration"),
            None,
        )
        created = datetime.fromisoformat(created_str.replace("Z", "")) if created_str else None
        expires = datetime.fromisoformat(expires_str.replace("Z", "")) if expires_str else None
        return created, expires
    except Exception:
        return None, None
def _strip_tz(dt):
    """Remove timezone info so arithmetic works."""
    if dt is None:
        return None
    return dt.replace(tzinfo=None) if hasattr(dt, "tzinfo") and dt.tzinfo else dt
def domain_age(domain: str) -> int:
    created, _ = safe_whois(domain)
    created = _strip_tz(created)
    if created is None:
        return -1
    try:
        return 1 if (datetime.now() - created).days >= 365 else -1
    except Exception:
        return -1
def domain_end_period(domain: str) -> int:
    _, expires = safe_whois(domain)
    expires = _strip_tz(expires)
    if expires is None:
        return -1
    try:
        return 1 if (expires - datetime.now()).days > 180 else -1
    except Exception:
        return -1
@st.cache_data(ttl=3600, show_spinner=False)
def web_traffic_single(domain: str) -> int:
    try:
        r = requests.get(
            f"https://tranco-list.eu/api/ranks/domain/{domain}", timeout=6
        )
        ranks = r.json().get("ranks", [])
        rank = ranks[0].get("rank", 0) if ranks else 0
        if 0 < rank <= 10_000:
            return 1
        if 0 < rank <= 500_000:
            return 0
        return -1
    except Exception:
        return -1
def check_dns(tld: str) -> int:
    try:
        dns.resolver.resolve(tld + ".", "SOA", lifetime=3)
        return 1
    except Exception:
        return 0
def entropy(s: str) -> float:
    if not isinstance(s, str) or not s:
        return 0.0
    probs = [c / len(s) for c in Counter(s).values()]
    return -sum(p * math.log2(p) for p in probs)
def count_subd(url: str) -> int:
    try:
        subd = tldextract.extract(url).subdomain
        return len(subd.split('.')) if subd else 0
    except Exception:
        return 0
def ip_typ(host: str) -> int:
    try:
        obj = ipaddress.ip_address(host)
        if obj.is_private:
            return 0
        if obj.is_global:
            return 1
        return 2
    except Exception:
        return -1
def clean_domain(host):
    if not host:
        return None
    host = str(host).lower().strip()
    if host.startswith("www."):
        host = host[4:]
    return host
def extract_features(inp: str) -> pd.DataFrame:
    inp = inp.strip()
    inp = re.sub(r'^(https?://)?www\.', r'\1', inp)
    leng    = len(inp)
    dots    = inp.count(".")
    ats     = inp.count("@")
    hyp     = inp.count("-")
    undsc   = inp.count("_")
    slsh    = inp.count("/")
    dbslsh  = inp.count("//")
    bcksl   = inp.count("\\")
    quem    = inp.count("?")
    ast     = inp.count("*")
    amp     = inp.count("&")
    eq      = inp.count("=")
    perc    = inp.count("%")
    digits  = sum(c.isdigit() for c in inp)
    char    = sum(c.isalpha() for c in inp)
    digtochar = digits / char if char else 0
    try:
        res = urlsplit(inp)
        sch, path, port = res.scheme, res.path, res.port
    except Exception:
        sch, path, port = None, None, None
    try:
        raw_host = urlparse(inp).hostname
    except Exception:
        raw_host = None
    domain = clean_domain(raw_host) or ""
    domain_leng = len(domain)
    tld_str    = tldextract.extract(inp).suffix
    subd_count = count_subd(inp)
    has_dig    = int(any(c.isdigit() for c in domain))
    HTTPSDomainURL = 1 if "https" in (domain + (path or "")).lower() else -1
    tld_exist    = check_dns(tld_str) if tld_str else 0
    shorteners   = {
        "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly",
        "adf.ly","short.io","rebrand.ly","tiny.cc","lnkd.in","db.tt","qr.ae","cur.lv",
    }
    is_shortened = int(domain in shorteners) if domain else 0
    ip_type      = ip_typ(domain) if domain else -1
    depth        = path.count("/") if path else 0
    dot3         = 1 if dots > 3 else 0
    port_val     = port if port is not None else (443 if sch == "https" else 80)
    redir        = 1 if inp.replace("://", "").count("//") > 0 else -1
    prefsuff     = 1 if "-" in domain else -1
    nonStdPort   = 1 if port is not None and port not in [80, 443] else -1
    d_entropy    = entropy(domain)
    dom_age = domain_age(domain) if domain else -1
    dom_end = domain_end_period(domain) if domain else -1
    web_traf = web_traffic_single(domain) if domain else -1
    port_feature = port if port is not None else np.nan
    features = {
        "url_len":        leng,
        "dot_count":      dots,
        "at_count":       ats,
        "hyphen_count":   hyp,
        "undersc_count":  undsc,
        "slash_count":    slsh,
        "doubleslash_count": dbslsh,
        "backslash_count": bcksl,
        "quemark_count":  quem,
        "asterisk_count": ast,
        "ampersand_count": amp,
        "equalto_count":  eq,
        "percent_count":  perc,
        "numeric_count":  digits,
        "letter_count":   char,
        "num_to_alpha":   digtochar,
        "port":           port_feature,
        "domain_length":  domain_leng,
        "has_digit":      has_dig,
        "HTTPSDomainURL": HTTPSDomainURL,
        "subd_count":     subd_count,
        "tld_exists":     tld_exist,
        "is_shortened":   is_shortened,
        "ip_type":        ip_type,
        "path_depth":     depth,
        "dot>3":          dot3,
        "redirecting//":  redir,
        "prefsuff":       prefsuff,
        "nonStdPort":     nonStdPort,
        "domain_entropy": d_entropy,
        "DomainAge":      dom_age,
        "DomainEndPeriod": dom_end,
        "web_traffic":    web_traf,
    }
    return pd.DataFrame([features], columns=FEATURE_COLS)
def check(inp: str):
    df = extract_features(inp)
    verdict = rf.predict(df)[0].capitalize()
    proba   = rf.predict_proba(df)
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
            <div class="bar-bg"><div class="bar-fill-legit" style="width:  {lp}%"></div></div>
            <span class="bar-pct">{lp}%</span>
        </div>
        <div class="bar-row">
            <span class="bar-label">Phishing</span>
            <div class="bar-bg"><div class="bar-fill-phish" style="width:{pp}%"></div></div>
            <span class="bar-pct">{pp}%</span>
        </div>
    </div>
    """, unsafe_allow_html=True)
def render_invalid(url, reason="Not a valid URL"):
    st.markdown(f"""
    <div class="result-item">
        <div class="result-url">{url or "(empty)"}</div>
        <div class="result-verdict verdict-invalid">{reason}</div>
    </div>
    """, unsafe_allow_html=True)
def main():
    st.markdown("<h1>Phishing or Legitimate?</h1>", unsafe_allow_html=True)
    st.markdown('<p class="subtitle">Paste one or more URLs, separated by commas</p>',
                unsafe_allow_html=True)
    textt = st.text_area("", placeholder="https://example.com, https://another.com", height=90)
    if st.button("Check"):
        urls = [u.strip() for u in textt.split(",") if u.strip()]
        if not urls:
            st.warning("Please enter at least one URL.")
            return
        for url in urls:
            if "." not in url:
                render_invalid(url)
                continue
            verdict, prob = check(url)
            render_result(url, verdict, prob)
if __name__ == "__main__":
    main()
