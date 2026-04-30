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
from gensim.models import FastText

warnings.filterwarnings("ignore", category=UserWarning)
rf = joblib.load('random_forest.joblib')

model = FastText.load("url_word2vec.model")

FEATURE_COLS = [
    'url_len', 'dot_count', 'at_count', 'hyphen_count', 'undersc_count',
    'slash_count', 'doubleslash_count', 'backslash_count', 'quemark_count',
    'asterisk_count', 'ampersand_count', 'equalto_count', 'percent_count',
    'numeric_count', 'letter_count', 'num_to_alpha', 'port',
    'domain_length', 'has_digit', 'HTTPSDomainURL', 'subd_count',
    'tld_exists', 'is_shortened', 'ip_type', 'path_depth', 'dot>3',
    'redirecting//', 'prefsuff', 'nonStdPort', 'domain_entropy',
    'web_traffic',
] + [f'embed_{i}' for i in range(model.vector_size)]  

FEATURE_META = {
    'url_len': ('URL length', 'Longer URLs are more suspicious'),
    'dot_count': ('Dot count', 'Many dots suggest subdomain abuse'),
    'at_count': ('@ symbols', '@ in URL tricks browsers into ignoring the real domain'),
    'hyphen_count': ('Hyphens', 'Hyphens often used to mimic brands (e.g. paypal-login.com)'),
    'undersc_count': ('Underscores', 'Unusual in legitimate domains'),
    'slash_count': ('Slash count', 'Deep paths can indicate redirect tricks'),
    'doubleslash_count': ('Double slashes', 'Extra // can indicate redirection abuse'),
    'backslash_count': ('Backslashes', 'Backslashes are not valid in URLs'),
    'quemark_count': ('Question marks', 'Many query params can indicate obfuscation'),
    'asterisk_count': ('Asterisks', 'Wildcards are unusual in real URLs'),
    'ampersand_count': ('Ampersands', 'Excessive params can signal phishing forms'),
    'equalto_count': ('Equal signs', 'Many = signs suggest heavy query manipulation'),
    'percent_count': ('Percent encoding', 'Encoding used to hide malicious characters'),
    'numeric_count': ('Digit count', 'Many digits in URL is unusual for legitimate sites'),
    'letter_count': ('Letter count', 'Baseline character count'),
    'num_to_alpha': ('Digit-to-letter ratio', 'High ratio means URL is mostly numbers'),
    'port': ('Port number', 'Non-standard port suggests unusual server setup'),
    'domain_length': ('Domain length', 'Very long domains are suspicious'),
    'has_digit': ('Digit in domain', 'Numbers in domain name can mimic brands'),
    'HTTPSDomainURL': ('HTTPS in domain/path', 'Embedding https in URL text to appear secure'),
    'subd_count': ('Subdomain count', 'Many subdomains is a phishing technique'),
    'tld_exists': ('TLD valid', 'Invalid TLD means the domain cannot resolve'),
    'is_shortened': ('URL shortener', 'Shorteners hide the real destination'),
    'ip_type': ('IP address type', 'IP-based URLs skip domain validation'),
    'path_depth': ('Path depth', 'Very deep paths can indicate phishing redirects'),
    'dot>3': ('More than 3 dots', 'Excessive dots indicate subdomain abuse'),
    'redirecting//': ('Redirect double-slash', 'Double slash after domain signals redirection'),
    'prefsuff': ('Hyphen in domain', 'Hyphens used to fake brand names'),
    'nonStdPort': ('Non-standard port', 'Ports other than 80/443 are suspicious'),
    'domain_entropy': ('Domain entropy', 'High randomness in domain name suggests DGA'),
    'web_traffic': ('Web traffic rank', 'Low-traffic or unknown domains are more risky'),

}

PHISH_THRESHOLDS = {
    'url_len': 75,
    'dot_count': 4,
    'hyphen_count': 3,
    'slash_count': 5,
    'at_count': 1,
    'backslash_count': 1,
    'quemark_count': 2,
    'asterisk_count': 1,
    'ampersand_count': 3,
    'equalto_count': 3,
    'percent_count': 3,
    'numeric_count': 10,
    'num_to_alpha': 0.3,
    'domain_length': 30,
    'subd_count': 3,
    'path_depth': 5,
    'domain_entropy': 4.0,
    'doubleslash_count': 1,
    'undersc_count': 2,
}

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
    padding: 1rem 1.1rem; margin-bottom: 0.4rem; background: #fff;
}
.result-url { font-size: 0.78rem; color: #888; word-break: break-all; margin-bottom: 0.45rem; }
.result-verdict { font-size: 1rem; font-weight: 600; margin-bottom: 0.6rem; }
.verdict-legit { color: #1a9e5c; }
.verdict-phish { color: #d63c3c; }
.verdict-uncertain{ color: #d47c00; }
.verdict-invalid { color: #999; }
.verdict-rule { font-size: 0.72rem; color: #aaa; margin-top: 0.1rem; }f
.bar-row { display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.3rem; }
.bar-label { font-size: 0.75rem; color: #999; width: 65px; flex-shrink: 0; }
.bar-bg { flex: 1; height: 5px; background: #f0f0f0; border-radius: 3px; overflow: hidden; }
.bar-fill-legit { height: 100%; background: #1a9e5c; border-radius: 3px; }
.bar-fill-phish { height: 100%; background: #d63c3c; border-radius: 3px; }
.bar-pct { font-size: 0.75rem; color: #aaa; width: 38px; text-align: right; }
.feat-table { width: 100%; border-collapse: collapse; font-size: 0.8rem; margin-top: 0.5rem; }
.feat-table th {
    text-align: left; color: #edf2ef; font-weight: 500;
    border-bottom: 1px solid #eee; padding: 0.3rem 0.4rem;
}
.feat-table td { padding: 0.35rem 0.4rem; color: #edf2ef; vertical-align: top; }
.feat-risk-high { color: #d63c3c; font-weight: 500; }
.feat-risk-low { color: #1a9e5c; font-weight: 500; }
.feat-risk-neutral { color: #888; }
.feat-imp-bar {
    display: inline-block; height: 7px; border-radius: 3px;
    background: #d0d0d0; vertical-align: middle; margin-right: 6px;
}
</style>
""", unsafe_allow_html=True)


def _raw_whois(domain):
    w = whois.whois(domain)
    created = w.creation_date
    expires = w.expiration_date
    created = created[0] if isinstance(created, list) else created
    expires = expires[0] if isinstance(expires, list) else expires
    return created, expires

@st.cache_data(ttl=86400, show_spinner=False)
def safe_whois(domain: str, timeout: int = 10):
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(_raw_whois, domain)
            created, expires = future.result(timeout=timeout)
            return created, expires
    except Exception:
        pass
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=8)
        events = r.json().get("events", [])
        created_str = next((e["eventDate"] for e in events if e.get("eventAction") == "registration"), None)
        expires_str = next((e["eventDate"] for e in events if e.get("eventAction") == "expiration"), None)
        created = datetime.fromisoformat(created_str.replace("Z", "")) if created_str else None
        expires = datetime.fromisoformat(expires_str.replace("Z", "")) if expires_str else None
        return created, expires
    except Exception:
        return None, None

def _strip_tz(dt):
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
    for d in [domain, 'www.' + domain]:
        try:
            r = requests.get(
                f"https://tranco-list.eu/api/ranks/domain/{d}", timeout=6
            )
            ranks = r.json().get("ranks", [])
            rank = ranks[0].get("rank", 0) if ranks else 0
            if 0 < rank <= 10_000:  return 1
            if 0 < rank <= 500_000: return 0
        except Exception:
            continue
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
        if obj.is_private: return 0
        if obj.is_global:  return 1
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



def tokenize_url(url):
    url = url.lower().strip()
    if not url.startswith("http"):
        url = "http://" + url
    parsed = urlparse(url)
    tokens  = re.split(r'[^a-z0-9]', parsed.netloc)
    tokens += re.split(r'[^a-z0-9]', parsed.path)
    tokens += re.split(r'[^a-z0-9]', parsed.query)
    return [t for t in tokens if t]

def url_embedding(url):
    tokens = tokenize_url(url)
    vecs = [model.wv[w] for w in tokens if w in model.wv]
    return np.mean(vecs, axis=0) if vecs else np.zeros(model.vector_size)


def extract_features(inp: str) -> pd.DataFrame:
    inp = inp.strip()
    inp = re.sub(r'^(https?://)?www\.', r'\1', inp)
    leng = len(inp)
    dots = inp.count(".")
    ats = inp.count("@")
    hyp = inp.count("-")
    undsc = inp.count("_")
    slsh = inp.count("/")
    dbslsh = inp.count("//")
    bcksl = inp.count("\\")
    quem = inp.count("?")
    ast = inp.count("*")
    amp = inp.count("&")
    eq = inp.count("=")
    perc = inp.count("%")
    digits = sum(c.isdigit() for c in inp)
    char = sum(c.isalpha() for c in inp)
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
    tld_str = tldextract.extract(inp).suffix
    subd_count = count_subd(inp)
    has_dig = int(any(c.isdigit() for c in domain))
    HTTPSDomainURL = 1 if "https" in (domain + (path or "")).lower() else -1
    tld_exist = check_dns(tld_str) if tld_str else 0
    shorteners  = {"bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly",
                   "adf.ly","short.io","rebrand.ly","tiny.cc","lnkd.in","db.tt","qr.ae","cur.lv"}
    is_shortened = int(domain in shorteners) if domain else 0
    ip_type = ip_typ(domain) if domain else -1
    depth = path.count("/") if path else 0
    dot3 = 1 if dots > 3 else 0
    redir = 1 if inp.replace("://", "").count("//") > 0 else 0
    prefsuff = 1 if "-" in domain else -1
    nonStdPort = 1 if port is not None and port not in [80, 443] else -1
    d_entropy = entropy(domain)
    dom_age = domain_age(domain) if domain else -1
    dom_end = domain_end_period(domain) if domain else -1
    web_traf = web_traffic_single(domain) if domain else -1
    emb = url_embedding(inp)
    embed_cols = [f'embed_{i}' for i in range(model.vector_size)]
    embed_dict = dict(zip(embed_cols, emb))
    port_feature = port if port is not None else np.nan


    features = {
        "url_len": leng, "dot_count": dots, "at_count": ats,
        "hyphen_count": hyp, "undersc_count": undsc, "slash_count": slsh,
        "doubleslash_count": dbslsh, "backslash_count": bcksl,
        "quemark_count": quem, "asterisk_count": ast, "ampersand_count": amp,
        "equalto_count": eq, "percent_count": perc, "numeric_count": digits,
        "letter_count": char, "num_to_alpha": digtochar, "port": port_feature,
        "domain_length": domain_leng, "has_digit": has_dig,
        "HTTPSDomainURL": HTTPSDomainURL, "subd_count": subd_count,
        "tld_exists": tld_exist, "is_shortened": is_shortened,
        "ip_type": ip_type, "path_depth": depth, "dot>3": dot3,
        "redirecting//": redir, "prefsuff": prefsuff, "nonStdPort": nonStdPort,
        "domain_entropy": d_entropy, "DomainAge": dom_age,
        "DomainEndPeriod": dom_end, "web_traffic": web_traf,
    }
    features.update(embed_dict)
    return pd.DataFrame([features], columns=FEATURE_COLS)


def apply_hard_rules(feature_df: pd.DataFrame) -> tuple[str | None, str | None]:
    """
    Returns (verdict, reason) if a hard rule fires, else (None, None).
    verdict is 'Phishing' or 'Legitimate'.
    """
    row = feature_df.iloc[0]

    if row.get('at_count', 0) > 0:
        return 'Phishing', '@ symbol found in URL'
    if row.get('is_shortened', 0) == 1:
        return 'Phishing', 'URL shortener detected'
    if row.get('tld_exists', 1) == 0:
        return 'Phishing', 'TLD does not exist in DNS'
    if row.get('ip_type', -1) in [0, 1, 2]:
        return 'Phishing', 'IP address used instead of domain'
    if row.get('dot_count', 0) > 6:
        return 'Phishing', f"Excessive dots ({int(row['dot_count'])})"
    if row.get('url_len', 0) > 200:
        return 'Phishing', f"URL too long ({int(row['url_len'])} chars)"
    if row.get('backslash_count', 0) > 0:
        return 'Phishing', 'Backslash found in URL'

    if row.get('web_traffic', -1) == 1:
        return 'Legitimate', 'Top-10,000 ranked domain (Tranco)'

    return None, None  


CONFIDENCE_THRESHOLD = 0.65

def check(inp: str):
    """
    Returns (verdict, proba, feature_df, rule_reason)
    verdict: 'Phishing' | 'Legitimate' | 'Uncertain'
    rule_reason: str if rule fired, else None
    """
    feat_df = extract_features(inp)
    rule_verdict, rule_reason = apply_hard_rules(feat_df)

    if rule_verdict is not None:
        if rule_verdict == 'Phishing':
            proba = np.array([[0.05, 0.95]])
        else:
            proba = np.array([[0.95, 0.05]])
        return rule_verdict, proba, feat_df, rule_reason
    feat_df = feat_df.reindex(columns=rf.feature_names_in_, fill_value=0)
    proba = rf.predict_proba(feat_df)
    ml_prob = proba[0][1]   

    if ml_prob >= CONFIDENCE_THRESHOLD:
        verdict = 'Phishing'
    elif ml_prob <= (1 - CONFIDENCE_THRESHOLD):
        verdict = 'Legitimate'
    else:
        verdict = 'Uncertain'

    return verdict, proba, feat_df, None


def risk_signal(col, val):
    phish_if_one = {'dot>3', 'redirecting//', 'nonStdPort', 'is_shortened', 'has_digit'}
    safe_if_one  = {'tld_exists'}
    safe_if_high = {'web_traffic', 'letter_count'}

    try:
        v = float(val)
    except (TypeError, ValueError):
        return 'neutral', '—'

    if col in PHISH_THRESHOLDS:
        threshold = PHISH_THRESHOLDS[col]
        return ('high' if v > threshold else 'low'), f'{v:.3g}'
    if col in phish_if_one:
        return ('high' if v == 1 else 'low'), ('Yes' if v == 1 else 'No')
    if col in safe_if_one:
        return ('low' if v == 1 else 'high'), ('Yes' if v == 1 else 'No')
    if col in safe_if_high:
        return ('low' if v > 0 else 'high'), f'{v:.3g}'
    if col == 'ip_type':
        label = {0: 'Private IP', 1: 'Public IP', 2: 'Other IP'}.get(int(v), 'Not IP')
        return ('high' if v >= 0 else 'neutral'), label
    if col == 'prefsuff':
        return ('high' if v == 1 else 'neutral'), ('Yes' if v == 1 else 'No')
    if col == 'HTTPSDomainURL':
        return 'neutral', ('Yes' if v == 1 else 'No')
    return 'neutral', f'{v:.3g}'


def build_explanation(feature_df: pd.DataFrame) -> str:
    importances = rf.feature_importances_
    feat_imp = dict(zip(FEATURE_COLS, importances))

    rows = []
    for col, (label, explanation) in FEATURE_META.items():
        val = feature_df[col].iloc[0]
        imp = feat_imp.get(col, 0)
        rows.append((imp, col, label, explanation, val))

    rows.sort(reverse=True)
    top_rows = rows[:12]
    max_imp = max(r[0] for r in top_rows) or 1

    html_rows = ""
    for imp, col, label, explanation, val in top_rows:
        bar_w = int((imp / max_imp) * 55)
        risk, display_val = risk_signal(col, val)
        risk_css = {'high': 'feat-risk-high', 'low': 'feat-risk-low'}.get(risk, 'feat-risk-neutral')
        signal_txt = {'high': '⚠ Suspicious', 'low': '✓ Safe'}.get(risk, '—')

        html_rows += f"""
        <tr>
          <td>
            <span class="feat-imp-bar" style="width:{bar_w}px"></span>
            <strong>{label}</strong><br>
            <span style="color:#aaa;font-size:0.71rem">{explanation}</span>
          </td>
          <td style="text-align:center;white-space:nowrap" class="{risk_css}">{display_val}</td>
          <td style="text-align:center;white-space:nowrap" class="{risk_css}">{signal_txt}</td>
        </tr>"""

    return f"""
    <table class="feat-table">
      <thead>
        <tr>
          <th>Feature <span style="color: #FFFFFF ;font-weight:400;font-size:0.7rem">(bar = importance)</span></th>
          <th style="text-align:center">Value</th>
          <th style="text-align:center">Signal</th>
        </tr>
      </thead>
      <tbody>{html_rows}</tbody>
    </table>
    <p style="font-size:0.71rem;color:#ccc;margin-top:0.6rem">
      Top 12 features by model importance. FastText embedding features are excluded from this view.
    </p>
    """


def render_result(url, verdict, prob, feature_df, rule_reason):
    is_legit = verdict.lower() == 'legitimate'
    is_uncertain = verdict.lower() == 'uncertain'
    css = 'verdict-uncertain' if is_uncertain else ('verdict-legit' if is_legit else 'verdict-phish')
    icon = '? Uncertain' if is_uncertain else ('✓ Legitimate'  if is_legit else '✗ Phishing')
    lp = round(prob[0][0] * 100, 1)
    pp = round(prob[0][1] * 100, 1)

    with st.container(border=True):
        st.markdown(f'<div class="result-url">{url}</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="result-verdict {css}">{icon}</div>', unsafe_allow_html=True)

        if rule_reason:
            st.caption(f"🔎 Rule: {rule_reason}")

        col1, col2 = st.columns([1, 4])
        with col1:
            st.caption("Legitimate")
        with col2:
            st.progress(lp / 100, text=f"{lp}%")

        col3, col4 = st.columns([1, 4])
        with col3:
            st.caption("Phishing")
        with col4:
            st.progress(pp / 100, text=f"{pp}%")

        with st.expander("Why this verdict? — feature breakdown"):
            if rule_reason:
                st.markdown(
                    f"<p style='font-size:0.85rem;color:#555;margin-bottom:0.75rem'>"
                    f"<strong>Hard rule fired:</strong> {rule_reason} — ML was not used.</p>",
                    unsafe_allow_html=True
                )
            st.markdown(build_explanation(feature_df), unsafe_allow_html=True)
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
            try:
                ext = tldextract.extract(url)
                host_str = '.'.join(filter(None, [ext.subdomain, ext.domain, ext.suffix]))
                socket.gethostbyname(host_str)
            except Exception:
                render_invalid(url, "Website doesn't exist")
                continue

            verdict, prob, feature_df, rule_reason = check(url)
            render_result(url, verdict, prob, feature_df, rule_reason)


if __name__ == "__main__":
    main()
