"""
Extracts the 25 live-computable phishing-detection features from a raw URL,
in the same convention as the trimmed dataset/schema (data_schema/schema_trimmed.yaml):
    -1 = suspicious/phishing-leaning, 0 = borderline/unknown, 1 = legitimate-leaning

Requires: requests, beautifulsoup4, python-whois, dnspython, tldextract
    pip install requests beautifulsoup4 python-whois dnspython tldextract --break-system-packages

Every check is wrapped so a single failed lookup (site down, WHOIS blocked, etc.)
falls back to a neutral 0 rather than crashing the whole extraction.
"""
import re
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse

import requests
import tldextract
import dns.resolver
import whois
from bs4 import BeautifulSoup

REQUEST_TIMEOUT = 6
HEADERS = {"User-Agent": "Mozilla/5.0 (NetworkSecurityBot/1.0)"}

SHORTENER_PATTERN = re.compile(
    r"(bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|"
    r"cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|"
    r"snipurl\.com|short\.to|budurl\.com|ping\.fm|post\.ly|just\.as|bkite\.com|snipr\.com|"
    r"fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|"
    r"bit\.do|lnkd\.in|db\.tt|qr\.ae|adf\.ly|bitly\.com|cur\.lv|tinyurl\.com|ity\.im|"
    r"q\.gs|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|"
    r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|"
    r"v\.gd|tr\.im|link\.zip\.net)",
    re.IGNORECASE,
)

TRUSTED_CERT_ISSUERS = {
    "let's encrypt", "digicert", "sectigo", "godaddy", "globalsign",
    "comodo", "amazon", "google trust services", "cloudflare",
}


def _safe(fn, default=0):
    try:
        return fn()
    except Exception:
        return default


def _get_domain(url):
    ext = tldextract.extract(url)
    return ".".join(part for part in [ext.domain, ext.suffix] if part)


def _get_hostname(url):
    return urlparse(url).hostname or ""


def having_ip_address(url):
    hostname = _get_hostname(url)
    ip_pattern = re.compile(
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    )
    return -1 if ip_pattern.match(hostname) else 1


def url_length(url):
    n = len(url)
    if n < 54:
        return 1
    elif n <= 75:
        return 0
    return -1


def shortining_service(url):
    return -1 if SHORTENER_PATTERN.search(url) else 1


def having_at_symbol(url):
    return -1 if "@" in url else 1


def double_slash_redirecting(url):
    last_double_slash = url.rfind("//")
    return -1 if last_double_slash > 7 else 1


def prefix_suffix(url):
    domain = _get_hostname(url)
    return -1 if "-" in domain else 1


def having_sub_domain(url):
    ext = tldextract.extract(url)
    subdomain = ext.subdomain
    if not subdomain:
        return 1
    dots = subdomain.count(".") + 1
    if dots <= 1:
        return 0
    return -1


def https_token(url):
    hostname = _get_hostname(url)
    return -1 if "https" in hostname.replace("www.", "") else 1


def get_port(url):
    parsed = urlparse(url)
    port = parsed.port
    if port is None or port in (80, 443):
        return 1
    return -1


def ssl_final_state(url):
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return -1

    def _check():
        hostname = parsed.hostname
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=REQUEST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        issuer = dict(x[0] for x in cert.get("issuer", []))
        issuer_name = issuer.get("organizationName", "").lower()
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        age_days = (not_after - datetime.utcnow()).days
        trusted = any(t in issuer_name for t in TRUSTED_CERT_ISSUERS)
        if trusted and age_days > 180:
            return 1
        return 0

    return _safe(_check, default=0)


def domain_registration_length(url):
    def _check():
        domain = _get_domain(url)
        w = whois.whois(domain)
        expiry = w.expiration_date
        created = w.creation_date
        if isinstance(expiry, list):
            expiry = expiry[0]
        if isinstance(created, list):
            created = created[0]
        if not expiry or not created:
            return 0
        months = (expiry - created).days / 30
        return -1 if months <= 12 else 1

    return _safe(_check, default=0)


def favicon(url):
    def _check():
        resp = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
        soup = BeautifulSoup(resp.text, "html.parser")
        page_domain = _get_domain(url)
        icon_link = soup.find("link", rel=lambda v: v and "icon" in v.lower())
        if icon_link is None or not icon_link.get("href"):
            return 1  # no favicon declared, not inherently suspicious
        href = icon_link["href"]
        if href.startswith("http"):
            icon_domain = _get_domain(href)
            return 1 if icon_domain == page_domain else -1
        return 1  # relative path, same domain

    return _safe(_check, default=0)


def _fetch_page(url):
    resp = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT, allow_redirects=True)
    return resp, BeautifulSoup(resp.text, "html.parser")


def request_url(soup, page_domain):
    tags = soup.find_all(["img", "script", "audio", "embed", "iframe"])
    total, external = 0, 0
    for tag in tags:
        src = tag.get("src")
        if not src or not src.startswith("http"):
            continue
        total += 1
        if _get_domain(src) != page_domain:
            external += 1
    if total == 0:
        return 1
    pct = external / total
    if pct < 0.22:
        return 1
    elif pct <= 0.61:
        return 0
    return -1


def url_of_anchor(soup, page_domain):
    anchors = soup.find_all("a")
    total, suspicious = 0, 0
    for a in anchors:
        href = a.get("href")
        if not href:
            continue
        total += 1
        if href.startswith("#") or href.lower().startswith("javascript:") or href.strip() == "":
            suspicious += 1
        elif href.startswith("http") and _get_domain(href) != page_domain:
            suspicious += 1
    if total == 0:
        return 1
    pct = suspicious / total
    if pct < 0.31:
        return 1
    elif pct <= 0.67:
        return 0
    return -1


def links_in_tags(soup, page_domain):
    tags = soup.find_all(["meta", "script", "link"])
    total, external = 0, 0
    for tag in tags:
        src = tag.get("src") or tag.get("href")
        if not src or not src.startswith("http"):
            continue
        total += 1
        if _get_domain(src) != page_domain:
            external += 1
    if total == 0:
        return 1
    pct = external / total
    if pct < 0.17:
        return 1
    elif pct <= 0.81:
        return 0
    return -1


def sfh(soup, page_domain):
    forms = soup.find_all("form")
    if not forms:
        return 1
    for form in forms:
        action = form.get("action", "")
        if action.strip() in ("", "about:blank"):
            return -1
        if action.startswith("http") and _get_domain(action) != page_domain:
            return 0
    return 1


def submitting_to_email(soup):
    forms = soup.find_all("form")
    for form in forms:
        action = form.get("action", "")
        if "mailto:" in action.lower():
            return -1
    html_str = str(soup)
    if "mail(" in html_str.lower():
        return -1
    return 1


def abnormal_url(url):
    def _check():
        domain = _get_domain(url)
        w = whois.whois(domain)
        registered_domain = (w.domain_name or "")
        if isinstance(registered_domain, list):
            registered_domain = registered_domain[0] if registered_domain else ""
        if not registered_domain:
            return 0
        return 1 if domain.lower() in registered_domain.lower() else -1

    return _safe(_check, default=0)


def redirect_count(resp):
    n = len(resp.history)
    if n <= 1:
        return 1
    elif n < 4:
        return 0
    return -1


def on_mouseover(soup):
    html_str = str(soup).lower()
    return -1 if "onmouseover" in html_str and "window.status" in html_str else 1


def right_click(soup):
    html_str = str(soup).lower()
    if "event.button==2" in html_str.replace(" ", "") or "oncontextmenu" in html_str:
        return -1
    return 1


def pop_up_window(soup):
    html_str = str(soup).lower()
    if "window.open" in html_str and ("<input" in html_str or "<form" in html_str):
        return -1
    return 1


def iframe(soup):
    frames = soup.find_all("iframe")
    if not frames:
        return 1
    for f in frames:
        if f.get("frameborder") in ("0", 0):
            return -1
    return 0


def age_of_domain(url):
    def _check():
        domain = _get_domain(url)
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if not created:
            return 0
        age_days = (datetime.utcnow() - created).days
        return 1 if age_days >= 180 else -1

    return _safe(_check, default=0)


def dns_record(url):
    def _check():
        domain = _get_domain(url)
        dns.resolver.resolve(domain, "A")
        return 1
    return _safe(_check, default=-1)


# Column order MUST match data_schema/schema_trimmed.yaml (minus Result)
FEATURE_COLUMNS = [
    "having_IP_Address", "URL_Length", "Shortining_Service", "having_At_Symbol",
    "double_slash_redirecting", "Prefix_Suffix", "having_Sub_Domain", "SSLfinal_State",
    "Domain_registeration_length", "Favicon", "port", "HTTPS_token", "Request_URL",
    "URL_of_Anchor", "Links_in_tags", "SFH", "Submitting_to_email", "Abnormal_URL",
    "Redirect", "on_mouseover", "RightClick", "popUpWidnow", "Iframe",
    "age_of_domain", "DNSRecord",
]


def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def extract_features(url: str) -> dict:
    """Returns a dict of the 25 features for a single URL, ready to build a DataFrame row."""
    url = normalize_url(url)

    page_domain = _get_domain(url)

    # URL-string-only features (fast, no network needed)
    features = {
        "having_IP_Address": having_ip_address(url),
        "URL_Length": url_length(url),
        "Shortining_Service": shortining_service(url),
        "having_At_Symbol": having_at_symbol(url),
        "double_slash_redirecting": double_slash_redirecting(url),
        "Prefix_Suffix": prefix_suffix(url),
        "having_Sub_Domain": having_sub_domain(url),
        "HTTPS_token": https_token(url),
        "port": get_port(url),
    }

    # Network-dependent features
    features["SSLfinal_State"] = ssl_final_state(url)
    features["Domain_registeration_length"] = domain_registration_length(url)
    features["Favicon"] = favicon(url)
    features["Abnormal_URL"] = abnormal_url(url)
    features["age_of_domain"] = age_of_domain(url)
    features["DNSRecord"] = dns_record(url)

    def _page_dependent():
        resp, soup = _fetch_page(url)
        return {
            "Request_URL": request_url(soup, page_domain),
            "URL_of_Anchor": url_of_anchor(soup, page_domain),
            "Links_in_tags": links_in_tags(soup, page_domain),
            "SFH": sfh(soup, page_domain),
            "Submitting_to_email": submitting_to_email(soup),
            "Redirect": redirect_count(resp),
            "on_mouseover": on_mouseover(soup),
            "RightClick": right_click(soup),
            "popUpWidnow": pop_up_window(soup),
            "Iframe": iframe(soup),
        }

    page_defaults = {
        "Request_URL": 0, "URL_of_Anchor": 0, "Links_in_tags": 0, "SFH": 0,
        "Submitting_to_email": 1, "Redirect": 0, "on_mouseover": 1,
        "RightClick": 1, "popUpWidnow": 1, "Iframe": 1,
    }
    features.update(_safe(_page_dependent, default=page_defaults))

    return {col: features[col] for col in FEATURE_COLUMNS}