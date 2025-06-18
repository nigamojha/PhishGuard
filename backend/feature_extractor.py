# feature_extractor.py (Corrected function calls)

from urllib.parse import urlparse, urljoin
import tldextract
import re
from datetime import datetime
import whois
import requests
from bs4 import BeautifulSoup

# --- Phase 3: HTML Content Analysis ---
def get_html_content(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=5, verify=False)
        if response.status_code == 200:
            return BeautifulSoup(response.content, 'html.parser')
        else:
            return None
    except requests.RequestException:
        return None

def has_insecure_forms(soup, base_url):
    if not soup: return 0
    forms = soup.find_all('form')
    if not forms: return -1
    for form in forms:
        action = form.get('action', '').lower()
        full_action_url = urljoin(base_url, action)
        if urlparse(full_action_url).scheme == 'http':
            return 1
    return -1

# --- Phase 2: Real-time Threat Intelligence ---
def get_domain_age_in_days(url):
    try:
        domain_name = tldextract.extract(url).registered_domain
        if not domain_name: return -1
        domain_info = whois.whois(domain_name)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list): creation_date = creation_date[0]
        return (datetime.now() - creation_date).days if creation_date else -1
    except Exception:
        return -1

# --- Phase 1: URL-based Features ---
def get_num_dots(url): return url.count('.')
def get_subdomain_level(url):
    subdomain = tldextract.extract(url).subdomain
    return 0 if not subdomain else len(subdomain.split('.'))
def get_path_level(url):
    path = urlparse(url).path.strip('/')
    return 0 if not path else len(path.split('/'))
def get_url_length(url): return len(url)
def get_num_dashes(url): return url.count('-')
def get_num_dashes_in_hostname(url): return urlparse(url).netloc.count('-')
def has_at_symbol(url): return 1 if '@' in url else -1
def has_tilde_symbol(url): return 1 if '~' in url else -1
def get_num_underscores(url): return url.count('_')
def get_num_percents(url): return url.count('%')
def get_num_query_components(url):
    query = urlparse(url).query
    if not query: return 0
    return len([item for sublist in [q.split('=') for q in query.split('&')] for item in sublist])
def get_num_ampersands(url): return url.count('&')
def get_num_hash(url): return url.count('#')
def get_num_numeric_chars(url): return sum(c.isdigit() for c in url)
def is_http_scheme(url): return 1 if urlparse(url).scheme == 'http' else -1
def has_ip_address(url):
    ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    return 1 if ip_pattern.search(urlparse(url).netloc) else -1
def get_hostname_length(url): return len(urlparse(url).netloc)
def get_path_length(url): return len(urlparse(url).path)
def get_query_length(url): return len(urlparse(url).query)
def has_domain_in_subdomains(url):
    ext = tldextract.extract(url)
    return 1 if ext.domain and ext.domain in ext.subdomain else -1
def has_domain_in_paths(url):
    ext = tldextract.extract(url)
    return 1 if ext.domain and ext.domain in urlparse(url).path else -1
def has_https_in_hostname(url):
    return 1 if 'https' in urlparse(url).netloc else -1
def get_num_sensitive_words(url):
    sensitive_words = ['secure', 'login', 'signin', 'bank', 'account', 'password', 'verify', 'update', 'webscr']
    return sum(len(re.findall(r'\b' + word + r'\b', url.lower())) for word in sensitive_words)
def has_random_string(url):
    no_vowels_pattern = re.compile(r'\b[b-df-hj-np-tv-z]{7,}\b', re.I)
    return 1 if no_vowels_pattern.search(url) else -1
def has_double_slash_in_path(url): return 1 if '//' in urlparse(url).path else -1

# --- Main Orchestrator Function ---
def extract_features_from_url(url):
    """
    This is the main function that orchestrates the entire feature extraction process.
    """
    
    # --- Part 1 & 2: URL Analysis and Real-time Intelligence ---
    # NOTE THE (url) AFTER EVERY FUNCTION CALL. This is the fix.
    features = {
        'NumDots': get_num_dots(url), 'SubdomainLevel': get_subdomain_level(url), 'PathLevel': get_path_level(url),
        'UrlLength': get_url_length(url), 'NumDash': get_num_dashes(url), 'NumDashInHostname': get_num_dashes_in_hostname(url),
        'AtSymbol': has_at_symbol(url), 'TildeSymbol': has_tilde_symbol(url), 'NumUnderscore': get_num_underscores(url),
        'NumPercent': get_num_percents(url), 'NumQueryComponents': get_num_query_components(url),
        'NumAmpersand': get_num_ampersands(url), 'NumHash': get_num_hash(url), 'NumNumericChars': get_num_numeric_chars(url),
        'NoHttps': is_http_scheme(url), 'RandomString': has_random_string(url), 'IpAddress': has_ip_address(url),
        'DomainInSubdomains': has_domain_in_subdomains(url), 'DomainInPaths': has_domain_in_paths(url),
        'HttpsInHostname': has_https_in_hostname(url), 'HostnameLength': get_hostname_length(url),
        'PathLength': get_path_length(url), 'QueryLength': get_query_length(url),
        'DoubleSlashInPath': has_double_slash_in_path(url), 'NumSensitiveWords': get_num_sensitive_words(url),
        'DomainAge': get_domain_age_in_days(url),
    }

    # --- Part 3: HTML Content Analysis ---
    soup = get_html_content(url)
    features['InsecureForms'] = has_insecure_forms(soup, url)
    
    # --- Final Step: Ensure all original 48 features are present for the model ---
    all_feature_names = [ 'NumDots', 'SubdomainLevel', 'PathLevel', 'UrlLength', 'NumDash', 'NumDashInHostname', 'AtSymbol', 'TildeSymbol', 'NumUnderscore', 'NumPercent', 'NumQueryComponents', 'NumAmpersand', 'NumHash', 'NumNumericChars', 'NoHttps', 'RandomString', 'IpAddress', 'DomainInSubdomains', 'DomainInPaths', 'HttpsInHostname', 'HostnameLength', 'PathLength', 'QueryLength', 'DoubleSlashInPath', 'NumSensitiveWords', 'EmbeddedBrandName', 'PctExtHyperlinks', 'PctExtResourceUrls', 'ExtFavicon', 'InsecureForms', 'RelativeFormAction', 'ExtFormAction', 'AbnormalFormAction', 'PctNullSelfRedirectHyperlinks', 'FrequentDomainNameMismatch', 'FakeLinkInStatusBar', 'RightClickDisabled', 'PopUpWindow', 'SubmitInfoToEmail', 'IframeOrFrame', 'MissingTitle', 'ImagesOnlyInForm', 'SubdomainLevelRT', 'UrlLengthRT', 'PctExtResourceUrlsRT', 'AbnormalExtFormActionR', 'ExtMetaScriptLinkRT', 'PctExtNullSelfRedirectHyperlinksRT' ]
    all_feature_names.append('DomainAge')

    final_feature_vector = {}
    for feature_name in all_feature_names:
        final_feature_vector[feature_name] = features.get(feature_name, 0)
        
    return final_feature_vector