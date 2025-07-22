# in backend/test_features.py
from feature_extractor import (
    get_num_dots,
    has_at_symbol,
    get_num_sensitive_words,
    has_domain_in_subdomains,
    is_http_scheme
)

# Test case for counting dots
def test_get_num_dots():
    assert get_num_dots("www.google.com") == 2
    assert get_num_dots("example.co.uk") == 2
    assert get_num_dots("a.b.c.d.e") == 4

# Test case for the '@' symbol feature
def test_has_at_symbol():
    assert has_at_symbol("user@example.com/login") == 1
    assert has_at_symbol("www.google.com") == -1

# Test case for counting sensitive words
def test_get_num_sensitive_words():
    assert get_num_sensitive_words("http://example.com/secure/login") == 2
    assert get_num_sensitive_words("http://example.com/account-update") == 2
    assert get_num_sensitive_words("http://images.com/gallery") == 0

# Test case for the deceptive subdomain trick
def test_has_domain_in_subdomains():
    assert has_domain_in_subdomains("http://google.com.malicious.com") == 1
    assert has_domain_in_subdomains("http://www.google.com") == -1
    assert has_domain_in_subdomains("http://mail.google.com") == 1

# Test case for checking the URL scheme
def test_is_http_scheme():
    assert is_http_scheme("http://example.com") == 1
    assert is_http_scheme("https://example.com") == -1