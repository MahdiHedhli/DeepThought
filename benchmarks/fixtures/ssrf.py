"""SSRF (CWE-918) fixture: a VULNERABLE function and two PATCHED functions in one file,
so a single scan of DT-SSRF-TAINT proves it discriminates. Modeled on the seed, dify
CVE-2025-0184 (a raw requests.get on an attacker-controlled URL, later routed through an
SSRF-safe proxy). No code here executes in the benchmark; the detector only parses it.
"""

import ipaddress
import socket
from urllib.parse import urlparse

import requests

from myapp.helper import ssrf_proxy


# VULNERABLE: fetches an attacker-controlled URL with no host/scheme validation — an
# attacker can point `url` at an internal service or the cloud metadata endpoint.
def fetch_vulnerable(url):
    return requests.get(url, stream=True)  # SINK: unguarded outbound request


# PATCHED (sink substitution): the raw sink is routed through an SSRF-hardened proxy,
# exactly like the dify fix (requests.get -> ssrf_proxy.get).
def fetch_patched_proxy(url):
    return ssrf_proxy.get(url, stream=True)


# PATCHED (guard added): the URL's host is resolved and every IP checked to be global
# before the request — the lmdeploy / gradio shape.
def fetch_patched_guard(url):
    host = urlparse(url).hostname
    if not host:
        raise ValueError("no host")
    for info in socket.getaddrinfo(host, None):
        if not ipaddress.ip_address(info[4][0]).is_global:
            raise ValueError("URL is blocked for security reasons")
    return requests.get(url, stream=True)
