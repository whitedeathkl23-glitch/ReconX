#!/usr/bin/env python3
"""
ReconX - A compact, ethical recon tool for website penetration testing.

Features:
- HTTP headers & status
- robots.txt and sitemap discovery
- Subdomain enumeration (wordlist-based)
- Basic port scanner (top common ports)
- Directory brute-forcing (wordlist-based)
- Link extraction and basic asset summary
- WHOIS lookup
- SSL certificate info (expiry, issuer)

Usage examples:
  python3 reconx.py -u https://example.com --subdomains --ports --dirs

Dependencies (pip):
  pip install requests dnspython python-whois beautifulsoup4 tqdm

NOTE: Use this tool only on targets you have explicit permission to test.
"""

import argparse
import concurrent.futures
import socket
import ssl
import sys
import threading
import time
from datetime import datetime
from urllib.parse import urljoin, urlparse

import dns.resolver
import requests
import whois
from bs4 import BeautifulSoup
from tqdm import tqdm

# -------------------- Configuration / small wordlists --------------------
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 8080, 8443]
SMALL_SUBDOMAIN_WORDLIST = [
    'www', 'mail', 'ftp', 'cpanel', 'webmail', 'api', 'dev', 'staging', 'test', 'admin'
]
SMALL_DIR_WORDLIST = [
    'admin', 'login', 'uploads', 'images', 'css', 'js', 'backup', 'config', 'robots.txt'
]
TIMEOUT = 5

# Thread-safe print
print_lock = threading.Lock()

def safe_print(*a, **k):
    with print_lock:
        print(*a, **k)

# -------------------- Networking helpers --------------------

def fetch_url(target, path=''):
    try:
        url = urljoin(target, path)
        resp = requests.get(url, timeout=TIMEOUT, allow_redirects=True)
        return resp
    except Exception as e:
        return None

# -------------------- Recon functions --------------------

def fetch_headers(target):
    safe_print('\n[+] Fetching headers and basic response info')
    resp = fetch_url(target)
    if not resp:
        safe_print('  - Failed to reach target')
        return
    safe_print(f'  - URL: {resp.url}')
    safe_print(f'  - Status: {resp.status_code}')
    safe_print('  - Server headers:')
    for k, v in resp.headers.items():
        safe_print(f'     {k}: {v}')


def fetch_robots_sitemap(target):
    safe_print('\n[+] Checking robots.txt and sitemap.xml')
    parsed = urlparse(target)
    base = f'{parsed.scheme}://{parsed.netloc}'
    for p in ['/robots.txt', '/sitemap.xml']:
        resp = fetch_url(base, p)
        if resp and resp.status_code == 200:
            safe_print(f'  - Found {p} (length {len(resp.text)} bytes)')
        else:
            safe_print(f'  - {p} not found')


def extract_links(target):
    safe_print('\n[+] Extracting links and assets')
    resp = fetch_url(target)
    if not resp:
        safe_print('  - Failed to fetch page for link extraction')
        return
    soup = BeautifulSoup(resp.text, 'html.parser')
    links = set()
    assets = set()
    for tag in soup.find_all(['a', 'link', 'script', 'img']):
        if tag.name == 'a' and tag.get('href'):
            links.add(urljoin(resp.url, tag.get('href')))
        if tag.name in ('img', 'script') and tag.get('src'):
            assets.add(urljoin(resp.url, tag.get('src')))
        if tag.name == 'link' and tag.get('href'):
            assets.add(urljoin(resp.url, tag.get('href')))
    safe_print(f'  - Found {len(links)} links and {len(assets)} assets')
    if links:
        sample_links = list(links)[:10]
        for l in sample_links:
            safe_print('    *', l)


def whois_lookup(target):
    safe_print('\n[+] WHOIS lookup')
    try:
        parsed = urlparse(target)
        domain = parsed.netloc or parsed.path
        w = whois.whois(domain)
        safe_print('  - Domain:', domain)
        if w.domain_name:
            safe_print('  - Registrar:', w.registrar)
            safe_print('  - Creation date:', w.creation_date)
            safe_print('  - Expiration date:', w.expiration_date)
    except Exception as e:
        safe_print('  - WHOIS lookup failed:', e)


def ssl_info(target):
    safe_print('\n[+] SSL certificate info')
    try:
        parsed = urlparse(target)
        host = parsed.netloc.split(':')[0]
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(TIMEOUT)
            s.connect((host, 443))
            cert = s.getpeercert()
            issuer = dict(x[0] for x in cert.get('issuer'))
            subject = dict(x[0] for x in cert.get('subject'))
            notAfter = cert.get('notAfter')
            safe_print('  - Subject:', subject.get('commonName'))
            safe_print('  - Issuer:', issuer.get('commonName'))
            safe_print('  - Expires:', notAfter)
    except Exception as e:
        safe_print('  - SSL check failed:', e)

# -------------------- Subdomain enumeration --------------------

def try_resolve(subdomain, domain):
    host = f"{subdomain}.{domain}"
    try:
        answers = dns.resolver.resolve(host, 'A')
        ips = [r.to_text() for r in answers]
        return host, ips
    except Exception:
        return None


def subdomain_enum(domain, wordlist=None, threads=10):
    safe_print('\n[+] Subdomain enumeration')
    wordlist = wordlist or SMALL_SUBDOMAIN_WORDLIST
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(try_resolve, w, domain): w for w in wordlist}
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                host, ips = res
                safe_print(f'  - {host} -> {ips}')
                found.append((host, ips))
    if not found:
        safe_print('  - No subdomains found with small wordlist')

# -------------------- Port scanner --------------------

def scan_port(host, port, timeout=2):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False


def port_scan(host, ports=None, threads=50):
    safe_print('\n[+] Port scanning')
    ports = ports or COMMON_PORTS
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(scan_port, host, p): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            p = futures[fut]
            if fut.result():
                safe_print(f'  - Port {p} is OPEN')
                open_ports.append(p)
    if not open_ports:
        safe_print('  - No common ports open (in scanned set)')

# -------------------- Directory brute-force --------------------

def dir_worker(base, path):
    try:
        url = urljoin(base, path)
        r = requests.get(url, timeout=TIMEOUT, allow_redirects=False)
        return path, r.status_code
    except Exception:
        return path, None


def dir_bruteforce(target, wordlist=None, threads=20):
    safe_print('\n[+] Directory brute-force')
    wordlist = wordlist or SMALL_DIR_WORDLIST
    found = []
    base = target if target.endswith('/') else target + '/'
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(dir_worker, base, p): p for p in wordlist}
        for fut in concurrent.futures.as_completed(futures):
            path, status = fut.result()
            if status and status < 400:
                safe_print(f'  - {path} -> {status}')
                found.append((path, status))
    if not found:
        safe_print('  - No interesting directories found in small list')

# -------------------- CLI and main --------------------

def parse_args():
    p = argparse.ArgumentParser(description='ReconX - compact recon tool')
    p.add_argument('-u', '--url', required=True, help='Target URL (e.g. https://example.com)')
    p.add_argument('--subdomains', action='store_true', help='Run subdomain enumeration')
    p.add_argument('--ports', action='store_true', help='Run basic port scan')
    p.add_argument('--dirs', action='store_true', help='Run directory brute-force')
    p.add_argument('--whois', action='store_true', help='Run whois lookup')
    p.add_argument('--ssl', action='store_true', help='Fetch SSL certificate info')
    p.add_argument('--all', action='store_true', help='Run all checks')
    return p.parse_args()


def main():
    args = parse_args()
    target = args.url
    parsed = urlparse(target)
    if not parsed.scheme:
        safe_print('Please include scheme (http:// or https://) in URL')
        sys.exit(1)

    safe_print('\n=== ReconX scan started at', datetime.now().isoformat(), '===')
    # Always fetch headers & links
    fetch_headers(target)
    extract_links(target)
    fetch_robots_sitemap(target)

    if args.all or args.whois:
        whois_lookup(target)
    if args.all or args.ssl:
        ssl_info(target)
    if args.all or args.subdomains:
        domain = parsed.netloc.split(':')[0]
        subdomain_enum(domain)
    if args.all or args.ports:
        host = parsed.netloc.split(':')[0]
        port_scan(host)
    if args.all or args.dirs:
        dir_bruteforce(target)

    safe_print('\n=== ReconX finished at', datetime.now().isoformat(), '===')

if __name__ == '__main__':
    main()
