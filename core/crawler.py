import requests
import warnings
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3.exceptions import InsecureRequestWarning

warnings.simplefilter("ignore", InsecureRequestWarning)


def same_domain(url, base):
    return urlparse(url).netloc == urlparse(base).netloc

def fetch(url, headers=None):
    try:
        r = requests.get(url, headers=headers, timeout=10, verify=False)
        if r.status_code == 200:
            return r.text
    except Exception:
        return None
    return None

def extract_links(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    links = set()

    for tag in soup.find_all(["a", "form", "script"]):
        attr = tag.get("href") or tag.get("action") or tag.get("src")
        if not attr:
            continue
        links.add(urljoin(base_url, attr))

    return links

def crawl(start_url, max_depth=2, max_pages=100, threads=10, headers=None):
    visited = set()
    discovered = set()
    queue = [(start_url, 0)]

    while queue and len(visited) < max_pages:
        batch = []
        next_queue = []

        for url, depth in queue:
            if url in visited or depth > max_depth:
                continue
            visited.add(url)
            batch.append((url, depth))

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(fetch, url, headers): (url, depth)
                for url, depth in batch
            }

            for future in as_completed(futures):
                html = future.result()
                url, depth = futures[future]

                if not html:
                    continue

                for link in extract_links(html, url):
                    if same_domain(link, start_url):
                        discovered.add(link)
                        next_queue.append((link, depth + 1))

        queue = next_queue

    return discovered
