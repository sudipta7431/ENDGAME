import re
import requests
from urllib.parse import urljoin


def extract_js_sources(html, base_url):
    """
    Extract inline JS and external JS URLs
    """
    inline_scripts = re.findall(
        r"<script[^>]*>(.*?)</script>",
        html,
        re.DOTALL | re.IGNORECASE
    )

    external_scripts = re.findall(
        r'<script[^>]+src=["\'](.*?)["\']',
        html,
        re.IGNORECASE
    )

    external_urls = [urljoin(base_url, src) for src in external_scripts]
    return inline_scripts, external_urls


def analyze_js_logic(base_url, patterns, headers=None):
    """
    Detect security-meaningful JS logic patterns
    """
    findings = []

    try:
        html = requests.get(
            base_url,
            headers=headers,
            timeout=10,
            verify=False
        ).text
    except Exception:
        return findings

    inline_scripts, external_urls = extract_js_sources(html, base_url)

    # -------- INLINE JS --------
    for script in inline_scripts:
        for name, pattern in patterns.items():
            if re.search(pattern, script, re.IGNORECASE):
                findings.append({
                    "type": "inline",
                    "pattern": name,
                    "confidence": "HIGH"
                })

    # -------- EXTERNAL JS --------
    for js_url in external_urls:
        try:
            content = requests.get(
                js_url,
                headers=headers,
                timeout=10,
                verify=False
            ).text
        except Exception:
            continue

        for name, pattern in patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                findings.append({
                    "type": "external",
                    "pattern": name,
                    "source": js_url,
                    "confidence": "HIGH"
                })

    return findings
