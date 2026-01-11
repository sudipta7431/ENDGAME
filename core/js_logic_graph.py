import re
import requests
from urllib.parse import urljoin


FETCH_PATTERN = r"(fetch|axios\.get|axios\.post)\(['\"](.*?)['\"]"

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


def build_js_logic_graph(base_url, condition_patterns, headers=None):
    """
    Build JS logic graph:
    CONDITION → API → JS SOURCE
    """
    graph = []

    try:
        html = requests.get(
            base_url,
            headers=headers,
            timeout=10,
            verify=False
        ).text
    except Exception:
        return graph

    inline_scripts, external_urls = extract_js_sources(html, base_url)

    # -------- INLINE JS --------
    for script in inline_scripts:
        for condition, pattern in condition_patterns.items():
            if re.search(pattern, script, re.IGNORECASE):
                apis = re.findall(FETCH_PATTERN, script)
                for _, api in apis:
                    graph.append({
                        "js_file": "inline-script",
                        "condition": condition,
                        "api_call": api,
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

        for condition, pattern in condition_patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                apis = re.findall(FETCH_PATTERN, content)
                for _, api in apis:
                    graph.append({
                        "js_file": js_url,
                        "condition": condition,
                        "api_call": api,
                        "confidence": "HIGH"
                    })

    return graph
