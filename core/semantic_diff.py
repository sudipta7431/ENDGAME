import requests
import json
from urllib.parse import urlparse, parse_qs, urlencode


def extract_json_keys(data, prefix=""):
    """
    Recursively extract JSON key paths
    """
    keys = set()

    if isinstance(data, dict):
        for k, v in data.items():
            path = f"{prefix}.{k}" if prefix else k
            keys.add(path)
            keys |= extract_json_keys(v, path)

    elif isinstance(data, list):
        for item in data:
            keys |= extract_json_keys(item, prefix)

    return keys

def semantic_response_diff(url, headers=None):
    """
    Detect semantic (structural) response differences.
    """

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return {}

    try:
        baseline = requests.get(url, headers=headers, timeout=10, verify=False)
    except Exception:
        return {}

    # Only analyze JSON responses
    try:
        base_json = baseline.json()
    except Exception:
        return {}

    base_keys = extract_json_keys(base_json)
    results = {}

    for param in params:
        # Variant: remove parameter
        modified = params.copy()
        modified.pop(param, None)

        new_query = urlencode(modified, doseq=True)
        new_url = parsed._replace(query=new_query).geturl()

        try:
            test = requests.get(new_url, headers=headers, timeout=10, verify=False)
            test_json = test.json()
        except Exception:
            continue

        test_keys = extract_json_keys(test_json)

        added = test_keys - base_keys
        removed = base_keys - test_keys

        signals = []

        if added:
            signals.append({
                "type": "New JSON fields",
                "fields": sorted(list(added))
            })

        if removed:
            signals.append({
                "type": "Missing JSON fields",
                "fields": sorted(list(removed))
            })

        if signals:
            results[param] = signals

    return results
