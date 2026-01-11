import requests
from urllib.parse import urlparse, parse_qs, urlencode


def analyze_parameter_behavior(url, headers=None):
    """
    Analyze parameter behavior without exploitation.
    Returns behavioral signals per parameter.
    """

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return {}

    behaviors = {}

    try:
        # Baseline request
        base_resp = requests.get(url, headers=headers, timeout=10, verify=False)
        base_len = len(base_resp.text)
    except Exception:
        return {}

    for param in params:
        signals = []

        # Build modified request (empty value, not payload)
        test_params = params.copy()
        test_params[param] = ""

        test_query = urlencode(test_params, doseq=True)
        test_url = parsed._replace(query=test_query).geturl()

        try:
            test_resp = requests.get(test_url, headers=headers, timeout=10, verify=False)
            test_len = len(test_resp.text)

            # 1️⃣ Response length delta
            if abs(test_len - base_len) > 100:
                signals.append("Response length change")

            # 2️⃣ Reflection check (safe)
            if param in test_resp.text:
                signals.append("Parameter reflected")

            # 3️⃣ File-like parameter
            if param.lower() in ["file", "path", "page"]:
                signals.append("File-like behavior")

            # 4️⃣ Redirect control
            if param.lower() in ["redirect", "url", "next"]:
                if test_resp.is_redirect or test_resp.status_code in [301,302]:
                    signals.append("Redirect control")

            # 5️⃣ Error signal
            if test_resp.status_code >= 500:
                signals.append("Server error influence")

        except Exception:
            continue

        if signals:
            behaviors[param] = signals

    return behaviors
