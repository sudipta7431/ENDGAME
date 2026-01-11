import requests
from urllib.parse import urlparse, parse_qs, urlencode

def differential_analysis(url, headers=None):
    """
    Compare baseline response with controlled variations.
    Detects logic-level behavior changes.
    """

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # No parameters → nothing to diff
    if not params:
        return {}

    results = {}

    try:
        base = requests.get(url, headers=headers, timeout=10, verify=False)
        base_status = base.status_code
        base_len = len(base.text)
        base_headers = set(base.headers.keys())
    except Exception:
        return {}

    for param in params:
        signals = []

        # Variant: parameter removed
        modified_params = params.copy()
        modified_params.pop(param, None)

        new_query = urlencode(modified_params, doseq=True)
        new_url = parsed._replace(query=new_query).geturl()

        try:
            test = requests.get(new_url, headers=headers, timeout=10, verify=False)

            # 1️⃣ Status code difference
            if test.status_code != base_status:
                signals.append(
                    f"Status change {base_status} → {test.status_code}"
                )

            # 2️⃣ Response length difference
            if abs(len(test.text) - base_len) > 150:
                signals.append("Response length delta")

            # 3️⃣ Redirect behavior
            if test.is_redirect != base.is_redirect:
                signals.append("Redirect behavior change")

            # 4️⃣ Error handling difference
            if test.status_code >= 500 and base_status < 500:
                signals.append("Server error triggered")

            # 5️⃣ Header differences
            header_diff = set(test.headers.keys()) ^ base_headers
            if header_diff:
                signals.append("Response header difference")

        except Exception:
            continue

        if signals:
            results[param] = signals

    return results
