from urllib.parse import urlparse, parse_qs, urlencode

TRACKING_PARAMS = {"utm_source", "utm_medium", "utm_campaign", "ref"}

def normalize(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    clean_params = {
        k: v for k, v in params.items()
        if k.lower() not in TRACKING_PARAMS
    }

    query = urlencode(sorted(clean_params.items()), doseq=True)

    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}" + (
        f"?{query}" if query else ""
    )
