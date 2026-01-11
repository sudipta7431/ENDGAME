import requests

HEADERS = {
    "User-Agent": "endgame-v5",
    "Content-Type": "application/json"
}

COMMON_GRAPHQL_PATHS = [
     # =========================
    # STANDARD / COMMON
    # =========================
    "/graphql",
    "/gql",
    "/api/graphql",
    "/api/gql",

    # =========================
    # VERSIONED
    # =========================
    "/v1/graphql",
    "/v2/graphql",
    "/v3/graphql",
    "/api/v1/graphql",
    "/api/v2/graphql",

    # =========================
    # BACKEND FRAMEWORK DEFAULTS
    # =========================
    "/graphql/api",
    "/graphql/endpoint",
    "/graphql/playground",
    "/graphql/explorer",
    "/graphql/schema",

    # =========================
    # FRONTEND / SPA GATEWAYS
    # =========================
    "/app/graphql",
    "/frontend/graphql",
    "/client/graphql",
    "/web/graphql",

    # =========================
    # ADMIN / INTERNAL (HIGH VALUE)
    # =========================
    "/internal/graphql",
    "/admin/graphql",
    "/private/graphql",
    "/secure/graphql",
    "/staff/graphql",

    # =========================
    # CLOUD / ENTERPRISE
    # =========================
    "/services/graphql",
    "/gateway/graphql",
    "/core/graphql",
    "/platform/graphql",

    # =========================
    # LEGACY / MISCONFIG
    # =========================
    "/graphiql",
    "/graphiql/graphql",
    "/graphql-console",
    "/graphql-ui",
    "/explorer/graphql",

    # =========================
    # MOBILE / BFF (Backend-for-Frontend)
    # =========================
    "/mobile/graphql",
    "/bff/graphql",
    "/ios/graphql",
    "/android/graphql"
]

SAFE_QUERIES = {
    "typename": {"query": "{ __typename }"},
    "introspection_probe": {"query": "{ __schema { queryType { name } } }"},
    "deep_probe": {
        "query": """
        query DeepTest {
          __typename
        }
        """
    }
}

def analyze_graphql_depth(base_url, headers=None, timeout=10):
    findings = []
    # Build request headers safely
    req_headers = {
        "Content-Type": "application/json"
    }
    if headers:
        req_headers.update(headers)

    for path in COMMON_GRAPHQL_PATHS:
        url = base_url.rstrip("/") + path

        endpoint_result = {
            "endpoint": url,
            "graphql_detected": False,
            "introspection_enabled": False,
            "depth_limited": False,
            "verbose_errors": False,
            "notes": []
        }

        try:
            # Step 1: Detect GraphQL
            r = requests.post(
                url,
                json=SAFE_QUERIES["typename"],
                headers=req_headers,
                timeout=timeout,
                verify=False
            )
        except Exception:
            continue

        body = r.text.lower()

        if "graphql" not in body and "__typename" not in body:
            continue

        endpoint_result["graphql_detected"] = True

        # Step 2: Introspection probe (SAFE)
        try:
            intro = requests.post(
                url,
                json=SAFE_QUERIES["introspection_probe"],
                headers=req_headers,
                timeout=timeout,
                verify=False
            )
            if "__schema" in intro.text:
                endpoint_result["introspection_enabled"] = True
        except Exception:
            pass

        # Step 3: Error verbosity & depth hints
        if any(k in body for k in ["stack trace", "exception", "resolver", "at line"]):
            endpoint_result["verbose_errors"] = True
            endpoint_result["notes"].append("Verbose GraphQL errors")

        if any(k in body for k in ["depth", "complexity", "max depth"]):
            endpoint_result["depth_limited"] = True
            endpoint_result["notes"].append("Depth / complexity protection detected")

        findings.append(endpoint_result)

    return findings
