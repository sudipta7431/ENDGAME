import requests

HEADERS = {
    "User-Agent": "endgame-v5",
    "Content-Type": "application/json"
}

# Common GraphQL paths
GRAPHQL_PATHS = [

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

def analyze_graphql(base_url, headers=None):
    """
    Perform safe GraphQL intelligence analysis.
    No exploitation, no schema dumping.
    """

    findings = []
    # Ensure required headers
    req_headers = {
        "Content-Type": "application/json"
    }
    if headers:
        req_headers.update(headers)
    for path in GRAPHQL_PATHS:
        url = base_url.rstrip("/") + path

        try:
            # Minimal harmless query
            payload = {"query": "{__typename}"}
            r = requests.post(url, json=payload, headers=req_headers, timeout=10, verify=False)
        except Exception:
            continue

        if r.status_code not in [200, 400, 401, 403]:
            continue

        body = r.text.lower()

        # GraphQL confirmation
        if "__typename" not in body and "graphql" not in body:
            continue

        intel = {
            "endpoint": url,
            "introspection": "__schema" in body,
            "verbose_errors": any(x in body for x in ["stack trace", "exception", "traceback"]),
            "auth_required": r.status_code in (401, 403)
        }
        findings.append(intel)
    return findings
