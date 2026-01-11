from urllib.parse import urlparse, parse_qs
from core.severity import severity

# -------------------------
# Advanced Parameter Rules
# -------------------------

PARAM_RULES = {

    # =========================
    # FILE / PATH HANDLING
    # =========================
    "file": ["LFI", "Path Traversal"],
    "path": ["LFI", "Path Traversal"],
    "page": ["LFI"],
    "template": ["LFI", "SSTI"],
    "include": ["LFI"],
    "dir": ["Path Traversal"],
    "folder": ["Path Traversal"],
    "doc": ["LFI"],
    "download": ["LFI"],

    # =========================
    # DATABASE / OBJECT ACCESS
    # =========================
    "id": ["SQLi", "IDOR"],
    "uid": ["SQLi", "IDOR"],
    "userid": ["SQLi", "IDOR"],
    "user": ["SQLi", "IDOR"],
    "account": ["IDOR"],
    "account_id": ["IDOR"],
    "order": ["IDOR"],
    "order_id": ["IDOR"],
    "record": ["IDOR"],
    "invoice": ["IDOR"],
    "profile": ["IDOR"],

    # =========================
    # SEARCH / FILTER / QUERY
    # =========================
    "q": ["XSS", "SQLi"],
    "query": ["XSS", "SQLi"],
    "search": ["XSS", "SQLi"],
    "filter": ["SQLi", "NoSQL Injection"],
    "where": ["SQLi"],
    "sort": ["SQLi"],
    "keyword": ["XSS"],
    "term": ["XSS"],

    # =========================
    # REDIRECT / URL / SSRF
    # =========================
    "redirect": ["Open Redirect"],
    "url": ["Open Redirect", "SSRF"],
    "next": ["Open Redirect"],
    "return": ["Open Redirect"],
    "dest": ["Open Redirect"],
    "callback": ["Open Redirect"],
    "continue": ["Open Redirect"],
    "target": ["SSRF"],
    "host": ["SSRF"],
    "endpoint": ["SSRF"],

    # =========================
    # COMMAND / CODE EXECUTION
    # =========================
    "cmd": ["RCE"],
    "exec": ["RCE"],
    "command": ["RCE"],
    "run": ["RCE"],
    "shell": ["RCE"],
    "script": ["RCE"],
    "process": ["RCE"],

    # =========================
    # TEMPLATE / RENDERING
    # =========================
    "view": ["SSTI"],
    "render": ["SSTI"],
    "layout": ["SSTI"],

    # =========================
    # SERIALIZATION / API
    # =========================
    "json": ["Insecure Deserialization"],
    "object": ["Insecure Deserialization"],
    "data": ["Insecure Deserialization", "XXE"],
    "payload": ["Insecure Deserialization"],
    "state": ["Insecure Deserialization"],
    "input": ["Insecure Deserialization"],

    # =========================
    # XML / SOAP
    # =========================
    "xml": ["XXE"],
    "doctype": ["XXE"],
    "entity": ["XXE"],

    # =========================
    # AUTH / ACCESS CONTROL
    # =========================
    "role": ["Privilege Escalation"],
    "admin": ["Privilege Escalation"],
    "access": ["Broken Access Control"],
    "permission": ["Broken Access Control"],
    "scope": ["Broken Access Control"],
    "level": ["Broken Access Control"],
    "group": ["Broken Access Control"],

    # =========================
    # TOKENS / SECRETS
    # =========================
    "token": ["Auth Bypass"],
    "auth": ["Auth Bypass"],
    "apikey": ["Auth Bypass"],
    "api_key": ["Auth Bypass"],
    "secret": ["Sensitive Data Exposure"],
    "key": ["Sensitive Data Exposure"],

    # =========================
    # FILE UPLOAD / PARSING
    # =========================
    "filename": ["File Upload"],
    "upload": ["File Upload"],
    "filetype": ["File Upload"],
    "content": ["File Upload"],

    # =========================
    # BUSINESS LOGIC
    # =========================
    "price": ["Business Logic Flaw"],
    "amount": ["Business Logic Flaw"],
    "discount": ["Business Logic Flaw"],
    "quantity": ["Business Logic Flaw"],
    "balance": ["Business Logic Flaw"],
    "limit": ["Business Logic Flaw"],
    "count": ["Business Logic Flaw"]
}


# -------------------------
# Contextual Path Signals
# -------------------------

SENSITIVE_PATH_HINTS = [

    # =========================
    # ADMIN / MANAGEMENT
    # =========================
    "/admin","/administrator","/admins","/admin-panel","/adminpanel",
    "/manage","/management","/manager","/console","/dashboard",
    "/control","/controlpanel","/cp","/cms","/backend","/backoffice",
    "/operator","/ops","/operations","/root","/superuser",

    # =========================
    # INTERNAL / PRIVATE
    # =========================
    "/internal","/private","/restricted","/secure","/protected",
    "/intranet","/staff","/employee","/employees","/members",
    "/partners","/partner","/corp","/corporate",

    # =========================
    # API ROOTS
    # =========================
    "/api","/apis","/rest","/graphql","/gql",
    "/service","/services","/gateway","/bff","/backend-api",

    # =========================
    # VERSIONING
    # =========================
    "/v1","/v2","/v3","/v4","/v5",
    "/api/v1","/api/v2","/api/v3","/api/v4",
    "/rest/v1","/rest/v2","/rest/v3",

    # =========================
    # AUTH / ACCESS
    # =========================
    "/auth","/authentication","/authorize","/oauth","/oauth2",
    "/login","/logout","/signin","/signup","/register",
    "/sso","/saml","/oidc","/token","/tokens",
    "/session","/sessions","/password","/reset","/forgot",

    # =========================
    # USER / ACCOUNT
    # =========================
    "/user","/users","/account","/accounts","/profile","/profiles",
    "/member","/members","/customer","/customers","/client","/clients",
    "/identity","/identities",

    # =========================
    # DEBUG / TEST / DEV
    # =========================
    "/debug","/debugger","/trace","/logs","/log",
    "/test","/tests","/testing","/qa","/uat",
    "/dev","/development","/staging","/sandbox",
    "/mock","/mocks","/fake","/dummy","/example",

    # =========================
    # CONFIG / META
    # =========================
    "/config","/configs","/configuration","/settings","/options",
    "/preferences","/env","/environment","/meta","/metadata",
    "/status","/health","/healthcheck","/metrics","/monitor",

    # =========================
    # DATA / FILE OPS
    # =========================
    "/file","/files","/download","/downloads","/upload","/uploads",
    "/export","/exports","/import","/imports","/backup","/backups",
    "/restore","/archives","/archive","/storage",

    # =========================
    # DATABASE / OBJECTS
    # =========================
    "/db","/database","/databases","/sql","/nosql",
    "/query","/queries","/search","/filter","/filters",
    "/index","/indexes","/records","/objects",

    # =========================
    # PAYMENT / FINANCE
    # =========================
    "/payment","/payments","/billing","/invoice","/invoices",
    "/order","/orders","/checkout","/cart","/wallet",
    "/transaction","/transactions","/refund","/refunds",

    # =========================
    # BUSINESS LOGIC
    # =========================
    "/pricing","/price","/discount","/coupon","/promo",
    "/offer","/offers","/subscription","/subscriptions",
    "/plan","/plans","/usage","/quota","/limits",

    # =========================
    # CLOUD / INFRA
    # =========================
    "/cloud","/aws","/azure","/gcp","/kubernetes","/k8s",
    "/cluster","/node","/nodes","/pod","/pods",
    "/container","/containers","/vm","/instance","/instances",

    # =========================
    # CI/CD / DEVOPS
    # =========================
    "/ci","/cd","/pipeline","/pipelines","/build","/builds",
    "/deploy","/deployment","/releases","/artifacts",
    "/jenkins","/gitlab","/github","/bitbucket",

    # =========================
    # MOBILE / BFF
    # =========================
    "/mobile","/android","/ios","/app","/apps",
    "/device","/devices","/push","/notification","/notifications",
    "/bff","/frontend","/client",

    # =========================
    # LEGACY / RISKY
    # =========================
    "/old","/legacy","/deprecated","/beta","/alpha",
    "/v0","/testapi","/temp","/tmp","/backup_old",

    # =========================
    # MISC HIGH-VALUE
    # =========================
    "/report","/reports","/analytics","/stats","/statistics",
    "/audit","/audits","/compliance","/risk","/security",
    "/policy","/policies","/terms","/legal"
]

STATIC_EXTENSIONS = (
    ".css",".js",".png",".jpg",".jpeg",".gif",".svg",
    ".woff",".woff2",".ttf",".eot",".ico",".map",".pdf",
    ".exe",".py",".txt",".zip",".sh",".md",".txt",".html",
    ".aspx"
)

# -------------------------
# Classifier Engine
# -------------------------

def classify(endpoint):
    """
    Advanced recon-only vulnerability classification.
    Uses parameter names + endpoint context.
    """

    findings = []

    # Skip static assets
    if endpoint.lower().endswith(STATIC_EXTENSIONS):
        return findings

    parsed = urlparse(endpoint)

    # No parameters → low signal
    if not parsed.query:
        return findings

    params = parse_qs(parsed.query)
    path = parsed.path.lower()

    is_sensitive_path = any(hint in path for hint in SENSITIVE_PATH_HINTS)

    for param in params:
        key = param.lower()

        if key not in PARAM_RULES:
            continue

        vulns = PARAM_RULES[key]

        for vuln in vulns:
            score, level = severity(vuln)

            # 🔥 Risk amplification
            if is_sensitive_path:
                score += 1

            findings.append({
                "parameter": key,
                "vulnerability": vuln,
                "severity": level,
                "score": score,
                "context": {
                    "sensitive_path": is_sensitive_path,
                    "endpoint": path
                }
            })

    return findings
