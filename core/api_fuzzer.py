import json
import requests
from urllib.parse import urljoin

# High-signal parameter names
SENSITIVE_PARAMS = {

    # =========================
    # IDENTIFIERS / IDOR
    # =========================
    "id","uid","uuid","guid","user","user_id","userid","account","account_id",
    "profile","profile_id","member","member_id","customer","customer_id",
    "order","order_id","invoice","invoice_id","payment","payment_id",
    "transaction","transaction_id","record","record_id","object","object_id",
    "resource","resource_id","item","item_id","asset","asset_id",

    # =========================
    # AUTH / SESSION / TOKENS
    # =========================
    "token","access_token","refresh_token","auth","authorization","bearer",
    "session","session_id","sid","jwt","csrf","csrf_token","xsrf","xsrf_token",
    "apikey","api_key","api-key","secret","client_secret","private_key",
    "key","sign","signature","sig","nonce","otp","pin","passcode",

    # =========================
    # ROLES / PERMISSIONS
    # =========================
    "role","roles","admin","administrator","superuser","root","staff",
    "permission","permissions","scope","scopes","access","access_level",
    "level","group","groups","privilege","privileges","capability",
    "is_admin","isAdmin","is_staff","isStaff","is_root",

    # =========================
    # FILE / PATH / STORAGE
    # =========================
    "file","filename","filepath","path","dir","directory","folder",
    "doc","document","attachment","upload","download","export","import",
    "template","view","layout","include","resource_path","storage",
    "bucket","object_key","s3key","blob","container",

    # =========================
    # REDIRECT / URL / SSRF
    # =========================
    "url","uri","redirect","redirect_url","redirect_uri","next","return",
    "return_url","callback","callback_url","continue","dest","destination",
    "target","target_url","host","hostname","domain","origin","referer",
    "ref","link","source","endpoint","webhook","webhook_url",

    # =========================
    # SEARCH / FILTER / QUERY
    # =========================
    "q","query","search","keyword","term","filter","filters","where",
    "condition","criteria","sort","order_by","orderby","group_by",
    "having","limit","offset","page","page_size","count","size",

    # =========================
    # COMMAND / EXECUTION
    # =========================
    "cmd","command","exec","execute","run","shell","script","process",
    "job","task","action","operation","op","function","method",

    # =========================
    # DATA / SERIALIZATION
    # =========================
    "data","payload","body","content","json","object","objects",
    "state","state_id","context","params","arguments","input","inputs",
    "config","configuration","settings","options","preferences",

    # =========================
    # XML / XXE / PARSING
    # =========================
    "xml","doctype","entity","entities","schema","dtd","xpath","xquery",

    # =========================
    # BUSINESS LOGIC / MONEY
    # =========================
    "price","amount","total","subtotal","balance","credit","debit",
    "discount","coupon","promo","voucher","offer","reward","points",
    "rate","tax","fee","commission","margin","currency","wallet",
    "limit","threshold","quota","usage","consumption",

    # =========================
    # PAYMENT / FINANCIAL
    # =========================
    "card","card_number","cc","cc_number","pan","cvv","cvc","expiry",
    "iban","swift","bic","routing","account_number","bank","branch",
    "payment_method","method","provider","gateway",

    # =========================
    # USER DATA / PII
    # =========================
    "email","username","login","password","passwd","pwd","hash",
    "phone","mobile","contact","address","zipcode","postcode",
    "ssn","sin","national_id","passport","dob","birthdate",

    # =========================
    # API / VERSIONING
    # =========================
    "api","api_version","version","v","v1","v2","v3","build","release",
    "revision","commit","branch","environment","env",

    # =========================
    # DEBUG / INTERNAL
    # =========================
    "debug","debug_mode","test","testing","sandbox","internal","private",
    "dev","development","staging","qa","trace","trace_id","log","logs",
    "verbose","diagnostic","health","status",

    # =========================
    # GRAPHQL / BFF
    # =========================
    "query","mutation","operationName","variables","extensions",
    "persistedQuery","depth","complexity","cost","resolver","field",

    # =========================
    # CLOUD / INFRA
    # =========================
    "project","project_id","tenant","tenant_id","org","organization",
    "subscription","subscription_id","region","zone","cluster","node",
    "instance","instance_id","vm","container_id",

    # =========================
    # MOBILE / DEVICE
    # =========================
    "device","device_id","deviceid","imei","imsi","android_id","ios_id",
    "push_token","fcm","apns","notification","token_id",

    # =========================
    # MISC HIGH-SIGNAL
    # =========================
    "code","status","state","result","response","message","error",
    "reason","type","category","mode","flag","enabled","disabled",
    "active","inactive","verified","approved","locked","blocked"
}


# HTTP method risk weight
METHOD_RISK = {
    "GET": 1,
    "POST": 2,
    "PUT": 3,
    "PATCH": 3,
    "DELETE": 4
}


def load_openapi_schema(path):
    with open(path, "r") as f:
        return json.load(f)

def generate_safe_tests(schema, base_url, headers=None, timeout=10):
    """
        Generate SAFE API intelligence from OpenAPI schema.
        No exploitation. No payload fuzzing.
        Cookie-aware.
        """

    findings = []

    paths = schema.get("paths", {})

    for path, methods in paths.items():
        for method, meta in methods.items():

            method = method.upper()
            params = meta.get("parameters", [])

            param_names = []
            required_params = []
            sensitive = []

            for p in params:
                name = p.get("name")
                if not name:
                    continue

                param_names.append(name)

                if p.get("required"):
                    required_params.append(name)

                if name.lower() in SENSITIVE_PARAMS:
                    sensitive.append(name)

            # Replace path params with safe placeholder
            test_path = path
            for p in param_names:
                test_path = test_path.replace(f"{{{p}}}", "1")

            url = urljoin(base_url.rstrip("/") + "/", test_path.lstrip("/"))

            # Build request
            try:
                r = requests.request(
                    method,
                    url,
                    headers=headers,
                    timeout=timeout,
                    verify=False
                )
                status = r.status_code
                length = len(r.text)
                ctype = r.headers.get("Content-Type", "")
            except Exception:
                continue

            finding = {
                "endpoint": url,
                "method": method,
                "risk_score": METHOD_RISK.get(method, 1),
                "parameters": param_names,
                "required_parameters": required_params,
                "sensitive_parameters": sensitive,
                "auth_required": status in (401, 403),
                "response": {
                    "status": status,
                    "length": length,
                    "content_type": ctype
                }
            }

            # Risk classification
            if sensitive and METHOD_RISK.get(method, 1) >= 3:
                finding["risk"] = "HIGH"
            elif sensitive:
                finding["risk"] = "MEDIUM"
            else:
                finding["risk"] = "LOW"

            findings.append(finding)

    return findings
