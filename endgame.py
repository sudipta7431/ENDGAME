#!/usr/bin/env python3

import argparse
import datetime
from pathlib import Path
from urllib.parse import urlparse

# Core modules
from core.browser import browser_crawl
from core.auth_flows import login_form
from core.api_fuzzer import load_openapi_schema, generate_safe_tests
from core.diffing import save_snapshot, load_snapshot, diff
from core.threatintel import enrich
from core.crawler import crawl
from core.classifier import classify
from core.normalizer import normalize
from core.behavior import analyze_parameter_behavior
from core.differential import differential_analysis
from core.semantic_diff import semantic_response_diff
from core.scoring import score_endpoint

# Advanced intelligence
from core.js_intel import analyze_js_logic              # JS signals
from core.js_patterns import JS_PATTERNS
from core.js_logic_graph import build_js_logic_graph    # JS logic graph
from core.graphql_intel import analyze_graphql
from core.graphql_depth import analyze_graphql_depth
# Reporting
from reporting.report import generate_report

# -------------------------
# Utility
# -------------------------

def domain_from_url(url):
    return urlparse(url).netloc.replace("www.", "")

def today():
    return datetime.date.today().isoformat()

def ensure_dirs():
    Path("data/snapshots").mkdir(parents=True, exist_ok=True)
    Path("output/reports").mkdir(parents=True, exist_ok=True)

# -------------------------
# CLI
# -------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="ENDGAME v5 – Advanced Attack Surface Intelligence Engine"
    )

    parser.add_argument("-u", "--url", required=True, help="Target URL")
    #cookie
    parser.add_argument(
        "--cookie",
        help="Cookie header value (e.g. key1=value; key2=value)"
    )
    # Performance
    parser.add_argument("--depth", type=int, default=2)
    parser.add_argument("--pages", type=int, default=100)
    parser.add_argument("--threads", type=int, default=10)

    # Browser & Auth
    parser.add_argument("--browser", action="store_true")
    parser.add_argument("--auth", choices=["form"])
    parser.add_argument("--login-url")
    parser.add_argument("--username")
    parser.add_argument("--password")
    parser.add_argument("--user-sel")
    parser.add_argument("--pass-sel")
    parser.add_argument("--submit-sel")

    # API
    parser.add_argument("--api-fuzz")

    # Intelligence
    parser.add_argument("--diff", action="store_true")

    return parser.parse_args()

# -------------------------
# Main Execution
# -------------------------

def main():
    args = parse_args()
    ensure_dirs()

    headers = {
        "User-Agent": "endgame-v5"
    }
    if args.cookie:
        headers["Cookie"] = args.cookie

    discovered_endpoints = set()
    report = []

    print("[*] ENDGAME v5 started")

    # -------------------------
    # Authentication
    # -------------------------
    if args.auth == "form":
        print("[*] Capturing authenticated session")
        selectors = {
            "username": args.user_sel,
            "password": args.pass_sel,
            "submit": args.submit_sel
        }
        login_form(
            args.login_url,
            args.username,
            args.password,
            selectors
        )

    # -------------------------
    # HTTP Crawling
    # -------------------------
    print("[*] Running HTTP crawler")
    for ep in crawl(
        args.url,
        max_depth=args.depth,
        max_pages=args.pages,
        threads=args.threads,
        headers=headers,
    ):
        discovered_endpoints.add(normalize(ep))

    # -------------------------
    # Browser Crawling
    # -------------------------
    if args.browser:
        print("[*] Running headless browser crawl")
        for ep in browser_crawl(args.url):
            discovered_endpoints.add(normalize(ep))

    # -------------------------
    # API Discovery
    # -------------------------
    if args.api_fuzz:
        print("[*] Loading OpenAPI schema")
        schema = load_openapi_schema(args.api_fuzz)
        api_intel = generate_safe_tests(schema, args.url, headers)
        if api_intel:
            report.append({"api_intelligence": api_intel})
            for item in api_intel:
                discovered_endpoints.add(item["endpoint"])

    # -------------------------
    # GraphQL Intelligence
    # -------------------------
    print("[*] Analyzing GraphQL surface")
    graphql_intel = analyze_graphql(args.url, headers)
    if graphql_intel:
        report.append({"graphql_intelligence": graphql_intel})
    # -------------------------
    # GraphQL Depth Intelligence (ADVANCED)
    # -------------------------
    print("[*] Analyzing GraphQL depth intelligence")
    graphql_depth = analyze_graphql_depth(args.url, headers)
    if graphql_depth:
        report.append({
            "graphql_depth_intelligence": graphql_depth
        })
    # -------------------------
    # JavaScript Intelligence (Signals)
    # -------------------------
    print("[*] Analyzing JavaScript logic signals")
    js_intel = analyze_js_logic(args.url, JS_PATTERNS, headers)
    if js_intel:
        report.append({"js_logic_intelligence": js_intel})

    # -------------------------
    # JavaScript Logic Graph (ADVANCED)
    # -------------------------
    print("[*] Building JavaScript logic graph")
    js_logic_graph = build_js_logic_graph(args.url, JS_PATTERNS, headers)
    if js_logic_graph:
        report.append({"js_logic_graph": js_logic_graph})

    # -------------------------
    # Endpoint Analysis
    # -------------------------
    print("[*] Classifying, enriching, and scoring attack surface")

    for ep in sorted(discovered_endpoints):
        issues = classify(ep)
        intel = enrich(ep)
        behavior = analyze_parameter_behavior(ep, headers)
        differential = differential_analysis(ep, headers)
        semantic = semantic_response_diff(ep, headers)

        scoring = score_endpoint(
            ep,
            issues,
            behavior,
            differential,
            intel
        )

        report.append({
            "endpoint": ep,
            "issues": issues,
            "intelligence": intel,
            "behavior": behavior,
            "differential": differential,
            "semantic_diff": semantic,
            "attack_surface_score": scoring
        })

    # -------------------------
    # Snapshot + Diff
    # -------------------------
    if discovered_endpoints:
        save_snapshot(list(discovered_endpoints), today())

    if args.diff:
        yesterday = (datetime.date.today() - datetime.timedelta(days=1)).isoformat()
        changes = diff(load_snapshot(yesterday), list(discovered_endpoints))
        report.append({"diff": changes})

    # -------------------------
    # Single HTML Output
    # -------------------------
    domain = domain_from_url(args.url)
    html_output = f"output/reports/{domain}.html"

    generate_report(report, html_output)

    print(f"[+] Unified HTML report generated: {html_output}")
    print("[+] ENDGAME v5 completed successfully")

# -------------------------
if __name__ == "__main__":
    main()
