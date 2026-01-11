import json
from pathlib import Path
from datetime import datetime

def generate_report(report_data, output_html):
    """
    Generate a SINGLE self-contained HTML report
    containing ALL scan intelligence and raw JSON.
    """

    endpoints = []
    js_logic = []          # JS logic signals (simple)
    js_logic_graph = []    # JS logic graph (advanced)
    graphql = []
    diff_data = []
    graphql_depth = []
    api_intel = []


    for item in report_data:
        # Endpoint-level intelligence
        if "endpoint" in item:
            endpoints.append(item)

        #api intel
        if "api_intelligence" in item:
            api_intel.extend(item["api_intelligence"])

        # JS logic intelligence (regex-based signals)
        if "js_logic_intelligence" in item:
            js_logic.extend(item["js_logic_intelligence"])

        # JS logic graph (condition → API → JS file)
        if "js_logic_graph" in item:
            js_logic_graph.extend(item["js_logic_graph"])

        # GraphQL intelligence
        if "graphql_intelligence" in item:
            graphql.extend(item["graphql_intelligence"])
        if "graphql_depth_intelligence" in item:
            graphql_depth.extend(item["graphql_depth_intelligence"])

        # Attack surface diff
        if "diff" in item:
            diff_data = item["diff"]

    template = Path("reporting/template.html").read_text()

    html = (
        template
        .replace("__GENERATED__", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))
        .replace("__ENDPOINTS__", json.dumps(endpoints))
        .replace("__JS_LOGIC__", json.dumps(js_logic, indent=2))
        .replace("__JS_LOGIC_GRAPH__", json.dumps(js_logic_graph, indent=2))
        .replace("__GRAPHQL__", json.dumps(graphql, indent=2))
        .replace("__API_INTEL__", json.dumps(api_intel, indent=2))
        .replace("__GRAPHQL_DEPTH__", json.dumps(graphql_depth, indent=2))
        .replace("__DIFF__", json.dumps(diff_data, indent=2) if diff_data else "null")
        .replace("__RAW_JSON__", json.dumps(report_data, indent=2))
    )

    Path(output_html).write_text(html)
