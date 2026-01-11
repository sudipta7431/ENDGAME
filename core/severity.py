SCORES = {
    "RCE": 9.8,
    "SQLi": 8.2,
    "LFI": 7.5,
    "XSS": 6.1,
    "Open Redirect": 5.3,
    "INFO": 3.0
}

def severity(vuln):
    score = SCORES.get(vuln, 3.0)

    if score >= 9:
        level = "CRITICAL"
    elif score >= 7:
        level = "HIGH"
    elif score >= 5:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level
