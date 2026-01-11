def score_endpoint(endpoint, issues, behavior, differential, intel):
    """
    Context-based attack surface scoring.
    Prioritizes endpoints for manual testing.
    """

    score = 0
    reasons = []

    # Semantic response difference
    if semantic := differential:
        score += 2
        reasons.append("Semantic response difference")

    # Intelligence signals
    for item in intel:
        if "admin" in item.lower():
            score += 3
            reasons.append("Admin surface")

        if "internal" in item.lower():
            score += 2
            reasons.append("Internal surface")

    # Parameter-based risk
    for issue in issues:
        vuln = issue.get("vulnerability", "")
        if vuln in ["LFI", "RCE"]:
            score += 3
            reasons.append(f"High-risk parameter ({vuln})")
        elif vuln in ["SQLi", "XSS"]:
            score += 2
            reasons.append(f"Medium-risk parameter ({vuln})")

    # Behavior analysis
    if behavior:
        score += 2
        reasons.append("Behavioral change detected")

    # Differential analysis
    if differential:
        score += 3
        reasons.append("Logic difference detected")

    # Final priority label
    if score >= 8:
        priority = "🔥 VERY HIGH"
    elif score >= 5:
        priority = "⚠️ HIGH"
    elif score >= 3:
        priority = "ℹ️ MEDIUM"
    else:
        priority = "LOW"

    return {
        "score": score,
        "priority": priority,
        "reasons": reasons
    }
