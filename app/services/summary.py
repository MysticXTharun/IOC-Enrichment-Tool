def summarize_ip(abuse, otx, vt):
    """
    Build a simple analyst-friendly summary for IP addresses.
    """

    abuse_score = (
        abuse.get("data", {})
        .get("abuseConfidenceScore", 0)
    )

    vt_stats = (
        vt.get("data", {})
        .get("attributes", {})
        .get("last_analysis_stats", {})
    )

    malicious = vt_stats.get("malicious", 0)
    suspicious = vt_stats.get("suspicious", 0)

    pulses = len(
        otx.get("pulse_info", {})
        .get("pulses", [])
    )

    if abuse_score >= 75 or malicious >= 10:
        risk = "High"

    elif abuse_score >= 25 or malicious >= 3:
        risk = "Medium"

    else:
        risk = "Low"

    return {
        "risk": risk,
        "abuse_confidence": abuse_score,
        "malicious_engines": malicious,
        "suspicious_engines": suspicious,
        "otx_pulses": pulses,
    }
