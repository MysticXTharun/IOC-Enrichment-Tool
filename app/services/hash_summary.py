def summarize_hash(vt_result):

    attributes = vt_result.get("data", {}).get("attributes", {})

    stats = attributes.get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if malicious >= 10:
        risk = "High"
    elif malicious >= 3:
        risk = "Medium"
    elif malicious >= 1:
        risk = "Low"
    else:
        risk = "Clean"

    return {
        "risk": risk,
        "malicious_engines": malicious,
        "suspicious_engines": suspicious,
    }
