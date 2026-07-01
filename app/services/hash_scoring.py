def score_hash(vt_result):

    attributes = vt_result.get("data", {}).get("attributes", {})

    stats = attributes.get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    risk_score = 0

    risk_score += malicious * 15
    risk_score += suspicious * 5

    if risk_score > 100:
        risk_score = 100

    if risk_score >= 80:
        verdict = "Malicious"
        confidence = "High"

    elif risk_score >= 50:
        verdict = "Suspicious"
        confidence = "Medium"

    elif risk_score >= 20:
        verdict = "Low"
        confidence = "Medium"

    else:
        verdict = "Clean"
        confidence = "High"

    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "confidence": confidence,
        "signals": {
            "vt_malicious": malicious,
            "vt_suspicious": suspicious,
        },
    }
