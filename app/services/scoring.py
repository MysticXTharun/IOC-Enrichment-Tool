def score_ip(abuseipdb: dict, otx: dict, virustotal: dict):
    """
    Returns:
        risk_score (0–100)
        verdict (Clean / Low / Suspicious / Malicious)
        confidence (Low / Medium / High)
    """

    score = 0

    # -------------------------
    # AbuseIPDB signals
    # -------------------------
    abuse_confidence = (
        abuseipdb.get("data", {}).get("abuseConfidenceScore", 0)
    )

    if abuse_confidence > 75:
        score += 40
    elif abuse_confidence > 30:
        score += 25
    elif abuse_confidence > 0:
        score += 10

    # -------------------------
    # VirusTotal signals
    # -------------------------
    vt_stats = virustotal.get("data", {}).get("attributes", {}).get(
        "last_analysis_stats", {}
    )

    vt_malicious = vt_stats.get("malicious", 0)
    vt_suspicious = vt_stats.get("suspicious", 0)

    if vt_malicious > 5:
        score += 40
    elif vt_malicious > 0:
        score += 25

    if vt_suspicious > 0:
        score += 10

    # -------------------------
    # OTX signals
    # -------------------------
    otx_pulses = 0

    if isinstance(otx, dict):
        otx_pulses = otx.get("pulse_info", {}).get("count", 0)

    if otx_pulses > 50:
        score += 20
    elif otx_pulses > 10:
        score += 10
    elif otx_pulses > 0:
        score += 5

    # -------------------------
    # Normalize score
    # -------------------------
    if score > 100:
        score = 100

    # -------------------------
    # Verdict logic
    # -------------------------
    if score >= 75:
        verdict = "Malicious"
    elif score >= 40:
        verdict = "Suspicious"
    elif score > 0:
        verdict = "Low"
    else:
        verdict = "Clean"

    # -------------------------
    # Confidence logic
    # -------------------------
    signals = sum([
        abuse_confidence > 0,
        vt_malicious > 0,
        otx_pulses > 0,
    ])

    if signals == 3:
        confidence = "High"
    elif signals == 2:
        confidence = "Medium"
    else:
        confidence = "Low"

    return {
        "risk_score": score,
        "verdict": verdict,
        "confidence": confidence,
        "signals": {
            "abuse_confidence": abuse_confidence,
            "vt_malicious": vt_malicious,
            "otx_pulses": otx_pulses,
        },
    }
