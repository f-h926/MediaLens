RISK_WEIGHTS = {
    "http": 10,
    "raw_ip": 15,
    "private_ip": 25,
    "punycode": 25,
    "at_symbol": 25,
    "suspicious_keywords": 5,
    "long_url": 5,
    "excessive_subdomains": 10
}


def calculate_risk(analysis):
    
    # calculate a URL risk score based on the indicators discovered by the MediaLens URL analyser

    score = 0
    reasons = []

    # HTTP instead of HTTPS
    if not analysis["uses_https"]:
        score += RISK_WEIGHTS["http"]
        reasons.append({
            "indicator": "http",
            "score": RISK_WEIGHTS["http"],
            "reason": "The URL does not use HTTPS."
        })

    # raw IP address
    if analysis["is_ip_address"]:
        score += RISK_WEIGHTS["raw_ip"]
        reasons.append({
            "indicator": "raw_ip",
            "score": RISK_WEIGHTS["raw_ip"],
            "reason": "The URL uses a raw IP address."
        })

    # private network IP
    if analysis["is_private_ip"]:
        score += RISK_WEIGHTS["private_ip"]
        reasons.append({
            "indicator": "private_ip",
            "score": RISK_WEIGHTS["private_ip"],
            "reason": "The URL points to a private network address."
        })

    # punycode
    if analysis["uses_punycode"]:
        score += RISK_WEIGHTS["punycode"]
        reasons.append({
            "indicator": "punycode",
            "score": RISK_WEIGHTS["punycode"],
            "reason": "The domain uses Punycode."
        })

    # @ character
    if analysis["contains_at_symbol"]:
        score += RISK_WEIGHTS["at_symbol"]
        reasons.append({
            "indicator": "at_symbol",
            "score": RISK_WEIGHTS["at_symbol"],
            "reason": "The URL contains an @ symbol."
        })

    # suspicious words
    if analysis["keyword_matches"]:
        score += RISK_WEIGHTS["suspicious_keywords"]
        reasons.append({
            "indicator": "suspicious_keywords",
            "score": RISK_WEIGHTS["suspicious_keywords"],
            "reason": (
                "Potentially suspicious keywords were detected: "
                + ", ".join(analysis["keyword_matches"])
            )
        })

    # very long URL
    if analysis["url_length"] > 150:
        score += RISK_WEIGHTS["long_url"]
        reasons.append({
            "indicator": "long_url",
            "score": RISK_WEIGHTS["long_url"],
            "reason": "The URL is unusually long."
        })

    # excessive subdomains
    if analysis["excessive_subdomains"]:
        score += RISK_WEIGHTS["excessive_subdomains"]
        reasons.append({
            "indicator": "excessive_subdomains",
            "score": RISK_WEIGHTS["excessive_subdomains"],
            "reason": "The URL contains an unusually large number of subdomains."
        })

    # maximum possible displayed score
    score = min(score, 100)
    risk_level = get_risk_level(score)

    return {
        "score": score,
        "level": risk_level,
        "reasons": reasons
    }


def get_risk_level(score):

    if score <= 19:
        return "Low"

    elif score <= 49:
        return "Caution"

    elif score <= 74:
        return "Suspicious"

    else:
        return "High Risk"

def calculate_combined_risk(local_risk, virustotal, urlhaus):

    # combine the local risk score with the VirusTotal and URLhaus threat intelligence to produce a final risk score
    local_score = min(local_risk["score"], 40)

    combined_score = local_score

    reasons = list(local_risk["reasons"])

    threat_intelligence_used = False

    # virustotal 
    if virustotal.get("available", False) and virustotal.get("found", False):

        threat_intelligence_used = True

        stats = virustotal.get("stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        # stronger malicious detections = higher weight
        if malicious >= 10:

            combined_score += 60

            reasons.append({
                "indicator": "virustotal_malicious",
                "score": 60,
                "reason": (
                    f"VirusTotal reports {malicious} "
                    "security engines marking this URL as malicious."
                )
            })

        elif malicious >= 5:

            combined_score += 50

            reasons.append({
                "indicator": "virustotal_malicious",
                "score": 50,
                "reason": (
                    f"VirusTotal reports {malicious} "
                    "security engines marking this URL as malicious."
                )
            })

        elif malicious >= 2:

            combined_score += 35

            reasons.append({
                "indicator": "virustotal_malicious",
                "score": 35,
                "reason": (
                    f"VirusTotal reports {malicious} malicious detections."
                )
            })

        elif malicious == 1:

            combined_score += 15

            reasons.append({
                "indicator": "virustotal_malicious",
                "score": 15,
                "reason": (
                    "One VirusTotal security engine "
                    "marked this URL as malicious."
                )
            })

        # suspicious detections
        if suspicious >= 3:

            combined_score += 10

            reasons.append({
                "indicator": "virustotal_suspicious",
                "score": 10,
                "reason": (
                    f"{suspicious} VirusTotal engines "
                    "marked this URL as suspicious."
                )
            })

        elif suspicious >= 1:

            combined_score += 5

            reasons.append({
                "indicator": "virustotal_suspicious",
                "score": 5,
                "reason": (
                    f"{suspicious} VirusTotal engine(s) "
                    "marked this URL as suspicious."
                )
            })

        # URLhaus
        if urlhaus.get("available", False) and urlhaus.get("found", False):

            threat_intelligence_used = True

            combined_score += 50

            threat = urlhaus.get("threat") or "malware-related activity"

            reasons.append({
                "indicator": "urlhaus_match",
                "score": 50,
                "reason": (
                    "This URL has an exact match in the URLhaus "
                    f"malware database. Reported threat: {threat}."
                )
            })

        # prevent scores from exceeding 100
        combined_score = min(combined_score, 100)

        return {
            "score": combined_score,
            "level": get_risk_level(combined_score),
            "reasons": reasons,
            "threat_intelligence_used": threat_intelligence_used
        }
