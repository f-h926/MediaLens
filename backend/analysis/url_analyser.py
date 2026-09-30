from urllib.parse import urlparse
import ipaddress


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "account",
    "password",
    "free",
    "download",
    "torrent",
    "crack",
    "signin",
    "update",
    "secure"
]


def add_finding(findings, finding_type, severity, title, description):
    """
    Add a security finding to the results list.
    """

    findings.append({
        "type": finding_type,
        "severity": severity,
        "title": title,
        "description": description
    })


def analyse_url(url):
    parsed_url = urlparse(url)

    hostname = parsed_url.hostname or ""
    hostname_lower = hostname.lower()
    lowercase_url = url.lower()

    findings = []

    # -----------------------------
    # 1. HTTPS check
    # -----------------------------

    uses_https = parsed_url.scheme == "https"

    if not uses_https:
        add_finding(
            findings,
            "warning",
            "medium",
            "Connection is not encrypted",
            "This URL uses HTTP instead of HTTPS. Information sent to the website may not be securely encrypted."
        )

    # -----------------------------
    # 2. IP address check
    # -----------------------------

    is_ip_address = False
    is_private_ip = False

    try:
        ip = ipaddress.ip_address(hostname)

        is_ip_address = True
        is_private_ip = ip.is_private

        if is_private_ip:
            add_finding(
                findings,
                "warning",
                "high",
                "Private IP address detected",
                "This URL points to a private network address rather than a public website."
            )

        else:
            add_finding(
                findings,
                "warning",
                "medium",
                "Raw IP address used",
                "This URL uses an IP address instead of a normal domain name. This can sometimes be seen in suspicious or phishing links."
            )

    except ValueError:
        pass

    # -----------------------------
    # 3. Punycode check
    # -----------------------------

    uses_punycode = any(
        part.startswith("xn--")
        for part in hostname_lower.split(".")
    )

    if uses_punycode:
        add_finding(
            findings,
            "warning",
            "high",
            "Punycode domain detected",
            "This domain uses Punycode. Punycode can legitimately represent international characters, but it is also sometimes used to imitate trusted website names."
        )

    # -----------------------------
    # 4. Suspicious keyword check
    # -----------------------------

    keyword_matches = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in lowercase_url
    ]

    if keyword_matches:
        add_finding(
            findings,
            "warning",
            "low",
            "Suspicious URL keywords detected",
            "The URL contains potentially sensitive or suspicious terms: "
            + ", ".join(keyword_matches)
            + "."
        )

    # -----------------------------
    # 5. @ symbol check
    # -----------------------------

    contains_at_symbol = "@" in parsed_url.netloc

    if contains_at_symbol:
        add_finding(
            findings,
            "warning",
            "high",
            "@ symbol detected in URL",
            "The URL contains an @ symbol. This can sometimes be used to make the real destination of a link less obvious."
        )

    # -----------------------------
    # 6. URL length check
    # -----------------------------

    url_length = len(url)

    if url_length > 150:
        add_finding(
            findings,
            "warning",
            "low",
            "Unusually long URL",
            f"This URL is {url_length} characters long. Very long URLs can sometimes be used to hide suspicious information."
        )

    # -----------------------------
    # 7. Excessive subdomain check
    # -----------------------------

    hostname_parts = hostname_lower.split(".")

    excessive_subdomains = len(hostname_parts) > 4

    if excessive_subdomains:
        add_finding(
            findings,
            "warning",
            "medium",
            "Multiple subdomains detected",
            "This URL contains an unusually large number of subdomains, which can sometimes be used to disguise the actual website domain."
        )

    # -----------------------------
    # 8. Query string check
    # -----------------------------

    query_present = bool(parsed_url.query)

    # Query strings are normal, so we do not
    # automatically create a warning for them.

    # -----------------------------
    # No obvious findings
    # -----------------------------

    if not findings:
        add_finding(
            findings,
            "success",
            "info",
            "No obvious URL-based warnings detected",
            "The URL does not currently contain any of the suspicious characteristics checked by MediaLens."
        )

    # -----------------------------
    # Final response
    # -----------------------------

    return {
        "url": url,
        "scheme": parsed_url.scheme,
        "hostname": hostname,
        "path": parsed_url.path or "/",
        "query_present": query_present,

        "uses_https": uses_https,
        "is_ip_address": is_ip_address,
        "is_private_ip": is_private_ip,
        "uses_punycode": uses_punycode,
        "contains_at_symbol": contains_at_symbol,
        "excessive_subdomains": excessive_subdomains,

        "keyword_matches": keyword_matches,
        "url_length": url_length,

        "findings": findings
    }