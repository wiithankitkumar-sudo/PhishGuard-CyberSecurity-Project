import re
from urllib.parse import urlparse
from ipaddress import ip_address


def analyze_url(url):
    url = url.strip()

    if not url:
        return {
            "valid": False,
            "error": "Please enter a URL."
        }

    if any(ord(char) < 32 or char.isspace() for char in url):
        return {
            "valid": False,
            "error": "URL contains invalid whitespace or control characters."
        }

    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        if parsed.scheme not in ("http", "https") or not hostname:
            raise ValueError

        hostname = hostname.lower()

        # Basic domain validation
        try:
            ip_address(hostname)
            is_ip = True
        except ValueError:
            is_ip = False

        if not is_ip:
            try:
                hostname.encode("idna")
            except UnicodeError:
                raise ValueError

            labels = hostname.rstrip(".").split(".")

            if (
                len(hostname) > 253
                or len(labels) < 2
                or any(
                    not label
                    or len(label) > 63
                    or label.startswith("-")
                    or label.endswith("-")
                    or not re.fullmatch(r"[a-z0-9-]+", label)
                    for label in labels
                )
            ):
                raise ValueError

    except (ValueError, UnicodeError):
        return {
            "valid": False,
            "error": "Please enter a valid HTTP or HTTPS URL."
        }

    findings = []
    score = 0

    if parsed.scheme == "http":
        findings.append("The URL uses HTTP instead of HTTPS.")
        score += 15

    if is_ip:
        findings.append("The URL uses an IP address instead of a domain name.")
        score += 25

    if len(url) > 100:
        findings.append("The URL is unusually long.")
        score += 10

    if "@" in parsed.netloc:
        findings.append("The URL contains an @ symbol in its authority.")
        score += 20

    if hostname.count(".") >= 4:
        findings.append("The hostname contains many subdomain levels.")
        score += 10

    suspicious_words = [
        "login",
        "verify",
        "account",
        "password",
        "secure",
        "update",
        "wallet"
    ]

    matched_words = [
        word for word in suspicious_words
        if word in url.lower()
    ]

    if matched_words:
        findings.append(
            "Potentially suspicious keywords: "
            + ", ".join(matched_words)
        )
        score += min(20, 5 * len(matched_words))

    score = min(score, 100)

    if score < 20:
        risk = "Low"
    elif score < 50:
        risk = "Medium"
    else:
        risk = "High"

    if not findings:
        findings.append(
            "No configured suspicious indicators were detected."
        )

    return {
        "valid": True,
        "url": url,
        "hostname": hostname,
        "https": parsed.scheme == "https",
        "score": score,
        "risk": risk,
        "findings": findings
    }