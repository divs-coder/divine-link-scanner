from urllib.parse import urlparse
from datetime import datetime, timezone
import socket

import requests
import whois


def analyze_url(url):
    score = 0
    reasons = []

    # Clean the input
    url = url.strip()

    if url.startswith("https:// https://") or url.startswith("http:// http://"):
        return {
            "url": url,
            "risk_score": 100,
            "risk_level": "HIGH",
            "reasons": ["Malformed URL: duplicate protocol detected."]
        }

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        return {
            "url": url,
            "risk_score": 100,
            "risk_level": "HIGH",
            "reasons": ["Invalid URL."]
        }

    # -------------------------
    # HTTPS
    # -------------------------
    if parsed.scheme != "https":
        score += 15
        reasons.append("Website does not use HTTPS.")
    else:
        reasons.append("HTTPS is enabled.")

    # -------------------------
    # Suspicious URL keywords
    # -------------------------
    suspicious_words = [
        "login",
        "verify",
        "wallet",
        "bonus",
        "double",
        "profit",
        "investment",
        "crypto",
        "free-money",
        "claim",
        "reward"
    ]

    found_words = [
        word for word in suspicious_words
        if word in url.lower()
    ]

    if found_words:
        score += min(len(found_words) * 4, 20)
        reasons.append(
            "Suspicious keywords detected: " +
            ", ".join(found_words)
        )

    # -------------------------
    # URL length
    # -------------------------
    if len(url) > 150:
        score += 10
        reasons.append("URL is unusually long.")

    # -------------------------
    # DNS resolution
    # -------------------------
    try:
        ip = socket.gethostbyname(hostname)
        reasons.append(f"DNS resolves successfully to {ip}.")
    except socket.gaierror:
        score += 25
        reasons.append("Domain could not be resolved by DNS.")

    # -------------------------
    # WHOIS
    # -------------------------
    try:
        domain_info = whois.whois(hostname)
        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)

            age_days = (
                datetime.now(timezone.utc) - creation_date
            ).days

            if age_days < 30:
                score += 30
                reasons.append(
                    f"Domain is very new ({age_days} days old)."
                )
            elif age_days < 180:
                score += 15
                reasons.append(
                    f"Domain is relatively new ({age_days} days old)."
                )
            else:
                reasons.append(
                    f"Domain has existed for approximately "
                    f"{age_days} days."
                )
        else:
            reasons.append("WHOIS returned no creation date.")

    except Exception:
        # WHOIS failure should not automatically mean a website is fraudulent.
        reasons.append(
            "WHOIS information could not be retrieved."
        )

    # -------------------------
    # Website connection
    # -------------------------
    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": "DivineLinkScanner/1.0"
            }
        )

        if response.status_code >= 400:
            score += 20
            reasons.append(
                f"Website returned HTTP {response.status_code}."
            )
        else:
            reasons.append(
                f"Website responded successfully (HTTP {response.status_code})."
            )

        if response.history:
            redirect_count = len(response.history)
            score += min(redirect_count * 5, 15)
            reasons.append(
                f"Website used {redirect_count} redirect(s)."
            )

    except requests.RequestException as error:
        score += 30
        reasons.append(
            f"Website could not be reached: {error}"
        )

    # -------------------------
    # Final score
    # -------------------------
    score = min(score, 100)

    if score >= 70:
        risk = "HIGH"
    elif score >= 40:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "url": url,
        "risk_score": score,
        "risk_level": risk,
        "reasons": reasons
    }
