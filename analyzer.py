import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "verification",
    "secure",
    "account",
    "password",
    "update",
    "confirm",
    "claim",
    "bonus",
    "reward",
    "free",
    "winner",
    "urgent",
    "gift",
    "crypto",
    "wallet"
]


KNOWN_BRANDS = [
    "google.com",
    "facebook.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "paypal.com"
]


def analyze_url(url):
    score = 0
    reasons = []

    parsed = urlparse(url)

    # HTTPS check
    if parsed.scheme != "https":
        score += 25
        reasons.append("Website does not use HTTPS")

    domain = parsed.netloc.lower()

    # Remove username/password if present
    if "@" in url:
        score += 30
        reasons.append("URL contains an @ symbol")

    # Suspicious keywords
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url.lower():
            score += 10
            reasons.append(
                f"URL contains suspicious keyword: {keyword}"
            )

    # Very long URL
    if len(url) > 100:
        score += 10
        reasons.append("URL is unusually long")

    # Multiple subdomains
    if domain.count(".") >= 3:
        score += 10
        reasons.append(
            "Domain contains multiple subdomains"
        )

    # IP address instead of domain
    if re.search(r"^\d+\.\d+\.\d+\.\d+$", domain):
        score += 25
        reasons.append(
            "URL uses an IP address instead of a domain name"
        )

    # Suspicious TLDs
    suspicious_tlds = [
        ".zip",
        ".top",
        ".click",
        ".buzz",
        ".tk",
        ".ml",
        ".ga",
        ".cf"
    ]

    for tld in suspicious_tlds:
        if domain.endswith(tld):
            score += 15
            reasons.append(
                f"Domain uses a potentially risky TLD: {tld}"
            )
            break

    # URL shorteners
    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "cutt.ly"
    ]

    for shortener in shorteners:
        if shortener in domain:
            score += 15
            reasons.append(
                "URL uses a URL shortening service"
            )
            break

    # Possible brand impersonation
    brand_variations = {
        "paypal": ["paypa1", "pay-pal", "paypal-login"],
        "microsoft": ["micros0ft", "microsoft-login"],
        "facebook": ["faceb00k", "facebook-login"],
        "google": ["g00gle", "google-login"],
        "amazon": ["amaz0n", "amazon-login"]
    }

    for brand, variations in brand_variations.items():
        for variation in variations:
            if variation in domain:
                score += 25
                reasons.append(
                    f"Domain may be impersonating {brand}"
                )
                break

    return {
        "risk_level": calculate_risk(score),
        "score": min(score, 100),
        "reasons": reasons
    }


def analyze_message(message):
    score = 0
    reasons = []

    text = message.lower()

    urgent_words = [
        "urgent",
        "immediately",
        "act now",
        "last chance",
        "account suspended",
        "verify now"
    ]

    money_words = [
        "money",
        "cash",
        "payment",
        "transfer",
        "bank",
        "bonus",
        "reward",
        "prize"
    ]

    for word in urgent_words:
        if word in text:
            score += 15
            reasons.append(
                f"Message uses pressure language: {word}"
            )

    for word in money_words:
        if word in text:
            score += 10
            reasons.append(
                f"Message mentions financial activity: {word}"
            )

    if "click here" in text:
        score += 15
        reasons.append("Message asks the user to click a link")

    if "verify your account" in text:
        score += 20
        reasons.append("Message requests account verification")

    if re.search(r"https?://", text):
        score += 15
        reasons.append("Message contains a URL")

    return {
        "risk_level": calculate_risk(score),
        "score": min(score, 100),
        "reasons": reasons
    }


def analyze_email(email):
    score = 0
    reasons = []

    email = email.lower().strip()

    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
        score += 40
        reasons.append("Email address format appears invalid")

    suspicious_domains = [
        "tempmail",
        "mailinator",
        "10minutemail"
    ]

    for domain in suspicious_domains:
        if domain in email:
            score += 30
            reasons.append(
                "Email uses a temporary/disposable email service"
            )

    return {
        "risk_level": calculate_risk(score),
        "score": min(score, 100),
        "reasons": reasons
    }


def analyze_phone(phone):
    score = 0
    reasons = []

    cleaned = re.sub(r"[\s\-\(\)]", "", phone)

    if not re.match(r"^\+?\d{7,15}$", cleaned):
        score += 40
        reasons.append("Phone number format appears unusual")

    if len(cleaned) < 10:
        score += 20
        reasons.append("Phone number is unusually short")

    return {
        "risk_level": calculate_risk(score),
        "score": min(score, 100),
        "reasons": reasons
    }


def calculate_risk(score):

    if score >= 60:
        return "HIGH RISK"

    elif score >= 30:
        return "SUSPICIOUS"

    else:
        return "LOW RISK"
