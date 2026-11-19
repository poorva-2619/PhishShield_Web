import re

from backend.app.schemas import AnalysisReason, AnalyzeResponse
from backend.app.url_analysis import analyze_links


CREDENTIAL_REQUEST_PATTERNS = (
    re.compile(
        r"\b(?:send|share|reply(?:\s+with)?|provide|enter|submit|confirm|verify)\b"
        r".{0,50}\b(?:credential|credentials|password|passcode|pin|otp|one[- ]time password|"
        r"verification code|security code|login code)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:credential|credentials|password|passcode|pin|otp|one[- ]time password|"
        r"verification code|security code|login code)\b"
        r".{0,50}\b(?:send|share|reply|provide|enter|submit|confirm|verify)\b",
        re.IGNORECASE,
    ),
)

URGENCY_PATTERNS = (
    re.compile(
        r"\b(?:urgent|immediate(?:ly)?|right away|act now|final warning)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:account|access|service)\b.{0,40}"
        r"\b(?:will be|is|has been)?\s*(?:blocked|suspended|locked|closed)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bwithin\s+\d+\s+(?:minutes?|hours?|days?)\b", re.IGNORECASE),
)

UNEXPECTED_REWARD_PATTERNS = (
    re.compile(
        r"\b(?:selected|chosen|winner|won|eligible to receive|claim)\b.{0,100}"
        r"\b(?:reward|prize|bonus|gift|cash|lottery|jackpot)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:reward|prize|bonus|gift|cash|lottery|jackpot)\b.{0,100}"
        r"\b(?:selected|chosen|winner|won|eligible|claim)\b",
        re.IGNORECASE,
    ),
)

LIMITED_TIME_OFFER_PATTERNS = (
    re.compile(
        r"\b(?:offer|reward|prize|bonus|claim|promotion)\b.{0,60}"
        r"\b(?:expires?|ends?|valid)\b.{0,25}"
        r"\b(?:in|within|for)?\s*\d+\s+(?:minutes?|hours?|days?)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:expires?|ends?)\s+(?:in|within)\s+\d+\s+(?:minutes?|hours?|days?)\b",
        re.IGNORECASE,
    ),
)

SENSITIVE_INFORMATION_PATTERNS = (
    re.compile(r"\baccount number\b", re.IGNORECASE),
    re.compile(r"\b(?:registered )?mobile number\b", re.IGNORECASE),
    re.compile(r"\binternet banking user id\b", re.IGNORECASE),
    re.compile(r"\b(?:otp|one[- ]time password|verification code)\b", re.IGNORECASE),
    re.compile(r"\b(?:password|passcode|login credentials?)\b", re.IGNORECASE),
    re.compile(r"\b(?:debit|credit) card details?\b", re.IGNORECASE),
    re.compile(r"\bkyc details?\b", re.IGNORECASE),
)

SENSITIVE_INFORMATION_REQUEST_PATTERN = re.compile(
    r"\b(?:required to provide|asked to provide|provide|submit|share|send|"
    r"enter|verify|update|confirm)\b",
    re.IGNORECASE,
)

FINANCIAL_ACCOUNT_CONTEXT_PATTERN = re.compile(
    r"\b(?:bank|upi|payment|account|transactions?)\b",
    re.IGNORECASE,
)
IDENTITY_VERIFICATION_REQUEST_PATTERN = re.compile(
    r"\b(?:verify|confirm|validate|update)\b.{0,40}"
    r"\b(?:your\s+)?(?:identity|kyc|account)\b"
    r"|\b(?:identity|kyc|account)\b.{0,40}"
    r"\b(?:verify|confirm|validate|update)\b",
    re.IGNORECASE,
)
URL_PATTERN = re.compile(r"https?://\S+", re.IGNORECASE)
DELIVERY_CONTEXT_PATTERN = re.compile(
    r"\b(?:package|parcel|delivery|shipment|courier)\b",
    re.IGNORECASE,
)
DELIVERY_ADDRESS_ACTION_PATTERN = re.compile(
    r"\b(?:address|delivery details?)\b.{0,50}\b(?:incomplete|update|confirm|correct|verify)\b"
    r"|\b(?:update|confirm|correct|verify)\b.{0,50}\b(?:address|delivery details?)\b"
    r"|\b(?:return(?:ed|ing)?\s+(?:the\s+)?parcel|hold\s+(?:the\s+)?package)\b",
    re.IGNORECASE,
)
SUSPICIOUS_SIGN_IN_PATTERN = re.compile(
    r"\b(?:multiple|several|repeated|unsuccessful|failed)\b.{0,50}"
    r"\b(?:sign[- ]?in|log[- ]?in)\s+attempts?\b"
    r".{0,120}\b(?:unknown|unrecognized|unrecognised|new)\s+device\b"
    r"|\b(?:multiple|several|repeated|unsuccessful|failed)\b.{0,50}"
    r"\b(?:sign[- ]?in|log[- ]?in)\s+attempts?\b"
    r".{0,120}\b(?:account|profile)\b.{0,30}\bcompromised\b"
    r"|\b(?:account|profile)\b.{0,30}\bcompromised\b"
    r".{0,120}\b(?:multiple|several|repeated|unsuccessful|failed)\b.{0,50}"
    r"\b(?:sign[- ]?in|log[- ]?in)\s+attempts?\b",
    re.IGNORECASE,
)

SUGGESTIONS_BY_REASON = {
    "credential_request": (
        "Do not share passwords, PINs, or one-time codes in response to a message. "
        "Contact the organization through its official app or a number you already trust.",
    ),
    "sensitive_information_request": (
        "Do not send banking or identity details in reply. Contact your bank using its "
        "official app, website, or a phone number you already trust.",
    ),
    "identity_verification_request": (
        "Do not use the message link or share verification codes. Open your bank's official "
        "app or website yourself, or call a number you already trust.",
    ),
    "unexpected_reward": (
        "Do not pay fees or share personal or financial details to claim an unexpected prize. "
        "Verify the offer through the organization’s official channel.",
    ),
    "limited_time_offer": (
        "Do not let a deadline rush you. Verify the request independently before taking action.",
    ),
    "urgent_threat": (
        "Pause before acting on the threat. Contact the organization through an official "
        "channel you find independently.",
    ),
    "delivery_address_request": (
        "Don’t use the message link to update your address; check directly with the delivery "
        "company through its official site or app, using tracking details you already have.",
    ),
    "suspicious_login_activity": (
        "Do not use the message link to sign in or provide a security code. Open the service's "
        "official app or type its known website address yourself to review account activity.",
    ),
    "suspicious_link": (
        "Avoid opening this link or entering information on it. Visit the organization through "
        "its official app or a website address you already trust.",
    ),
}


def analyze_message(message_text: str) -> AnalyzeResponse:
    reasons: list[AnalysisReason] = []
    normalized_text = " ".join(message_text.split())
    links = analyze_links(message_text)

    suspicious_link_signals = {
        "embedded_credentials",
        "punycode_hostname",
        "ip_address_host",
    }
    for link in links:
        signals = suspicious_link_signals.intersection(link.signals)
        if signals:
            descriptions = {
                "embedded_credentials": "contains text before the actual host",
                "punycode_hostname": "uses an encoded internationalized hostname",
                "ip_address_host": "uses a numeric IP address instead of a domain name",
            }
            details = ", ".join(descriptions[signal] for signal in sorted(signals))
            reasons.append(
                AnalysisReason(
                    code="suspicious_link",
                    message=(
                        f"The link host '{link.host}' {details}. This can obscure a "
                        "destination, but does not by itself prove the link is malicious."
                    ),
                )
            )

    if any(pattern.search(normalized_text) for pattern in CREDENTIAL_REQUEST_PATTERNS):
        reasons.append(
            AnalysisReason(
                code="credential_request",
                message=(
                    "The message asks you to verify credentials or provide a password, PIN, "
                    "or security code."
                ),
            )
        )

    if any(pattern.search(normalized_text) for pattern in URGENCY_PATTERNS):
        reasons.append(
            AnalysisReason(
                code="urgent_threat",
                message="The message uses urgency or threatens an account or service restriction.",
            )
        )

    if any(pattern.search(normalized_text) for pattern in UNEXPECTED_REWARD_PATTERNS):
        reasons.append(
            AnalysisReason(
                code="unexpected_reward",
                message=(
                    "The message claims you were selected for a reward or bonus; "
                    "unexpected prize claims are a common scam lure."
                ),
            )
        )

    if any(pattern.search(normalized_text) for pattern in LIMITED_TIME_OFFER_PATTERNS):
        reasons.append(
            AnalysisReason(
                code="limited_time_offer",
                message=(
                    "The offer uses a short deadline to pressure a quick response."
                ),
            )
        )

    if (
        DELIVERY_CONTEXT_PATTERN.search(normalized_text)
        and DELIVERY_ADDRESS_ACTION_PATTERN.search(normalized_text)
        and URL_PATTERN.search(normalized_text)
    ):
        reasons.append(
            AnalysisReason(
                code="delivery_address_request",
                message=(
                    "The message asks you to update delivery details through a link, "
                    "a pattern commonly used in parcel scams."
                ),
            )
        )

    if SUSPICIOUS_SIGN_IN_PATTERN.search(normalized_text):
        reasons.append(
            AnalysisReason(
                code="suspicious_login_activity",
                message=(
                    "The message claims there were repeated sign-in attempts or activity "
                    "from an unfamiliar device; verify account activity independently."
                ),
            )
        )

    sensitive_information_terms = sum(
        pattern.search(normalized_text) is not None
        for pattern in SENSITIVE_INFORMATION_PATTERNS
    )
    if (
        sensitive_information_terms >= 2
        and SENSITIVE_INFORMATION_REQUEST_PATTERN.search(normalized_text)
    ):
        reasons.append(
            AnalysisReason(
                code="sensitive_information_request",
                message=(
                    "The message requests multiple sensitive banking or identity details, "
                    "which may expose the recipient to account misuse."
                ),
            )
        )

    has_account_urgency = any(
        reason.code == "urgent_threat" for reason in reasons
    )
    if (
        FINANCIAL_ACCOUNT_CONTEXT_PATTERN.search(normalized_text)
        and IDENTITY_VERIFICATION_REQUEST_PATTERN.search(normalized_text)
        and URL_PATTERN.search(normalized_text)
        and has_account_urgency
    ):
        reasons.append(
            AnalysisReason(
                code="identity_verification_request",
                message=(
                    "The message pressures you to verify an account or identity through a link "
                    "while threatening a financial-service restriction."
                ),
            )
        )

    if any(
        reason.code
        in {
            "credential_request",
            "sensitive_information_request",
            "identity_verification_request",
        }
        for reason in reasons
    ):
        risk_level = "high"
    elif reasons:
        risk_level = "medium"
    else:
        risk_level = "low"

    if any(reason.code == "delivery_address_request" for reason in reasons):
        suggestions = list(SUGGESTIONS_BY_REASON["delivery_address_request"])
    else:
        suggestions = list(
            dict.fromkeys(
                suggestion
                for reason in reasons
                for suggestion in SUGGESTIONS_BY_REASON[reason.code]
            )
        )
    if any("unencrypted_http" in link.signals for link in links):
        suggestions.append(
            "A link uses unencrypted HTTP. Do not enter passwords or payment details on it; "
            "navigate to the organization through its official app or website."
        )
    if not suggestions:
        suggestions = [
            "No specific warning signs were detected. Stay cautious with unexpected "
            "requests and verify them independently."
        ]

    return AnalyzeResponse(
        risk_level=risk_level,
        reasons=reasons,
        suggestions=suggestions,
        limitations=[
            "This MVP does not verify links or sender identity. It checks URL format only, does "
            "not check reputation or destination pages, and makes no external URL service calls."
        ],
        links=links,
    )
