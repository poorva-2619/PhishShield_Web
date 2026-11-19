import ipaddress
import re
from urllib.parse import urlsplit

from backend.app.schemas import LinkAnalysis

URL_CANDIDATE_PATTERN = re.compile(
    r"(?:https?://|www\.)[^\s<>\"']+",
    re.IGNORECASE,
)
TRAILING_URL_PUNCTUATION = ".,!?;:)]}"


def analyze_links(message_text: str) -> list[LinkAnalysis]:
    findings: list[LinkAnalysis] = []
    seen_urls: set[str] = set()

    for match in URL_CANDIDATE_PATTERN.finditer(message_text):
        candidate = match.group(0).rstrip(TRAILING_URL_PUNCTUATION)
        if not candidate:
            continue
        url = candidate if "://" in candidate else f"https://{candidate}"
        if url.casefold() in seen_urls:
            continue
        seen_urls.add(url.casefold())

        try:
            parsed = urlsplit(url)
            host = parsed.hostname
        except ValueError:
            continue
        if parsed.scheme not in {"http", "https"} or not host:
            continue

        signals: list[str] = []
        if parsed.username is not None or parsed.password is not None:
            signals.append("embedded_credentials")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            try:
                ascii_host = host.encode("idna").decode("ascii")
            except UnicodeError:
                ascii_host = host
            if any(label.startswith("xn--") for label in ascii_host.lower().split(".")):
                signals.append("punycode_hostname")
        else:
            signals.append("ip_address_host")

        if parsed.scheme == "http":
            signals.append("unencrypted_http")

        findings.append(LinkAnalysis(host=host, signals=signals))

    return findings
