from fastapi.testclient import TestClient
import pytest

from backend.app.main import app

client = TestClient(app)


@pytest.mark.parametrize(
    "platform", ["whatsapp_web", "telegram_web", "gmail_web", "outlook_web"]
)
def test_supported_web_platforms_can_be_analyzed(platform: str) -> None:
    response = client.post(
        "/api/v1/analyze",
        json={
            "schemaVersion": 1,
            "platform": platform,
            "messageText": "Are we still meeting tomorrow?",
        },
    )

    assert response.status_code == 200
    assert response.json()["riskLevel"] == "low"


def test_unsupported_platform_is_rejected() -> None:
    response = client.post(
        "/api/v1/analyze",
        json={
            "schemaVersion": 1,
            "platform": "mobile_app",
            "messageText": "Are we still meeting tomorrow?",
        },
    )

    assert response.status_code == 422


def test_suspicious_url_shape_is_explained_without_echoing_path_or_query() -> None:
    response = client.post(
        "/api/v1/analyze",
        json={
            "schemaVersion": 1,
            "platform": "telegram_web",
            "messageText": (
                "Open https://example.com@192.0.2.1/sign-in?token=private to continue."
            ),
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["riskLevel"] == "medium"
    assert result["links"] == [
        {
            "host": "192.0.2.1",
            "signals": ["embedded_credentials", "ip_address_host"],
        }
    ]
    assert [reason["code"] for reason in result["reasons"]] == ["suspicious_link"]
    assert "192.0.2.1" in result["reasons"][0]["message"]
    assert "private" not in response.text
    assert "/sign-in" not in response.text


def test_http_link_is_shown_as_unencrypted_without_escalating_risk() -> None:
    response = client.post(
        "/api/v1/analyze",
        json={
            "schemaVersion": 1,
            "platform": "outlook_web",
            "messageText": "Read more at http://example.com/article.",
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["riskLevel"] == "low"
    assert result["links"] == [
        {"host": "example.com", "signals": ["unencrypted_http"]}
    ]
    assert any("unencrypted HTTP" in suggestion for suggestion in result["suggestions"])


def test_health_check() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_credential_request_is_high_risk_and_explained() -> None:
    response = client.post(
        "/api/v1/analyze",
        json={
            "schemaVersion": 1,
            "platform": "whatsapp_web",
            "messageText": "Your account will be blocked. Reply with your OTP to verify.",
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "riskLevel": "high",
        "reasons": [
            {
                "code": "credential_request",
                "message": (
                    "The message asks you to verify credentials or provide a password, PIN, "
                    "or security code."
                ),
            },
            {
                "code": "urgent_threat",
                "message": "The message uses urgency or threatens an account or service restriction.",
            },
        ],
        "suggestions": [
            "Do not share passwords, PINs, or one-time codes in response to a message. "
            "Contact the organization through its official app or a number you already trust.",
            "Pause before acting on the threat. Contact the organization through an official "
            "channel you find independently.",
        ],
        "limitations": [
            "This MVP does not verify links or sender identity. It checks URL format only, does "
            "not check reputation or destination pages, and makes no external URL service calls."
        ],
        "links": [],
    }


def test_urgent_message_without_credential_request_is_medium_risk() -> None:
    response = client.post(
        "/api/v1/analyze",
        json={
            "schemaVersion": 1,
            "platform": "whatsapp_web",
            "messageText": "Act now or your account will be suspended.",
        },
    )

    assert response.status_code == 200
    assert response.json()["riskLevel"] == "medium"
    assert [reason["code"] for reason in response.json()["reasons"]] == ["urgent_threat"]
    assert response.json()["suggestions"] == [
        "Pause before acting on the threat. Contact the organization through an official "
        "channel you find independently."
    ]


def test_unexpected_reward_with_deadline_is_flagged_and_explained() -> None:
    response = client.post(
        "/api/v1/analyze",
        json={
            "schemaVersion": 1,
            "platform": "whatsapp_web",
            "messageText": (
                "Dear Valued Customer, Congratulations! Your bank account has been selected "
                "for our exclusive VIP Customer Reward Programme. You are eligible to receive "
                "a special bonus of Rs 9,99,999! To proceed, please visit your nearest branch "
                "and claim your imaginary fortune. IMPORTANT: This offer expires in 24 hours. "
                "Failure to respond may result in excessive happiness being credited to your account."
            ),
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["riskLevel"] == "medium"
    assert any("deadline" in suggestion for suggestion in result["suggestions"])
    assert [reason["code"] for reason in result["reasons"]] == [
        "unexpected_reward",
        "limited_time_offer",
    ]
    assert "unexpected prize claims" in result["reasons"][0]["message"]
    assert "short deadline" in result["reasons"][1]["message"]


def test_claim_your_prize_message_is_flagged() -> None:
    response = client.post(
        "/api/v1/analyze",
        json={
            "schemaVersion": 1,
            "platform": "whatsapp_web",
            "messageText": "Claim your prize before the offer expires in 48 hours.",
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["riskLevel"] == "medium"
    assert [reason["code"] for reason in result["reasons"]] == [
        "unexpected_reward",
        "limited_time_offer",
    ]


def test_bank_kyc_message_requesting_multiple_details_is_high_risk() -> None:
    response = client.post(
        "/api/v1/analyze",
        json={
            "schemaVersion": 1,
            "platform": "whatsapp_web",
            "messageText": (
                "⚠️ *URGENT: Your Bank Account Will Be Blocked!*\n\n"
                "Dear Customer,\n\n"
                "We have detected unusual activity associated with your bank account. "
                "As a security precaution, your account access will be temporarily "
                "suspended within 24 hours.\n\n"
                "To prevent permanent account blockage, immediately verify your identity "
                "and update your KYC details using the link below:\n\n"
                "🔗 https://secure-bank-kyc-verification.example.com/update\n\n"
                "You are required to provide:\n"
                "- Account Number\n"
                "- Registered Mobile Number\n"
                "- Internet Banking User ID\n"
                "- OTP Verification Code\n\n"
                "Failure to complete verification within 24 hours may result in account "
                "suspension and restricted transactions.\n\n"
                "*IMPORTANT:* Do not ignore this notification. Your account security is at risk.\n\n"
                "Bank Security Department"
            ),
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["riskLevel"] == "high"
    assert any("banking or identity details" in suggestion for suggestion in result["suggestions"])
    assert [reason["code"] for reason in result["reasons"]] == [
        "urgent_threat",
        "sensitive_information_request",
        "identity_verification_request",
    ]
    assert "multiple sensitive banking or identity details" in result["reasons"][1]["message"]


def test_urgent_upi_identity_verification_link_is_high_risk() -> None:
    response = client.post(
        "/api/v1/analyze",
        json={
            "schemaVersion": 1,
            "platform": "whatsapp_web",
            "messageText": (
                "Dear Customer,\n\n"
                "Your UPI account has been temporarily restricted due to suspicious "
                "transactions. Verify your identity immediately to restore payment services.\n\n"
                "Verification: https://upi-account-verify.example.com\n\n"
                "Failure to verify within 2 hours may result in permanent suspension."
            ),
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["riskLevel"] == "high"
    assert any("official" in suggestion for suggestion in result["suggestions"])
    assert [reason["code"] for reason in result["reasons"]] == [
        "urgent_threat",
        "identity_verification_request",
    ]
    assert "pressures you to verify" in result["reasons"][1]["message"]
    assert "does not verify links" in result["limitations"][0]


def test_message_without_detected_indicators_is_low_risk() -> None:
    response = client.post(
        "/api/v1/analyze",
        json={
            "schemaVersion": 1,
            "platform": "whatsapp_web",
            "messageText": "Are we still meeting for lunch tomorrow?",
        },
    )

    assert response.status_code == 200
    assert response.json()["riskLevel"] == "low"
    assert response.json()["reasons"] == []
    assert response.json()["suggestions"]


def test_delivery_address_message_has_delivery_specific_suggestion() -> None:
    response = client.post(
        "/api/v1/analyze",
        json={
            "schemaVersion": 1,
            "platform": "whatsapp_web",
            "messageText": (
                "Your package is currently on hold because your delivery address is incomplete.\n\n"
                "Update your address within 12 hours to avoid returning the parcel.\n\n"
                "Update here: https://parcel-track-update.example.com/confirm\n\n"
                "Thank you,\nDelivery Support Team"
            ),
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["riskLevel"] == "medium"
    assert "delivery_address_request" in [reason["code"] for reason in result["reasons"]]
    assert result["suggestions"] == [
        "Don’t use the message link to update your address; check directly with the delivery "
        "company through its official site or app, using tracking details you already have."
    ]


def test_security_alert_asking_for_credentials_and_code_is_high_risk() -> None:
    response = client.post(
        "/api/v1/analyze",
        json={
            "schemaVersion": 1,
            "platform": "whatsapp_web",
            "messageText": (
                "Microsoft Security Alert:\n\n"
                "We detected multiple unsuccessful login attempts on your account from an "
                "unknown device.\n\n"
                "Your account may be compromised.\n\n"
                "For immediate protection, verify your credentials and security code here:\n"
                "https://microsoft-security-check.example.com\n\n"
                "Microsoft Security Team"
            ),
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["riskLevel"] == "high"
    assert [reason["code"] for reason in result["reasons"]] == [
        "credential_request",
        "urgent_threat",
        "suspicious_login_activity",
    ]
    assert any("Do not use the message link to sign in" in suggestion
               for suggestion in result["suggestions"])
    assert "does not verify links" in result["limitations"][0]


def test_invalid_schema_returns_sanitized_validation_error() -> None:
    message = "private content that must not be echoed"
    response = client.post(
        "/api/v1/analyze",
        json={
            "schemaVersion": 1,
            "platform": "whatsapp_web",
            "messageText": message,
            "unexpected": "field",
        },
    )

    assert response.status_code == 422
    assert message not in response.text


def test_oversized_request_is_rejected() -> None:
    response = client.post(
        "/api/v1/analyze",
        content=b" " * 16_385,
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 413


def test_successful_response_does_not_echo_message_text() -> None:
    message = "private content that must not be echoed"
    response = client.post(
        "/api/v1/analyze",
        json={
            "schemaVersion": 1,
            "platform": "whatsapp_web",
            "messageText": message,
        },
    )

    assert message not in response.text
