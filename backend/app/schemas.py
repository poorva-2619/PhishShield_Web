from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictStr

MAX_MESSAGE_LENGTH = 10_000


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_version: Literal[1] = Field(alias="schemaVersion")
    platform: Literal["whatsapp_web", "telegram_web", "gmail_web", "outlook_web"]
    message_text: StrictStr = Field(
        alias="messageText",
        min_length=1,
        max_length=MAX_MESSAGE_LENGTH,
    )


class AnalysisReason(BaseModel):
    code: Literal[
        "credential_request",
        "urgent_threat",
        "unexpected_reward",
        "limited_time_offer",
        "sensitive_information_request",
        "identity_verification_request",
        "delivery_address_request",
        "suspicious_login_activity",
        "suspicious_link",
    ]
    message: str


class LinkAnalysis(BaseModel):
    host: str
    signals: list[
        Literal[
            "embedded_credentials",
            "punycode_hostname",
            "ip_address_host",
            "unencrypted_http",
        ]
    ]


class AnalyzeResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    risk_level: Literal["low", "medium", "high"] = Field(alias="riskLevel")
    reasons: list[AnalysisReason]
    suggestions: list[str]
    limitations: list[str]
    links: list[LinkAnalysis]
