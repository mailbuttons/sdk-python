"""Official SDK for mailbuttons — email for AI agents with policy enforcement."""
from __future__ import annotations

from .audit import AuditEntry, AuditOutcome, AuditPage, CapabilitiesGranted
from .client import DEFAULT_BASE_URL, Mailbuttons, OutboundReceipt
from .errors import (
    AuthError,
    MailbuttonsError,
    MailbuttonsErrorCode,
    NetworkError,
    NotFoundError,
    RateLimitError,
    ServerError,
    ValidationError,
    WebhookPayloadError,
    WebhookSignatureError,
)
from .messages import Message, Verdict, Verification
from .policy import (
    KNOWN_CAPABILITIES,
    AuditConfig,
    ContentGuard,
    DefaultAction,
    MailPolicy,
    PolicyResponse,
    RateLimit,
    SenderMatch,
    SenderRule,
    TokenBudget,
)
from .webhook import InboundMessageEvent, WebhookEvent, parse_webhook, verify_webhook

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_BASE_URL",
    "KNOWN_CAPABILITIES",
    "AuditConfig",
    "AuditEntry",
    "AuditOutcome",
    "AuditPage",
    "AuthError",
    "CapabilitiesGranted",
    "ContentGuard",
    "DefaultAction",
    "InboundMessageEvent",
    "MailPolicy",
    "Mailbuttons",
    "MailbuttonsError",
    "MailbuttonsErrorCode",
    "Message",
    "NetworkError",
    "NotFoundError",
    "OutboundReceipt",
    "PolicyResponse",
    "RateLimit",
    "RateLimitError",
    "SenderMatch",
    "SenderRule",
    "ServerError",
    "TokenBudget",
    "ValidationError",
    "Verdict",
    "Verification",
    "WebhookEvent",
    "WebhookPayloadError",
    "WebhookSignatureError",
    "__version__",
    "parse_webhook",
    "verify_webhook",
]
