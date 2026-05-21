"""Audit-log entry shape and query parameters."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .messages import Verdict

AuditOutcome = Literal[
    "delivered",
    "rejected_at_verification",
    "rejected_at_policy",
    "rejected_at_content_guard",
    "rate_limited",
    "budget_exhausted",
]


class CapabilitiesGranted(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")

    capabilities: list[str] = Field(default_factory=list[str])
    rule_index: int


class AuditEntry(BaseModel):
    """A single audit-log row as returned by ``Mailbuttons.get_audit_log``."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    id: int
    message_id: str
    thread_id: str | None = None
    sender_address: str | None = None
    recipient_address: str | None = None
    received_at: str
    """ISO-8601 UTC timestamp."""
    outcome: AuditOutcome
    reason: str | None = None
    verification_dkim: Verdict | None = None
    verification_spf: Verdict | None = None
    verification_dmarc: Verdict | None = None
    from_alignment: bool | None = None
    body_hash: str | None = None
    capabilities_granted: CapabilitiesGranted | None = None
    tools_used: object | None = None
    tokens_consumed: object | None = None
    reply_sent: object | None = None


class AuditPage(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")

    items: list[AuditEntry]
    next_cursor: int | None = None
