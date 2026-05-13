"""Policy schema. Wire format is camelCase; aliases handle the conversion."""
from __future__ import annotations

from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field

KNOWN_CAPABILITIES: Final[tuple[str, ...]] = (
    "read_calendar",
    "propose_meeting",
    "confirm_meeting",
    "ingest_conflict_notice",
)

DefaultAction = Literal["bounce", "drop"]


def _to_camel(field: str) -> str:
    parts = field.split("_")
    return parts[0] + "".join(p.title() for p in parts[1:])


class _CamelModel(BaseModel):
    model_config = ConfigDict(
        alias_generator=_to_camel,
        populate_by_name=True,
        extra="ignore",
    )


class SenderMatch(_CamelModel):
    address: str | None = None
    domain: str | None = None
    require_dkim: bool = False
    require_spf: bool = False


class RateLimit(_CamelModel):
    per_hour: int | None = None
    per_day: int | None = None


class TokenBudget(_CamelModel):
    per_thread: int | None = None
    per_day: int | None = None


class SenderRule(_CamelModel):
    match: SenderMatch
    capabilities: list[str] = Field(default_factory=list[str])
    rate_limit: RateLimit | None = None
    token_budget: TokenBudget | None = None


class ContentGuard(_CamelModel):
    """Pattern source. ECMAScript syntax; inline ``(?i)`` flag honoured server-side."""

    reject: str
    reason: str


class AuditConfig(_CamelModel):
    retention_days: int
    include_body_hash: bool = False


class MailPolicy(_CamelModel):
    default_action: DefaultAction
    senders: list[SenderRule] = Field(default_factory=list[SenderRule])
    content_guards: list[ContentGuard] = Field(default_factory=list[ContentGuard])
    audit_log: AuditConfig


class PolicyResponse(_CamelModel):
    """Server response to PUT/GET policy."""

    model_config = ConfigDict(
        alias_generator=_to_camel,
        populate_by_name=True,
        extra="ignore",
        frozen=True,
    )

    mailbox_id: int
    version: int
    policy: MailPolicy
    warnings: list[str] = Field(default_factory=list[str])
