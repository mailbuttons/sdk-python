"""Inbound message and verification result types."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Verdict = Literal["pass", "fail", "softfail", "neutral", "temperror", "permerror", "none"]


class Verification(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")

    dkim: Verdict = "none"
    spf: Verdict = "none"
    dmarc: Verdict = "none"
    from_alignment: bool | None = Field(default=None, alias="from_alignment")


class Message(BaseModel):
    """A verified, policy-evaluated inbound message ready for the agent."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    message_id: str
    thread_id: str | None = None
    from_: str = Field(alias="from")
    to: str
    subject: str | None = None
    body_text: str | None = None
    received_at: str
    verification: Verification
    capabilities: list[str] = Field(default_factory=list)
