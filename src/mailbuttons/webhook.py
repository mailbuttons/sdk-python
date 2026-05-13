"""Webhook signature verification and payload parsing."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Annotated, Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field
from pydantic import ValidationError as PydanticValidationError

from .errors import WebhookPayloadError, WebhookSignatureError
from .messages import Message

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def verify_webhook(raw_body: bytes | str, signature_header: str | None, secret: str) -> bool:
    """Verify the HMAC-SHA-256 signature of a raw webhook body.

    Returns True on match, False on mismatch. Raises ``WebhookSignatureError``
    when the input is malformed (missing header, missing secret, non-hex
    signature). Constant-time comparison via :func:`hmac.compare_digest`.
    """
    if not signature_header:
        raise WebhookSignatureError("Missing signature header")
    if not secret:
        raise WebhookSignatureError("Missing webhook secret")

    sig = signature_header[len("sha256=") :] if signature_header.startswith("sha256=") else signature_header
    if not _HEX_RE.match(sig) or len(sig) != 64:
        raise WebhookSignatureError("Malformed signature")

    body = raw_body if isinstance(raw_body, bytes) else raw_body.encode("utf-8")
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig.lower())


class InboundMessageEvent(BaseModel):
    """The platform's outbound webhook delivery for ``email.received``."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    type: Literal["inbound_message"] = "inbound_message"
    data: Message


WebhookEvent = Annotated[InboundMessageEvent, Field(discriminator="type")]


def parse_webhook(raw_body: bytes | str) -> WebhookEvent:
    """Parse a raw webhook body into a typed :class:`WebhookEvent`.

    Validates the top-level shape and the discriminator. Raises
    ``WebhookPayloadError`` on schema mismatch.

    The platform wraps deliveries as ``{"event": "<name>", "data": {...}}``.
    The ``event`` string maps to the union's ``type`` discriminator.
    """
    text = raw_body.decode("utf-8") if isinstance(raw_body, bytes) else raw_body
    try:
        raw: object = json.loads(text)
    except json.JSONDecodeError as exc:
        raise WebhookPayloadError(f"Body is not valid JSON: {exc}") from exc

    if not isinstance(raw, dict):
        raise WebhookPayloadError("Body is not a JSON object")
    parsed = cast(dict[str, Any], raw)

    event = parsed.get("event")
    data = parsed.get("data")
    if not isinstance(event, str):
        raise WebhookPayloadError("Missing or non-string `event` field")
    if not isinstance(data, dict):
        raise WebhookPayloadError("Missing or non-object `data` field")
    data_dict = cast(dict[str, Any], data)

    if event == "email.received":
        normalised = _normalise_inbound_message(data_dict)
        try:
            return InboundMessageEvent(type="inbound_message", data=Message.model_validate(normalised))
        except PydanticValidationError as exc:
            raise WebhookPayloadError(f"inbound_message payload invalid: {exc}") from exc

    raise WebhookPayloadError(f"Unknown webhook event type: {event}")


def _normalise_inbound_message(data: dict[str, Any]) -> dict[str, Any]:
    """Map the backend's snake_case wire shape onto the :class:`Message` field aliases."""

    out: dict[str, Any] = {}
    out["message_id"] = data.get("email_id") or data.get("messageId") or data.get("message_id")
    out["thread_id"] = data.get("thread_id") or data.get("threadId")
    out["from"] = data.get("sender_email") or data.get("from")
    out["to"] = data.get("recipient_email") or data.get("to")
    out["received_at"] = data.get("received_at") or data.get("receivedAt")
    if "subject" in data:
        out["subject"] = data["subject"]
    if "body_text" in data or "bodyText" in data:
        out["body_text"] = data.get("body_text") or data.get("bodyText")
    verification = data.get("verification")
    if isinstance(verification, dict):
        v = cast(dict[str, Any], verification)
        out["verification"] = {
            "dkim": v.get("dkim", "none"),
            "spf": v.get("spf", "none"),
            "dmarc": v.get("dmarc", "none"),
            "from_alignment": v.get("from_alignment") if "from_alignment" in v else v.get("fromAlignment"),
        }
    else:
        out["verification"] = {"dkim": "none", "spf": "none", "dmarc": "none", "from_alignment": None}
    if "capabilities" in data:
        out["capabilities"] = data["capabilities"]
    return out
