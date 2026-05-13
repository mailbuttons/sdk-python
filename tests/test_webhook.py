from __future__ import annotations

import hashlib
import hmac
import json

import pytest

from mailbuttons import (
    InboundMessageEvent,
    WebhookPayloadError,
    WebhookSignatureError,
    parse_webhook,
    verify_webhook,
)

SECRET = "shhh-this-is-a-test-secret"


def sign(body: str) -> str:
    digest = hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def test_verify_known_body_passes() -> None:
    body = json.dumps({"event": "email.received", "data": {"messageId": "m1"}})
    assert verify_webhook(body, sign(body), SECRET) is True


def test_verify_accepts_raw_hex_without_prefix() -> None:
    body = "x" * 10
    digest = hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
    assert verify_webhook(body, digest, SECRET) is True


def test_verify_rejects_tampered_body() -> None:
    body = "original"
    sig = sign(body)
    assert verify_webhook("modified", sig, SECRET) is False


def test_verify_rejects_tampered_signature() -> None:
    body = "original"
    good = sign(body)
    bad = good[:-1] + ("1" if good[-1] == "0" else "0")
    assert verify_webhook(body, bad, SECRET) is False


def test_verify_rejects_with_different_secret() -> None:
    body = "test"
    assert verify_webhook(body, sign(body), "different-secret") is False


def test_verify_works_on_bytes_input() -> None:
    body = "binary-input"
    assert verify_webhook(body.encode(), sign(body), SECRET) is True


def test_verify_raises_on_missing_signature() -> None:
    with pytest.raises(WebhookSignatureError):
        verify_webhook("body", None, SECRET)
    with pytest.raises(WebhookSignatureError):
        verify_webhook("body", "", SECRET)


def test_verify_raises_on_missing_secret() -> None:
    with pytest.raises(WebhookSignatureError):
        verify_webhook("body", sign("body"), "")


def test_verify_raises_on_malformed_signature() -> None:
    with pytest.raises(WebhookSignatureError):
        verify_webhook("body", "sha256=not-hex", SECRET)
    with pytest.raises(WebhookSignatureError):
        verify_webhook("body", "sha256=abcd", SECRET)


def test_parse_inbound_message_snake_case() -> None:
    body = json.dumps({
        "event": "email.received",
        "data": {
            "email_id": "msg-123",
            "thread_id": "thr-9",
            "sender_email": "alice@example.com",
            "recipient_email": "agent@my.app",
            "received_at": "2026-01-01T00:00:00Z",
            "subject": "Hi",
            "body_text": "hello",
            "verification": {"dkim": "pass", "spf": "pass", "dmarc": "pass", "from_alignment": True},
            "capabilities": ["read_calendar"],
        },
    })
    evt = parse_webhook(body)
    assert isinstance(evt, InboundMessageEvent)
    assert evt.type == "inbound_message"
    assert evt.data.message_id == "msg-123"
    assert evt.data.from_ == "alice@example.com"
    assert evt.data.to == "agent@my.app"
    assert evt.data.verification.dkim == "pass"
    assert evt.data.capabilities == ["read_calendar"]


def test_parse_accepts_camel_case_fallback() -> None:
    body = json.dumps({
        "event": "email.received",
        "data": {
            "messageId": "msg-9",
            "threadId": None,
            "from": "x@y.z",
            "to": "a@b.c",
            "receivedAt": "2026-01-01T00:00:00Z",
        },
    })
    evt = parse_webhook(body)
    assert isinstance(evt, InboundMessageEvent)
    assert evt.data.message_id == "msg-9"
    assert evt.data.thread_id is None
    assert evt.data.verification.dkim == "none"


def test_parse_rejects_invalid_json() -> None:
    with pytest.raises(WebhookPayloadError):
        parse_webhook("not json")


def test_parse_rejects_missing_event_field() -> None:
    with pytest.raises(WebhookPayloadError):
        parse_webhook(json.dumps({"data": {}}))


def test_parse_rejects_unknown_event_type() -> None:
    with pytest.raises(WebhookPayloadError):
        parse_webhook(json.dumps({"event": "weird.thing", "data": {}}))


def test_parse_rejects_missing_message_fields() -> None:
    body = json.dumps({"event": "email.received", "data": {"foo": "bar"}})
    with pytest.raises(WebhookPayloadError):
        parse_webhook(body)
