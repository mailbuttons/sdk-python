from __future__ import annotations

import httpx
import pytest
import respx

from mailbuttons import (
    AuditPage,
    AuthError,
    Mailbuttons,
    MailPolicy,
    Message,
    NotFoundError,
    RateLimitError,
    ServerError,
    ValidationError,
    Verification,
)

SAMPLE_POLICY = MailPolicy.model_validate({
    "defaultAction": "bounce",
    "senders": [
        {
            "match": {"domain": "example.com", "requireDkim": True},
            "capabilities": ["read_calendar"],
        }
    ],
    "contentGuards": [{"reject": "(?i)leak", "reason": "data exfil"}],
    "auditLog": {"retentionDays": 30, "includeBodyHash": True},
})

SAMPLE_MESSAGE = Message.model_validate({
    "message_id": "m-abc",
    "thread_id": "t-1",
    "from": "alice@example.com",
    "to": "bot@my.app",
    "received_at": "2026-01-01T00:00:00Z",
    "subject": "Hi",
    "body_text": "hello",
    "verification": {"dkim": "pass", "spf": "pass", "dmarc": "pass", "from_alignment": True},
    "capabilities": ["read_calendar"],
})


@respx.mock
async def test_set_policy_puts_and_returns_wrapped_response() -> None:
    route = respx.put("https://example.test/api/v1/mailboxes/42/policy").respond(
        200,
        json={
            "mailboxId": 42,
            "version": 7,
            "policy": SAMPLE_POLICY.model_dump(mode="json", by_alias=True),
            "warnings": [],
        },
    )
    async with Mailbuttons(api_key="k", base_url="https://example.test/api") as client:
        result = await client.set_policy(42, SAMPLE_POLICY)
    assert result.version == 7
    assert result.mailbox_id == 42
    sent = route.calls.last.request
    assert sent.headers["authorization"] == "Bearer k"
    assert b'"defaultAction":"bounce"' in sent.content


@respx.mock
async def test_set_policy_validation_error() -> None:
    respx.put("https://mailbuttons.com/api/v1/mailboxes/1/policy").respond(
        400, json={"errors": ["auditLog.retentionDays must be >= 1"]}
    )
    async with Mailbuttons(api_key="k") as client:
        with pytest.raises(ValidationError) as exc_info:
            await client.set_policy(1, SAMPLE_POLICY)
    err = exc_info.value
    assert err.field_errors == ["auditLog.retentionDays must be >= 1"]
    assert err.code == "validation"


@respx.mock
async def test_get_policy_returns_value() -> None:
    respx.get("https://mailbuttons.com/api/v1/mailboxes/5/policy").respond(
        200,
        json={
            "mailboxId": 5,
            "version": 1,
            "policy": SAMPLE_POLICY.model_dump(mode="json", by_alias=True),
            "warnings": ["unknown_capability:foo"],
        },
    )
    async with Mailbuttons(api_key="k") as client:
        result = await client.get_policy(5)
    assert result is not None
    assert result.warnings == ["unknown_capability:foo"]


@respx.mock
async def test_get_policy_returns_none_on_404() -> None:
    respx.get("https://mailbuttons.com/api/v1/mailboxes/99/policy").respond(404, text="Policy not found")
    async with Mailbuttons(api_key="k") as client:
        assert await client.get_policy(99) is None


@respx.mock
async def test_get_policy_raises_auth_on_401() -> None:
    respx.get("https://mailbuttons.com/api/v1/mailboxes/1/policy").respond(
        401, json={"error": "Invalid API key"}
    )
    async with Mailbuttons(api_key="bad") as client:
        with pytest.raises(AuthError):
            await client.get_policy(1)


@respx.mock
async def test_reply_posts_text_body() -> None:
    route = respx.post(
        "https://mailbuttons.com/api/v1/mailboxes/42/messages/m-abc/reply"
    ).respond(200, json={"success": True})
    async with Mailbuttons(api_key="k") as client:
        result = await client.reply(42, SAMPLE_MESSAGE, "Confirmed.")
    assert result.success is True
    assert b'"text_body":"Confirmed."' in route.calls.last.request.content


@respx.mock
async def test_reply_propagates_not_found() -> None:
    respx.post("https://mailbuttons.com/api/v1/mailboxes/1/messages/m-abc/reply").respond(
        404, text="Mailbox not found"
    )
    async with Mailbuttons(api_key="k") as client:
        with pytest.raises(NotFoundError):
            await client.reply(1, SAMPLE_MESSAGE, "hi")


@respx.mock
async def test_bounce_posts_reason() -> None:
    route = respx.post(
        "https://mailbuttons.com/api/v1/mailboxes/7/messages/m-abc/bounce"
    ).respond(200, json={"success": True})
    async with Mailbuttons(api_key="k") as client:
        result = await client.bounce(7, SAMPLE_MESSAGE, "Out of office until Monday.")
    assert result.success is True
    assert b'"reason":"Out of office until Monday."' in route.calls.last.request.content


@respx.mock
async def test_bounce_surfaces_server_error() -> None:
    respx.post("https://mailbuttons.com/api/v1/mailboxes/1/messages/m-abc/bounce").respond(
        502, text="upstream timeout"
    )
    async with Mailbuttons(api_key="k") as client:
        with pytest.raises(ServerError):
            await client.bounce(1, SAMPLE_MESSAGE, "no")


@respx.mock
async def test_get_audit_log_encodes_filters_and_parses_response() -> None:
    route = respx.get("https://mailbuttons.com/api/v1/mailboxes/7/audit-logs").respond(
        200,
        json={
            "items": [
                {
                    "id": 100,
                    "message_id": "m1",
                    "thread_id": "t1",
                    "sender_address": "alice@example.com",
                    "recipient_address": "bot@mailbox.com",
                    "received_at": 1700000000,
                    "outcome": "delivered",
                    "reason": None,
                    "verification_dkim": "pass",
                    "verification_spf": "pass",
                    "verification_dmarc": "pass",
                    "from_alignment": True,
                    "body_hash": "abc123",
                    "capabilities_granted": {"capabilities": ["read_calendar"], "rule_index": 0},
                    "tools_used": None,
                    "tokens_consumed": None,
                    "reply_sent": None,
                }
            ],
            "next_cursor": 99,
        },
    )
    async with Mailbuttons(api_key="k") as client:
        page = await client.get_audit_log(7, outcome="delivered", limit=25)
    assert isinstance(page, AuditPage)
    assert page.next_cursor == 99
    assert len(page.items) == 1
    entry = page.items[0]
    assert entry.outcome == "delivered"
    assert entry.capabilities_granted is not None
    assert entry.capabilities_granted.capabilities == ["read_calendar"]
    assert "outcome=delivered" in str(route.calls.last.request.url)
    assert "limit=25" in str(route.calls.last.request.url)


@respx.mock
async def test_get_audit_log_rate_limit() -> None:
    respx.get("https://mailbuttons.com/api/v1/mailboxes/1/audit-logs").respond(
        429, json={"error": "Too many requests"}, headers={"Retry-After": "12"}
    )
    async with Mailbuttons(api_key="k") as client:
        with pytest.raises(RateLimitError) as exc_info:
            await client.get_audit_log(1)
    assert exc_info.value.retry_after_seconds == 12


@respx.mock
async def test_network_error_wraps_transport_failure() -> None:
    respx.get("https://mailbuttons.com/api/v1/mailboxes/1/policy").mock(
        side_effect=httpx.ConnectError("dns lookup failed")
    )
    from mailbuttons import NetworkError

    async with Mailbuttons(api_key="k") as client:
        with pytest.raises(NetworkError):
            await client.get_policy(1)


def test_constructor_rejects_empty_api_key() -> None:
    from mailbuttons import MailbuttonsError

    with pytest.raises(MailbuttonsError):
        Mailbuttons(api_key="")


def test_message_round_trip_preserves_aliases() -> None:
    """Verification of the Message model that the from alias survives parsing."""
    msg = Message.model_validate({
        "message_id": "x",
        "from": "a@b.c",
        "to": "x@y.z",
        "received_at": "2026",
        "verification": Verification().model_dump(),
    })
    assert msg.from_ == "a@b.c"
    assert msg.message_id == "x"
