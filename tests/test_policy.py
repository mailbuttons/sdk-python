from __future__ import annotations

from mailbuttons import (
    KNOWN_CAPABILITIES,
    AuditConfig,
    ContentGuard,
    MailPolicy,
    RateLimit,
    SenderMatch,
    SenderRule,
    TokenBudget,
)


def test_policy_round_trips_through_wire_json() -> None:
    policy = MailPolicy(
        default_action="drop",
        senders=[
            SenderRule(
                match=SenderMatch(address="boss@acme.com", require_dkim=True, require_spf=True),
                capabilities=["read_calendar", "propose_meeting"],
                rate_limit=RateLimit(per_hour=10, per_day=100),
                token_budget=TokenBudget(per_thread=1000, per_day=50_000),
            ),
            SenderRule(
                match=SenderMatch(domain="acme.com"),
                capabilities=["read_calendar"],
            ),
        ],
        content_guards=[ContentGuard(reject="(?i)wire transfer", reason="phishing")],
        audit_log=AuditConfig(retention_days=30, include_body_hash=True),
    )

    wire = policy.model_dump(mode="json", by_alias=True, exclude_none=True)

    # Wire format uses camelCase
    assert wire["defaultAction"] == "drop"
    assert wire["senders"][0]["match"]["requireDkim"] is True
    assert wire["senders"][0]["rateLimit"]["perHour"] == 10
    assert wire["auditLog"]["retentionDays"] == 30

    # Round-trip
    parsed = MailPolicy.model_validate(wire)
    assert parsed.default_action == "drop"
    assert parsed.senders[0].match.address == "boss@acme.com"
    assert parsed.senders[0].rate_limit is not None
    assert parsed.senders[0].rate_limit.per_hour == 10
    assert parsed.audit_log.include_body_hash is True


def test_known_capabilities_constant() -> None:
    assert "read_calendar" in KNOWN_CAPABILITIES
    assert "propose_meeting" in KNOWN_CAPABILITIES
    assert "confirm_meeting" in KNOWN_CAPABILITIES
    assert "ingest_conflict_notice" in KNOWN_CAPABILITIES


def test_policy_rejects_invalid_default_action() -> None:
    import pydantic

    raw = {
        "defaultAction": "bogus",
        "senders": [],
        "auditLog": {"retentionDays": 30, "includeBodyHash": False},
    }
    try:
        MailPolicy.model_validate(raw)
    except pydantic.ValidationError:
        return
    raise AssertionError("expected pydantic ValidationError")
