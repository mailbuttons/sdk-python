# mailbuttons

Official SDK for [mailbuttons](https://mailbuttons.com) — email for AI agents with policy enforcement.

> v0.1.x is pre-stable. Breaking changes will be flagged in the [CHANGELOG](./CHANGELOG.md).

## Install

```bash
pip install mailbuttons
# or
uv add mailbuttons
```

Requires Python 3.11 or later.

## Quick start

```python
import asyncio
import os

from aiohttp import web
from mailbuttons import (
    Mailbuttons,
    MailPolicy,
    parse_webhook,
    verify_webhook,
)

MAILBOX_ID = 42
SECRET = os.environ["MAILBUTTONS_WEBHOOK_SECRET"]
client = Mailbuttons(api_key=os.environ["MAILBUTTONS_API_KEY"])

policy = MailPolicy.model_validate({
    "defaultAction": "bounce",
    "senders": [{
        "match": {"domain": "your-company.com", "requireDkim": True},
        "capabilities": ["read_calendar", "propose_meeting"],
        "rateLimit": {"perHour": 30},
    }],
    "contentGuards": [{"reject": "(?i)wire transfer", "reason": "phishing"}],
    "auditLog": {"retentionDays": 30, "includeBodyHash": True},
})

async def main() -> None:
    await client.set_policy(MAILBOX_ID, policy)

async def webhook(request: web.Request) -> web.Response:
    raw = await request.read()
    sig = request.headers.get("X-Mailbuttons-Signature")
    if not verify_webhook(raw, sig, SECRET):
        return web.Response(status=401)
    event = parse_webhook(raw)
    if event.type == "inbound_message":
        await client.reply(MAILBOX_ID, event.data, "Got it — replying soon.")
    return web.Response(status=204)

app = web.Application()
app.router.add_post("/webhook", webhook)
asyncio.run(main())
```

## Policy schema

A `MailPolicy` declares which senders can talk to your mailbox, what they're allowed to do, and how the platform enforces it. See [mailbuttons.com/docs/policy](https://mailbuttons.com/docs/policy) for the full reference.

```python
from mailbuttons import (
    AuditConfig, ContentGuard, MailPolicy, RateLimit, SenderMatch, SenderRule,
)

policy = MailPolicy(
    default_action="bounce",
    senders=[
        SenderRule(
            match=SenderMatch(address="boss@acme.com"),
            capabilities=["read_calendar", "confirm_meeting"],
        ),
        SenderRule(
            match=SenderMatch(domain="acme.com", require_dkim=True),
            capabilities=["read_calendar"],
            rate_limit=RateLimit(per_hour=30),
        ),
    ],
    content_guards=[ContentGuard(reject=r"(?i)\bsecret\b", reason="data exfil")],
    audit_log=AuditConfig(retention_days=90, include_body_hash=True),
)
```

## Webhook handling

`verify_webhook` checks the HMAC-SHA-256 signature in `X-Mailbuttons-Signature` (format `sha256=<hex>`) against your shared secret. `parse_webhook` validates the JSON shape and returns a discriminated `WebhookEvent`.

```python
ok = verify_webhook(raw_body, headers.get("X-Mailbuttons-Signature"), secret)
if not ok:
    return reject()
event = parse_webhook(raw_body)
if event.type == "inbound_message":
    await handle(event.data)
```

The signature is computed over the raw body bytes; do not parse JSON before verifying.

## Errors

Every method raises one of:

- `AuthError` (401/403) — missing or revoked API key.
- `NotFoundError` (404) — mailbox or message not found.
- `ValidationError` (400/422) — request body rejected; `.field_errors` lists the failures.
- `RateLimitError` (429) — too many requests; `.retry_after_seconds` if the server hinted.
- `ServerError` (5xx) — backend or upstream failure.
- `NetworkError` — transport-level failure (DNS, TCP, timeout); `.__cause__` carries the original.
- `WebhookSignatureError` — `verify_webhook` got malformed input.
- `WebhookPayloadError` — `parse_webhook` got a body that didn't match the expected schema.

Every error has a stable `.code` string for programmatic dispatch (`"auth"`, `"rate_limited"`, etc.).

## Reference integration

A working agent built on top of this SDK lives at [`mailbuttons/claude-scheduling-agent-py`](https://github.com/mailbuttons/claude-scheduling-agent-py). Five end-to-end scenarios; same harness as the TypeScript version.

## Status & versioning

Pre-1.0. Breaking changes will be called out in [CHANGELOG.md](./CHANGELOG.md). Once the public surface settles, this package will move to 1.0 and adopt strict semver.

## Licence

MIT.
