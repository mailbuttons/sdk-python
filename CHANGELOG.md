# Changelog

All notable changes to this package will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-04-28

### Added
- `Mailbuttons` async client with `set_policy`, `get_policy`, `reply`, `bounce`, and `get_audit_log`.
- `verify_webhook` (HMAC-SHA-256, constant-time) and `parse_webhook` (discriminated union via pydantic).
- Typed error hierarchy: `AuthError`, `NotFoundError`, `ValidationError`, `RateLimitError`, `ServerError`, `NetworkError`, `WebhookSignatureError`, `WebhookPayloadError`.
- Pydantic v2 models for every wire type, with `frozen=True` on responses.
- `py.typed` marker for downstream type-checkers.

### Notes
- Pre-stable. The public surface may change in future 0.x releases; breaking changes will be flagged here.
