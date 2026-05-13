"""Async-first client for the mailbuttons HTTP API."""
from __future__ import annotations

from typing import Any, cast

import httpx
from pydantic import BaseModel, ConfigDict

from .audit import AuditEntry, AuditOutcome, AuditPage
from .errors import (
    AuthError,
    MailbuttonsError,
    NetworkError,
    NotFoundError,
    RateLimitError,
    ServerError,
    ValidationError,
)
from .messages import Message
from .policy import MailPolicy, PolicyResponse

DEFAULT_BASE_URL = "https://mailbuttons.com/api"


class OutboundReceipt(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")

    success: bool


class Mailbuttons:
    """Async client for the mailbuttons HTTP API.

    Construct once, await methods many times. Internally holds a long-lived
    :class:`httpx.AsyncClient`; call :meth:`aclose` on shutdown or use as an
    async context manager.
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 30.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not api_key:
            raise MailbuttonsError("api_key is required")
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._owns_client = client is None
        self._http = client or httpx.AsyncClient(timeout=timeout)

    async def __aenter__(self) -> Mailbuttons:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_client:
            await self._http.aclose()

    async def set_policy(self, mailbox_id: int, policy: MailPolicy) -> PolicyResponse:
        """PUT a :class:`MailPolicy` for the given mailbox."""
        wire = policy.model_dump(mode="json", by_alias=True, exclude_none=True)
        raw = await self._request("PUT", f"/v1/mailboxes/{mailbox_id}/policy", json=wire)
        return PolicyResponse.model_validate(raw)

    async def get_policy(self, mailbox_id: int) -> PolicyResponse | None:
        """Returns the current policy or ``None`` if none is set."""
        try:
            raw = await self._request("GET", f"/v1/mailboxes/{mailbox_id}/policy")
        except NotFoundError:
            return None
        return PolicyResponse.model_validate(raw)

    async def reply(self, mailbox_id: int, message: Message, body: str) -> OutboundReceipt:
        """Send a threaded reply to a previously-received message."""
        raw = await self._request(
            "POST",
            f"/v1/mailboxes/{mailbox_id}/messages/{message.message_id}/reply",
            json={"text_body": body},
        )
        return OutboundReceipt.model_validate(raw)

    async def bounce(self, mailbox_id: int, message: Message, reason: str) -> OutboundReceipt:
        """Send a notification-style bounce to the original sender.

        The ``reason`` is used verbatim as the explanation paragraph.
        """
        raw = await self._request(
            "POST",
            f"/v1/mailboxes/{mailbox_id}/messages/{message.message_id}/bounce",
            json={"reason": reason},
        )
        return OutboundReceipt.model_validate(raw)

    async def get_audit_log(
        self,
        mailbox_id: int,
        *,
        message_id: str | None = None,
        thread_id: str | None = None,
        outcome: AuditOutcome | None = None,
        limit: int | None = None,
        cursor: int | None = None,
    ) -> AuditPage:
        """Query the audit log. Pagination is cursor-based."""
        params: dict[str, str] = {}
        if message_id is not None:
            params["message_id"] = message_id
        if thread_id is not None:
            params["thread_id"] = thread_id
        if outcome is not None:
            params["outcome"] = outcome
        if limit is not None:
            params["limit"] = str(limit)
        if cursor is not None:
            params["cursor"] = str(cursor)
        raw = await self._request("GET", f"/v1/mailboxes/{mailbox_id}/audit-logs", params=params)
        if not isinstance(raw, dict):
            raise ServerError("Audit response was not an object", status=200)
        raw_dict = cast(dict[str, Any], raw)
        items_raw = raw_dict.get("items")
        if not isinstance(items_raw, list):
            raise ServerError("Audit response missing `items`", status=200)
        items = [AuditEntry.model_validate(item) for item in cast(list[Any], items_raw)]
        cursor_raw = raw_dict.get("next_cursor")
        next_cursor = cursor_raw if isinstance(cursor_raw, int) else None
        return AuditPage(items=items, next_cursor=next_cursor)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: object | None = None,
        params: dict[str, str] | None = None,
    ) -> Any:
        url = f"{self._base_url}{path}"
        try:
            response = await self._http.request(
                method,
                url,
                json=json,
                params=params,
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Accept": "application/json",
                },
            )
        except httpx.HTTPError as exc:
            raise NetworkError(f"Request to {method} {path} failed", exc) from exc

        if response.is_success:
            text = response.text
            if not text:
                return None
            try:
                return response.json()
            except ValueError as exc:
                raise ServerError(
                    f"Response from {method} {path} was not valid JSON: {exc}",
                    status=response.status_code,
                    response_body=text,
                ) from exc

        raise _map_http_error(response, method, path)


def _map_http_error(response: httpx.Response, method: str, path: str) -> MailbuttonsError:
    status = response.status_code
    body = response.text
    summary = f"{method} {path} -> {status}"

    if status in (401, 403):
        return AuthError(f"{summary}: {_extract_message(body) or 'auth failed'}", status=status, response_body=body)
    if status == 404:
        return NotFoundError(f"{summary}: {_extract_message(body) or 'not found'}", status=404, response_body=body)
    if status in (400, 422):
        return ValidationError(
            f"{summary}: {_extract_message(body) or 'validation failed'}",
            _extract_field_errors(body),
            response_body=body,
        )
    if status == 429:
        retry_after_raw = response.headers.get("retry-after")
        try:
            retry_after = int(retry_after_raw) if retry_after_raw else None
        except (TypeError, ValueError):
            retry_after = None
        return RateLimitError(f"{summary}: rate limited", retry_after, response_body=body)
    if status >= 500:
        return ServerError(f"{summary}: {_extract_message(body) or 'server error'}", status=status, response_body=body)
    return MailbuttonsError(f"{summary}: unexpected status", status=status, response_body=body)


def _extract_message(body: str) -> str | None:
    if not body:
        return None
    try:
        import json as _json

        parsed: object = _json.loads(body)
    except ValueError:
        return None
    if isinstance(parsed, dict):
        parsed_dict = cast(dict[str, Any], parsed)
        err = parsed_dict.get("error")
        if isinstance(err, str):
            return err
    return None


def _extract_field_errors(body: str) -> list[str]:
    if not body:
        return []
    try:
        import json as _json

        parsed: object = _json.loads(body)
    except ValueError:
        return []
    if isinstance(parsed, dict):
        parsed_dict = cast(dict[str, Any], parsed)
        errs = parsed_dict.get("errors")
        if isinstance(errs, list):
            errs_list = cast(list[Any], errs)
            string_errs = [e for e in errs_list if isinstance(e, str)]
            if len(string_errs) == len(errs_list):
                return string_errs
    return []
