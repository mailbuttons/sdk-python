"""Typed error hierarchy. No leaking ``httpx`` exceptions to consumers."""
from __future__ import annotations

from typing import Literal

MailbuttonsErrorCode = Literal[
    "auth",
    "not_found",
    "validation",
    "rate_limited",
    "server",
    "network",
    "webhook_signature",
    "webhook_payload",
]


class MailbuttonsError(Exception):
    """Base class for every error this SDK raises."""

    code: MailbuttonsErrorCode = "server"

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        response_body: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.response_body = response_body


class AuthError(MailbuttonsError):
    code: MailbuttonsErrorCode = "auth"


class NotFoundError(MailbuttonsError):
    code: MailbuttonsErrorCode = "not_found"


class ValidationError(MailbuttonsError):
    code: MailbuttonsErrorCode = "validation"

    def __init__(
        self,
        message: str,
        field_errors: list[str],
        *,
        response_body: str | None = None,
    ) -> None:
        super().__init__(message, status=400, response_body=response_body)
        self.field_errors = field_errors


class RateLimitError(MailbuttonsError):
    code: MailbuttonsErrorCode = "rate_limited"

    def __init__(
        self,
        message: str,
        retry_after_seconds: int | None,
        *,
        response_body: str | None = None,
    ) -> None:
        super().__init__(message, status=429, response_body=response_body)
        self.retry_after_seconds = retry_after_seconds


class ServerError(MailbuttonsError):
    code: MailbuttonsErrorCode = "server"


class NetworkError(MailbuttonsError):
    code: MailbuttonsErrorCode = "network"

    def __init__(self, message: str, cause: BaseException) -> None:
        super().__init__(message)
        self.__cause__ = cause


class WebhookSignatureError(MailbuttonsError):
    code: MailbuttonsErrorCode = "webhook_signature"


class WebhookPayloadError(MailbuttonsError):
    code: MailbuttonsErrorCode = "webhook_payload"
