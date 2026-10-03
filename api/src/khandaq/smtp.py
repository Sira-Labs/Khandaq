"""SMTP delivery for email alerts (spec 022).

The relay is deployment configuration (`KHANDAQ_SMTP_URL`), never user input. Every send runs
under a hard deadline, so a relay that accepts the connection and then stalls cannot hold the
worker and the runs queued behind it. smtplib's timeout only bounds each socket operation.
"""

from __future__ import annotations

import smtplib
import ssl
import threading
import urllib.parse
from dataclasses import dataclass
from email.message import EmailMessage

DEADLINE_SECONDS = 10.0
_DEFAULT_PORTS = {"smtps": 465, "smtp+starttls": 587, "smtp": 25}
TLS_SCHEMES = ("smtps", "smtp+starttls")


@dataclass(frozen=True)
class SmtpTarget:
    scheme: str  # smtps | smtp+starttls | smtp
    host: str
    port: int
    username: str | None


def parse_smtp_url(url: str) -> SmtpTarget:
    """``smtps://[user@]host[:port]``, ``smtp+starttls://…`` or ``smtp://…``; ValueError otherwise.
    A password in the URL is refused: it belongs in ``KHANDAQ_SMTP_PASSWORD``."""
    parts = urllib.parse.urlsplit(url.strip())
    if parts.scheme not in _DEFAULT_PORTS or not parts.hostname:
        raise ValueError(
            "KHANDAQ_SMTP_URL must be smtps://, smtp+starttls:// or smtp:// with a host"
        )
    if parts.password is not None:
        raise ValueError("KHANDAQ_SMTP_URL must not contain a password; use KHANDAQ_SMTP_PASSWORD")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ValueError("KHANDAQ_SMTP_URL takes no path, query or fragment")
    try:
        port = parts.port or _DEFAULT_PORTS[parts.scheme]
    except ValueError as exc:  # a non-numeric or out-of-range port
        raise ValueError(f"KHANDAQ_SMTP_URL has an invalid port: {exc}") from None
    username = urllib.parse.unquote(parts.username) if parts.username else None
    return SmtpTarget(scheme=parts.scheme, host=parts.hostname, port=port, username=username)


class SmtpSender:
    """Sends one message per call through the configured relay, within ``deadline_seconds``.

    On a deadline the attempt is reported as ``TimeoutError`` and the worker moves on; the abandoned
    daemon thread ends at its next socket timeout. The relay may still have accepted the message,
    so delivery is at-least-once (spec 022 §5)."""

    def __init__(
        self, target: SmtpTarget, password: str, deadline_seconds: float = DEADLINE_SECONDS
    ) -> None:
        self.target = target
        self.password = password
        self.deadline_seconds = deadline_seconds

    def send(self, message: EmailMessage) -> None:
        outcome: list[BaseException] = []

        def deliver() -> None:
            try:
                self._send(message)
            except BaseException as exc:  # handed to the caller's thread, which re-raises it
                outcome.append(exc)

        thread = threading.Thread(target=deliver, name="khandaq-smtp", daemon=True)
        thread.start()
        thread.join(self.deadline_seconds)
        if thread.is_alive():
            raise TimeoutError(f"SMTP delivery exceeded {self.deadline_seconds:.0f}s")
        if outcome:
            raise outcome[0]

    def _send(self, message: EmailMessage) -> None:
        t = self.target
        context = ssl.create_default_context()
        client: smtplib.SMTP
        if t.scheme == "smtps":
            client = smtplib.SMTP_SSL(
                t.host, t.port, timeout=self.deadline_seconds, context=context
            )
        else:
            client = smtplib.SMTP(t.host, t.port, timeout=self.deadline_seconds)
        with client:
            if t.scheme == "smtp+starttls":
                client.starttls(context=context)
            if t.username:
                client.login(t.username, self.password)
            client.send_message(message)
