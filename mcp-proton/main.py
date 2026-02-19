"""MCP Proton service – ProtonMail (via proton-bridge) + Calendar stubs."""

import email
import imaplib
import os
import smtplib
from email.header import decode_header
from email.mime.text import MIMEText
from email.utils import formataddr

from jose import JWTError, jwt
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
JWT_SECRET = os.environ["JWT_SECRET"]
IMAP_HOST = os.environ.get("IMAP_HOST", "proton-bridge")
IMAP_PORT = int(os.environ.get("IMAP_PORT", "1143"))
SMTP_HOST = os.environ.get("SMTP_HOST", "proton-bridge")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "1025"))
PROTON_EMAIL = os.environ["PROTON_EMAIL"]
PROTON_BRIDGE_PASSWORD = os.environ["PROTON_BRIDGE_PASSWORD"]

CALENDAR_STUB_MSG = (
    "Calendar access via the unofficial API is not yet implemented. "
    "Use the Proton web app for calendar operations."
)

# ---------------------------------------------------------------------------
# FastMCP server
# ---------------------------------------------------------------------------
# DNS rebinding protection is disabled: this service runs behind Traefik (trusted network)
_security = TransportSecuritySettings(allowed_hosts=["localhost"])
mcp = FastMCP("proton-mail", stateless_http=True, transport_security=_security)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _decode_header_value(value: str) -> str:
    """Decode an RFC-2047 encoded header value."""
    if value is None:
        return ""
    parts = decode_header(value)
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            decoded.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            decoded.append(part)
    return "".join(decoded)


def _imap_connect() -> imaplib.IMAP4:
    """Open and authenticate an IMAP connection to proton-bridge."""
    conn = imaplib.IMAP4(IMAP_HOST, IMAP_PORT)
    conn.login(PROTON_EMAIL, PROTON_BRIDGE_PASSWORD)
    return conn


def _extract_text(msg: email.message.Message) -> str:
    """Extract plain-text body from a MIME message."""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == "text/plain":
                payload = part.get_payload(decode=True)
                charset = part.get_content_charset() or "utf-8"
                return payload.decode(charset, errors="replace")
        # Fallback to text/html if no plain text
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == "text/html":
                payload = part.get_payload(decode=True)
                charset = part.get_content_charset() or "utf-8"
                return payload.decode(charset, errors="replace")
        return ""
    payload = msg.get_payload(decode=True)
    if payload is None:
        return ""
    charset = msg.get_content_charset() or "utf-8"
    return payload.decode(charset, errors="replace")


# ---------------------------------------------------------------------------
# Email tools
# ---------------------------------------------------------------------------

@mcp.tool()
def list_emails(folder: str = "INBOX", limit: int = 20, unread_only: bool = False) -> list[dict]:
    """List email summaries from a mailbox folder.

    Args:
        folder: IMAP folder name (default INBOX).
        limit: Maximum number of emails to return.
        unread_only: If True, only return unread emails.
    """
    conn = _imap_connect()
    try:
        conn.select(folder, readonly=True)
        criteria = "UNSEEN" if unread_only else "ALL"
        _status, data = conn.search(None, criteria)
        msg_nums = data[0].split()
        if not msg_nums:
            return []

        # Take the most recent `limit` messages
        msg_nums = msg_nums[-limit:]
        results = []
        for num in reversed(msg_nums):
            _status, msg_data = conn.fetch(num, "(FLAGS BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE MESSAGE-ID)])")
            raw = msg_data[0][1]
            flags_raw = msg_data[0][0]
            msg = email.message_from_bytes(raw)
            is_read = b"\\Seen" in flags_raw
            results.append({
                "from": _decode_header_value(msg.get("From", "")),
                "subject": _decode_header_value(msg.get("Subject", "")),
                "date": msg.get("Date", ""),
                "message_id": msg.get("Message-ID", ""),
                "read": is_read,
            })
        return results
    finally:
        conn.logout()


@mcp.tool()
def read_email(message_id: str) -> dict:
    """Fetch and return the full body of an email by its Message-ID header.

    Args:
        message_id: The Message-ID header value of the email.
    """
    conn = _imap_connect()
    try:
        conn.select("INBOX", readonly=True)
        _status, data = conn.search(None, f'HEADER Message-ID "{message_id}"')
        nums = data[0].split()
        if not nums:
            return {"error": f"No email found with Message-ID: {message_id}"}

        _status, msg_data = conn.fetch(nums[0], "(RFC822)")
        raw = msg_data[0][1]
        msg = email.message_from_bytes(raw)
        return {
            "from": _decode_header_value(msg.get("From", "")),
            "to": _decode_header_value(msg.get("To", "")),
            "subject": _decode_header_value(msg.get("Subject", "")),
            "date": msg.get("Date", ""),
            "message_id": msg.get("Message-ID", ""),
            "body": _extract_text(msg),
        }
    finally:
        conn.logout()


@mcp.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email via proton-bridge SMTP relay.

    Args:
        to: Recipient email address.
        subject: Email subject.
        body: Plain-text email body.
    """
    msg = MIMEText(body, "plain", "utf-8")
    msg["From"] = formataddr(("", PROTON_EMAIL))
    msg["To"] = to
    msg["Subject"] = subject

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
        smtp.login(PROTON_EMAIL, PROTON_BRIDGE_PASSWORD)
        smtp.send_message(msg)

    return f"Email sent to {to}."


@mcp.tool()
def search_emails(
    query: str,
    from_addr: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> list[dict]:
    """Search emails using IMAP SEARCH criteria.

    Args:
        query: Text to search for in the email body/subject.
        from_addr: Filter by sender address.
        date_from: Filter emails on or after this date (DD-Mon-YYYY, e.g. 01-Jan-2025).
        date_to: Filter emails on or before this date (DD-Mon-YYYY).
    """
    conn = _imap_connect()
    try:
        conn.select("INBOX", readonly=True)
        criteria_parts: list[str] = []
        if query:
            criteria_parts.append(f'TEXT "{query}"')
        if from_addr:
            criteria_parts.append(f'FROM "{from_addr}"')
        if date_from:
            criteria_parts.append(f'SINCE {date_from}')
        if date_to:
            criteria_parts.append(f'BEFORE {date_to}')

        criteria = " ".join(criteria_parts) if criteria_parts else "ALL"
        _status, data = conn.search(None, criteria)
        nums = data[0].split()
        if not nums:
            return []

        results = []
        for num in nums[-50:]:  # cap at 50 results
            _status, msg_data = conn.fetch(num, "(FLAGS BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE MESSAGE-ID)])")
            raw = msg_data[0][1]
            flags_raw = msg_data[0][0]
            msg = email.message_from_bytes(raw)
            is_read = b"\\Seen" in flags_raw
            results.append({
                "from": _decode_header_value(msg.get("From", "")),
                "subject": _decode_header_value(msg.get("Subject", "")),
                "date": msg.get("Date", ""),
                "message_id": msg.get("Message-ID", ""),
                "read": is_read,
            })
        return results
    finally:
        conn.logout()


# ---------------------------------------------------------------------------
# Calendar tools (stubs)
# ---------------------------------------------------------------------------

@mcp.tool()
def list_calendar_events(start_date: str, end_date: str) -> str:
    """List calendar events in a date range.

    Args:
        start_date: Start date (ISO 8601).
        end_date: End date (ISO 8601).
    """
    return CALENDAR_STUB_MSG


@mcp.tool()
def create_calendar_event(
    title: str,
    start: str,
    end: str,
    description: str | None = None,
    location: str | None = None,
) -> str:
    """Create a calendar event.

    Args:
        title: Event title.
        start: Start datetime (ISO 8601).
        end: End datetime (ISO 8601).
        description: Optional event description.
        location: Optional event location.
    """
    return CALENDAR_STUB_MSG


@mcp.tool()
def delete_calendar_event(event_id: str) -> str:
    """Delete a calendar event by ID.

    Args:
        event_id: The calendar event identifier.
    """
    return CALENDAR_STUB_MSG


# ---------------------------------------------------------------------------
# JWT auth middleware (raw ASGI — safe for SSE streaming)
# ---------------------------------------------------------------------------

class JWTAuthMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            response = Response(status_code=401)
            await response(scope, receive, send)
            return

        token = auth_header[7:]
        try:
            jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except JWTError:
            response = Response(status_code=401)
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


# ---------------------------------------------------------------------------
# ASGI app
# ---------------------------------------------------------------------------

_inner = mcp.streamable_http_app()
app = JWTAuthMiddleware(_inner)
