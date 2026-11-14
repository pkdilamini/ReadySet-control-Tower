"""A basic security layer for the page: only this computer, and only a browser that was given the session token.

Two checks, in order:
  1. Host: the request must name localhost or 127.0.0.1. A malicious website that tries DNS rebinding
     (pointing its own name at 127.0.0.1) sends its own name here, so it is refused.
  2. Token: every POST, and every /api/ call except the health check, must carry the token that the server
     printed when it started. Another page or program on this computer cannot guess it.
"""
import hmac
import secrets
from urllib.parse import urlsplit

ALLOWED_HOSTS = {"localhost", "127.0.0.1"}
TOKEN_HEADER = "X-Control-Token"


def new_token():
    """24 random bytes, URL-safe. A new one every time the server starts."""
    return secrets.token_urlsafe(24)


def guard(handler, token):
    """True if the request may continue. Otherwise a refusal has already been sent."""
    # "localhost:8010" -> "localhost"; "[::1]:8010" -> "::1" (not allowed).
    host = (handler.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
    if host not in ALLOWED_HOSTS:
        handler._json(403, {"detail": "this page only answers to this computer"})
        return False
    path = urlsplit(handler.path).path
    needs_token = handler.command == "POST" or (path.startswith("/api/") and path != "/api/health")
    if needs_token:
        given = handler.headers.get(TOKEN_HEADER) or ""
        # compare_digest takes the same time whatever the guess, so the token cannot be worked out bit by bit.
        if not hmac.compare_digest(given.encode(), token.encode()):
            handler._json(401, {"detail": "this needs the session token the page was opened with"})
            return False
    return True
