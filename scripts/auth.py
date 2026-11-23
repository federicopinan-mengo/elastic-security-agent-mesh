#!/usr/bin/env python3
"""Authentication for the Elastic endpoints this repo talks to.

Two modes are supported for every target:

- an API key (`ES_API_KEY`, `KIBANA_API_KEY`);
- a user and a password (`ES_USERNAME`/`ES_PASSWORD`,
  `KIBANA_USERNAME`/`KIBANA_PASSWORD`).

The API key wins when both are configured. A user and password attribute every
call to a named identity in the audit trail, which is why operators who already
manage native users prefer it; see `docs/security/least-privilege.md`.
"""

import base64
import os


def basic_auth(username, password):
    """Return the value of an HTTP Basic authorization header."""
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {token}"


def auth_header(api_key_var, user_var, password_var):
    """Return the Authorization header value for one target.

    Raises RuntimeError when neither an API key nor a complete user/password
    pair is configured, so a half-configured target fails loudly.
    """
    api_key = os.environ.get(api_key_var, "").strip()
    if api_key:
        return f"ApiKey {api_key}"
    username = os.environ.get(user_var, "").strip()
    password = os.environ.get(password_var, "")
    if username and password:
        return basic_auth(username, password)
    raise RuntimeError(f"Set {api_key_var}, or {user_var} and {password_var}")


def auth_mode(api_key_var, user_var, password_var):
    """Return "api key", "user/password" or "not configured" for one target."""
    if os.environ.get(api_key_var, "").strip():
        return "api key"
    if os.environ.get(user_var, "").strip() and os.environ.get(password_var, ""):
        return "user/password"
    return "not configured"
