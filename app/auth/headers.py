"""Proxy header construction for downstream otterwiki requests."""

from __future__ import annotations

from app.auth.permissions import format_permission_header


def build_proxy_headers(
    email: str,
    name: str,
    permissions: tuple[str, ...] | list[str],
) -> dict[str, str]:
    """Build the proxy headers dict for forwarding to otterwiki.

    Args:
        email: User's email address.
        name: User's display name.
        permissions: Sequence of permission strings (e.g., READ, WRITE).

    Returns:
        Dict with x-otterwiki-name, x-otterwiki-email, x-otterwiki-permissions.
    """
    return {
        "x-otterwiki-name": name,
        "x-otterwiki-email": email,
        "x-otterwiki-permissions": format_permission_header(permissions),
    }
