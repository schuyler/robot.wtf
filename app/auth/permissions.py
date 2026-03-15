"""Role-to-permission mapping for robot.wtf ACL system."""

from __future__ import annotations

# Permission constants
READ = "READ"
WRITE = "WRITE"
UPLOAD = "UPLOAD"
ADMIN = "ADMIN"

# Role -> permissions mapping
ROLE_PERMISSIONS: dict[str, tuple[str, ...]] = {
    "owner": (READ, WRITE, UPLOAD, ADMIN),
    "editor": (READ, WRITE, UPLOAD),
    "viewer": (READ,),
}


def permissions_for_role(role: str) -> tuple[str, ...]:
    """Return the permissions tuple for a given role.

    Raises:
        ValueError: If the role is not recognized.
    """
    perms = ROLE_PERMISSIONS.get(role)
    if perms is None:
        raise ValueError(f"Unknown role: {role}")
    return perms


def format_permission_header(permissions: tuple[str, ...] | list[str]) -> str:
    """Format permissions as a comma-separated header value string."""
    return ",".join(permissions)
