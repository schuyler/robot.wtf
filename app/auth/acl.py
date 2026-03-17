"""ACL enforcement layer for robot.wtf.

Determines whether a user or bearer token can access a wiki
and with which permissions.
"""

from __future__ import annotations

import logging
from typing import Any

from app.auth.middleware import AuthError
from app.auth.permissions import READ, permissions_for_role
from app.models.acl import AclModel
from app.models.wiki import WikiModel

logger = logging.getLogger(__name__)


class AclEnforcer:
    """Checks access permissions against the ACL and Wiki tables."""

    def __init__(self, *, acl_model: AclModel, wiki_model: WikiModel):
        self._acls = acl_model
        self._wikis = wiki_model

    def check_access(
        self, user_did: str, wiki_slug: str
    ) -> dict[str, Any]:
        """Check whether a user has access to a wiki via ACL or owner_did.

        Checks in order:
        1. ACL table entry (grantee_did match)
        2. owner_did on the wiki itself (implicit owner role)

        Args:
            user_did: The user's DID (grantee_did in acls table).
            wiki_slug: The wiki slug (PK in wikis table).

        Returns:
            Dict with 'role' and 'permissions' keys.

        Raises:
            AuthError: If no ACL entry or owner_did grants the user access.
        """
        acl = self._acls.get(wiki_slug, user_did)
        if acl:
            role = acl["role"]
            permissions = permissions_for_role(role)
            return {"role": role, "permissions": permissions}

        # Fall back to implicit owner access via owner_did
        wiki = self._wikis.get(wiki_slug)
        if wiki and wiki.get("owner_did") == user_did:
            permissions = permissions_for_role("owner")
            return {"role": "owner", "permissions": permissions}

        raise AuthError("Access denied", status=403)

    def check_public_access(self, wiki_slug: str) -> dict[str, Any]:
        """Grant anonymous READ access if the wiki exists.

        The is_public flag is intentionally ignored. Per-wiki READ_ACCESS
        preference (in wiki.db) is the sole gating mechanism for anonymous
        access; see _apply_wiki_access_restrictions() in the resolver.

        Args:
            wiki_slug: The wiki slug.

        Returns:
            Dict with 'role' set to 'public' and 'permissions' containing READ.

        Raises:
            AuthError: If the wiki is not found.
        """
        wiki = self._wikis.get(wiki_slug)
        if not wiki:
            raise AuthError("Wiki not found", status=404)

        return {"role": "public", "permissions": (READ,)}

    def check_bearer_token(
        self, token: str
    ) -> dict[str, Any]:
        """Validate a bearer token against stored bcrypt hashes.

        Args:
            token: The plaintext bearer token.

        Returns:
            Dict with 'wiki', 'role' set to 'token', and editor permissions.

        Raises:
            AuthError: If no wiki matches the token.
        """
        wiki = self._wikis.scan_by_token(token)
        if not wiki:
            raise AuthError("Invalid bearer token", status=401)

        return {
            "wiki": wiki,
            "role": "token",
            "permissions": permissions_for_role("editor"),
        }
