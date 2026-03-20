"""E2E tests for the OAuth login flow."""

import re

import pytest


def test_login_page_loads(page, platform_server):
    """Login page renders with the username input."""
    page.goto(f"{platform_server}/auth/login")
    page.wait_for_selector("#username")
    assert page.locator("#username").is_visible()


def test_client_metadata_served(platform_server):
    """Client metadata endpoint returns valid ATProto OAuth metadata."""
    import requests
    resp = requests.get(f"{platform_server}/auth/client-metadata.json")
    assert resp.status_code == 200
    meta = resp.json()
    assert "client_id" in meta
    assert "redirect_uris" in meta
    assert meta["token_endpoint_auth_method"] == "private_key_jwt"


def test_oauth_login(page, platform_server, test_account, pds):
    """Full OAuth login flow through mock PDS."""
    page.goto(f"{platform_server}/auth/login")

    # Enter the test account's DID (not handle, to avoid DNS resolution)
    page.fill("#username", test_account["did"])
    page.click("#username ~ input[type='submit']")

    # Should redirect to PDS authorization page
    page.wait_for_url(re.compile(r"127\.0\.0\.1.*oauth/authorize"), timeout=15000)

    # Fill mock PDS login form
    page.locator("input[name='identifier']").fill(test_account["handle"])
    page.locator("input[type='password']").fill(test_account["password"])
    page.locator("button[type='submit'][value='approve']").click()

    # Wait for redirect back to platform
    page.wait_for_url(re.compile(r"127\.0\.0\.1"), timeout=15000)

    # Check that we got a platform_token cookie
    cookies = page.context.cookies()
    cookie_names = [c["name"] for c in cookies]
    assert "platform_token" in cookie_names, f"Expected platform_token cookie, got: {cookie_names}"


def test_logout(authenticated_page, platform_server):
    """Logout clears the platform_token cookie."""
    page = authenticated_page

    # Verify we have the token cookie
    cookies = page.context.cookies()
    assert any(c["name"] == "platform_token" for c in cookies), \
        "Expected platform_token cookie before logout"

    page.goto(f"{platform_server}/auth/logout")

    cookies = page.context.cookies()
    platform_cookies = [c for c in cookies if c["name"] == "platform_token" and c.get("value")]
    assert not platform_cookies, "platform_token cookie should be cleared after logout"
