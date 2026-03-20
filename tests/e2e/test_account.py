"""E2E tests for the account page and account deletion flow."""

import re

import pytest


def test_account_page_renders(authenticated_page, platform_server, test_account):
    """Account page displays user info from JWT claims."""
    page = authenticated_page
    page.goto(f"{platform_server}/app/account")

    # Verify page loaded
    page.wait_for_selector("text=Account", timeout=5000)

    # Verify handle is displayed (use a specific cell to avoid strict mode error)
    handle_cell = page.locator("table td").filter(has_text=test_account["handle"]).first
    assert handle_cell.is_visible(timeout=5000)

    # DID should be in a <code> element
    did_prefix = test_account["did"][:20]
    did_element = page.locator(f"code").filter(has_text=did_prefix).first
    assert did_element.is_visible(timeout=5000)


def test_account_deletion_wrong_confirmation(authenticated_page, platform_server):
    """Account deletion fails with wrong handle confirmation."""
    page = authenticated_page
    page.goto(f"{platform_server}/app/account")

    # Expand the danger zone <details>
    page.locator("details summary").first.click()

    # Fill WRONG handle
    page.fill("input[name='confirm_handle']", "wrong-handle")

    # Submit
    page.locator("details button[type='submit']").click()

    # Should stay on account page with error flash
    page.wait_for_url(re.compile(r"/app/account"), timeout=5000)
    page.wait_for_load_state("networkidle")

    # Flash message is in page source (rendered via halfmoon script tag)
    content = page.content()
    assert "did not match" in content or "Confirmation" in content, \
        f"Error flash not found in page source"


def test_mcp_consent_page_renders(authenticated_page, platform_server, wiki_fixture):
    """MCP OAuth consent page displays client info, wiki name, and action buttons."""
    page = authenticated_page
    consent_url = (
        f"{platform_server}/auth/oauth/consent"
        f"?client_id=http://example.com/client"
        f"&redirect_uri=http://example.com/callback"
        f"&state=test-state"
        f"&scope=atproto"
        f"&wiki_slug={wiki_fixture['slug']}"
    )
    page.goto(consent_url)

    # Verify consent page rendered
    page.wait_for_selector("text=requesting access", timeout=5000)

    # Verify approve/deny buttons
    assert (
        page.locator("button:has-text('Approve'), input[value*='Approve']")
        .first.is_visible(timeout=3000)
    )
    assert (
        page.locator("button:has-text('Deny'), input[value*='Deny']")
        .first.is_visible(timeout=3000)
    )


def test_mcp_consent_deny_redirects(authenticated_page, platform_server, wiki_fixture):
    """Denying MCP consent redirects with error=access_denied parameter."""
    page = authenticated_page
    consent_url = (f"{platform_server}/auth/oauth/consent"
                   f"?client_id=http://127.0.0.1/client"
                   f"&redirect_uri=http://127.0.0.1/callback"
                   f"&state=test-state&scope=atproto"
                   f"&wiki_slug={wiki_fixture['slug']}")
    page.goto(consent_url)
    page.wait_for_selector("text=requesting access", timeout=5000)

    deny_btn = page.locator("button[value='deny'], button:has-text('Deny'), input[value*='Deny']").first
    assert deny_btn.is_visible(timeout=3000), "Deny button not visible on consent page"
    deny_btn.click()
    page.wait_for_load_state("networkidle")

    # Server redirects to redirect_uri with error=access_denied
    assert "access_denied" in page.url or "error" in page.url, \
        f"Expected access_denied in redirect URL, got: {page.url}"


def test_account_deletion(destructive_page, platform_server, test_account):
    """Account deletion with correct handle confirmation clears the session.

    This test uses a separate dedicated account to avoid invalidating the
    shared test_account used by other tests.
    """
    import requests

    # Create a dedicated account for this destructive test
    pds_url = None
    # Derive PDS URL from test_account DID prefix — look at env
    import os
    pds_url = os.environ.get("PLC_DIRECTORY_URL", "")
    if not pds_url:
        pytest.skip("Cannot determine PDS URL for dedicated account creation")

    disposable_handle = "e2e-delete-me.test"
    disposable_password = "delete-me-password-456"

    create_resp = requests.post(
        f"{pds_url}/xrpc/com.atproto.server.createAccount",
        json={
            "handle": disposable_handle,
            "email": "deleteme@test.com",
            "password": disposable_password,
        },
    )
    if create_resp.status_code not in (200, 201):
        # May already exist from a prior run — try createSession
        session_resp = requests.post(
            f"{pds_url}/xrpc/com.atproto.server.createSession",
            json={"identifier": disposable_handle, "password": disposable_password},
        )
        if session_resp.status_code != 200:
            pytest.skip("Could not create or re-use disposable test account")

    # Get the DID for the disposable account so we can log in via DID
    # (handle resolution via DNS/HTTP would fail for mock accounts)
    disposable_data = create_resp.json() if create_resp.status_code in (200, 201) else None
    if disposable_data is None:
        # Account already existed; fetch DID via createSession
        session_resp2 = requests.post(
            f"{pds_url}/xrpc/com.atproto.server.createSession",
            json={"identifier": disposable_handle, "password": disposable_password},
        )
        if session_resp2.status_code != 200:
            pytest.skip("Could not get DID for disposable account")
        disposable_data = session_resp2.json()
    disposable_did = disposable_data["did"]

    # Now log in as the disposable account using the destructive_page context
    page = destructive_page
    import re as _re

    # Navigate to login using DID (not handle) to avoid DNS resolution failure
    page.goto(f"{platform_server}/auth/logout")
    page.goto(f"{platform_server}/auth/login")
    page.fill("#username", disposable_did)
    page.click("#username ~ input[type='submit']")

    page.wait_for_url(_re.compile(r"127\.0\.0\.1.*oauth/authorize"), timeout=15000)
    page.locator("input[name='identifier']").fill(disposable_handle)
    page.locator("input[type='password']").fill(disposable_password)
    page.locator("button[type='submit'][value='approve']").click()
    page.wait_for_url(_re.compile(r"127\.0\.0\.1"), timeout=15000)

    # Now delete the account
    page.goto(f"{platform_server}/app/account")
    page.locator("details summary").first.click()
    page.fill("input[name='confirm_handle']", disposable_handle)
    page.locator("details button[type='submit']").click()

    # Should redirect away
    page.wait_for_url(_re.compile(r"127\.0\.0\.1"), timeout=10000)

    # Verify the platform_token cookie has been cleared
    cookies = page.context.cookies()
    platform_cookies = [
        c for c in cookies if c["name"] == "platform_token" and c.get("value")
    ]
    assert not platform_cookies, "platform_token should be cleared after account deletion"
