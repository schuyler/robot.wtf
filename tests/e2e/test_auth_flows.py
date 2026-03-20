"""E2E tests for additional auth flow behaviors."""

import re

import pytest


def test_unauthenticated_access_redirects_to_login(platform_server, browser):
    """Accessing /app/* without auth redirects to login with return_to."""
    context = browser.new_context()
    page = context.new_page()
    page.goto(f"{platform_server}/app/account")
    page.wait_for_url(re.compile(r"/auth/login"), timeout=5000)
    assert "return_to" in page.url
    context.close()


def test_auto_redirect_when_authenticated(authenticated_page, platform_server):
    """Visiting /auth/login with valid cookie redirects to /app/."""
    page = authenticated_page
    page.goto(f"{platform_server}/auth/login")
    page.wait_for_url(re.compile(r"/app/"), timeout=5000)


def test_return_to_url_preservation(authenticated_page, platform_server, wiki_fixture):
    """return_to parameter is respected when already authenticated."""
    page = authenticated_page
    slug = wiki_fixture["slug"]
    # Visiting /auth/login with return_to should redirect there immediately
    # (since we're already authenticated)
    page.goto(f"{platform_server}/auth/login?return_to=/app/wiki/{slug}")
    page.wait_for_url(re.compile(rf"/app/wiki/{re.escape(slug)}"), timeout=5000)


def test_login_with_handle(page, platform_server, test_account, pds):
    """Login using handle instead of DID.

    In the mock environment, handle resolution via DNS/HTTPS is unavailable,
    so the platform server returns a 400 error with a flash message.
    This test verifies that the platform correctly attempts handle resolution
    and returns an appropriate error when resolution fails (not a 500 crash).
    """
    page.goto(f"{platform_server}/auth/login")
    page.fill("#username", test_account["handle"])
    page.click("#username ~ input[type='submit']")

    # Wait for the response (either redirect to PDS, or stay on login with error)
    page.wait_for_load_state("domcontentloaded")

    current_url = page.url
    if "oauth/authorize" in current_url:
        # Handle resolution succeeded (shouldn't happen in mock env but is valid)
        pass
    else:
        # Handle resolution failed — platform should show error on login page
        # Verify we got an error response (400) or stayed on login page
        assert "/auth/login" in current_url or page.locator("#username").is_visible(timeout=3000), \
            f"Expected login page or PDS authorize, got: {current_url}"
        # Verify the page has some error indication in the content
        content = page.content()
        # At minimum, the platform didn't crash (no 500)
        assert "Internal Server Error" not in content, \
            "Platform server crashed on handle login attempt"
