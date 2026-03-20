"""E2E tests for wiki lifecycle: create, settings update, token regen, delete."""

import re

import pytest


def test_wiki_creation_form(authenticated_page, platform_server):
    """Create a wiki via the management UI form."""
    import uuid
    slug = f"e2e-{uuid.uuid4().hex[:8]}"
    page = authenticated_page

    page.goto(f"{platform_server}/app/create")
    page.fill("input[name='slug']", slug)
    page.fill("input[name='display_name']", "E2E Created Wiki")

    page.click("button[type='submit']")

    # Should redirect to wiki settings page
    page.wait_for_url(re.compile(rf"/app/wiki/{slug}"), timeout=10000)

    # MCP token shown on first creation (session flash) inside .token-display
    assert page.locator(".token-display").is_visible(timeout=5000)


def test_wiki_settings_update(authenticated_page, platform_server, wiki_fixture):
    """Update wiki display name via settings form."""
    page = authenticated_page
    page.goto(f"{platform_server}/app/wiki/{wiki_fixture['slug']}")

    display_name_input = page.locator("input[name='display_name']").first
    display_name_input.fill("Updated Wiki Name")

    # Save button is in the display name form (not the MCP regenerate form)
    display_name_input.press("Enter")

    page.wait_for_url(
        re.compile(rf"/app/wiki/{re.escape(wiki_fixture['slug'])}"), timeout=10000
    )

    # Flash messages are rendered via halfmoon.initStickyAlert() in a <script> tag.
    # Verify the page source contains the flash text (even if the sticky alert
    # element hasn't been inserted yet, the script tag will have the text).
    page.wait_for_load_state("networkidle")
    content = page.content()
    assert "Settings updated" in content, \
        f"Flash message 'Settings updated' not found in page source"

    # Reload and verify persistence
    page.reload()
    updated_value = page.locator("input[name='display_name']").first.input_value()
    assert updated_value == "Updated Wiki Name"


def test_wiki_deletion_with_confirmation(destructive_page, platform_server, wiki_fixture):
    """Delete a wiki via the danger zone confirmation flow."""
    page = destructive_page
    slug = wiki_fixture["slug"]
    page.goto(f"{platform_server}/app/wiki/{slug}")

    # Expand the danger zone <details>
    page.locator("details.collapse-panel summary").click()

    confirm_input = page.locator("input[name='confirm_slug']")
    confirm_input.wait_for(state="visible", timeout=5000)
    confirm_input.fill(slug)

    page.locator("details button[type='submit']").click()

    # Should redirect to dashboard
    page.wait_for_url(re.compile(r"/app/"), timeout=10000)
    page.wait_for_load_state("networkidle")

    # Verify flash message in page source
    content = page.content()
    assert "deleted" in content, f"Flash 'deleted' not found in page source"


def test_mcp_token_regeneration(authenticated_page, platform_server, wiki_fixture):
    """Regenerate MCP token via settings page."""
    page = authenticated_page
    page.goto(f"{platform_server}/app/wiki/{wiki_fixture['slug']}")

    # Accept the JavaScript confirm() dialog
    page.on("dialog", lambda dialog: dialog.accept())

    # Regenerate button is in the MCP card
    page.locator(".card button[type='submit']").filter(
        has_text=re.compile(r"[Rr]egenerate")
    ).click()

    page.wait_for_url(
        re.compile(rf"/app/wiki/{re.escape(wiki_fixture['slug'])}"), timeout=10000
    )
    page.wait_for_load_state("networkidle")

    # Flash message is in the page source (rendered via halfmoon script tag)
    content = page.content()
    assert "regenerated" in content.lower(), \
        f"Flash 'regenerated' not found in page source"

    # New token displayed in .token-display
    assert page.locator(".token-display").is_visible(timeout=5000)
