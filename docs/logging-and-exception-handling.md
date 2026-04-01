# Logging and Exception Handling

## Issue 1: Application logging doesn't reach journald

Python's `logging.getLogger(__name__)` creates loggers with no handlers. Gunicorn configures its own loggers (`gunicorn.error`, `gunicorn.access`) but never touches the root logger or application loggers. The result: `logger.exception(...)` calls silently go nowhere, while `print(..., file=sys.stderr)` works fine.

### Fix

Add `logging.basicConfig()` in the WSGI entrypoint (`app/wsgi.py`), at module level, before the app is constructed:

```python
import logging
import sys

logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(levelname)s %(name)s: %(message)s",
)
```

Standard library only. All application loggers propagate to root by default, so everything flows to stderr → journald via the systemd unit's `StandardError=journal`.

Alternative approaches (`logconfig_dict`, attaching to gunicorn's error handler, `systemd.journal.JournalHandler`) are unnecessary. `basicConfig` is sufficient.

Note: `preload_app = True` does not affect this — gunicorn never configures application loggers regardless of preload setting.

---

## Issue 2: Silent exception swallowing

An `except BaseException: pass` in `_get_per_wiki_user()` hid a critical production bug — the function was always throwing `RuntimeError: Working outside of application context.` but the exception was silently swallowed, making per-wiki user lookups completely non-functional. Every non-owner authenticated user was treated as having no per-wiki permissions.

### Audit results

9 silent exception handlers found in the codebase. Status by priority:

**Fix — no logging at all:**

| Location | Pattern | Action |
|---|---|---|
| `app/resolver.py:300` | `except Exception: pass` in `_swap_database()` error recovery during engine disposal | Add `logger.debug()` |
| `app/auth/atproto_identity.py:105` | `except Exception: return None` in `resolve_did()` for did:plc resolution | Add `logger.warning()` |
| `app/auth/atproto_identity.py:117` | Same pattern for did:web resolution | Add `logger.warning()` |
| `app/auth/middleware.py:97` | `except Exception: return None` in `authenticate_from_cookie()` for cookie parsing | Add `logger.debug()` |

**Fix — uses `print()` instead of logger:**

| Location | Pattern | Action |
|---|---|---|
| `app/auth/atproto_identity.py:77` | `print("DNS TXT handle resolution:", e)` in `resolve_handle()` | Replace with `logger.debug()` |
| `app/auth/atproto_identity.py:85` | `print("HTTP handle resolution:", e)` in `resolve_handle()` | Replace with `logger.warning()` |

**Acceptable — cleanup/heuristic paths:**

| Location | Notes |
|---|---|
| `app/auth/atproto_oauth.py:126,132` | Two `except Exception: pass` in `is_use_dpop_nonce_error_response()`. Heuristic detection; silent catch is reasonable. Consider `logger.debug()`. |
| `app/management/routes.py:329` | `except Exception: pass` during cleanup after wiki creation failure. Outer exception already logged. Consider `logger.debug()`. |

**Already correct:**

| Location | Notes |
|---|---|
| `app/resolver.py:777` | `except Exception: logger.exception(...)` in `_get_per_wiki_user()` |
| `app/management/routes.py:341` | `except Exception: logger.warning(..., exc_info=True)` |

### Rule

Never write `except: pass` or `except BaseException: pass`. At minimum, log at debug level.

For catch-all exception handlers:
- Use `except Exception` (not `BaseException`) — let `KeyboardInterrupt` and `SystemExit` propagate.
- Always call `logger.exception(...)` or `logger.warning(..., exc_info=True)` in the except block.
- If the function must return a fallback value, do so after logging.
