# Detailed Change Log

## 1) Reliability and Error Handling

### `steampy/client.py`
- Added unified HTTP helper `_request(...)` with timeout (`REQUEST_TIMEOUT_SECONDS = 20`) and `RequestException` -> `ApiException` conversion.
- Added unified JSON parsing helper `_json_or_raise(...)` with response preview in error text.
- Added explicit web-token guard `_ensure_webtoken(...)` to prevent hidden `AttributeError` when `use_webtoken=True`.
- Added stricter `api_call(...)` validation:
  - method normalization (`GET`/`POST` only),
  - explicit 429 -> `TooManyRequests`,
  - explicit 5xx -> `ApiException`.
- Replaced fragile flows that directly called `.json()` with guarded parsing in all key methods.
- `get_trade_offers(...)`:
  - fixed recursion-based retry into bounded retry loop (`MAX_JSON_RETRIES`),
  - preserved all arguments on retries,
  - added warning log on retry.
- `login(...)`:
  - removed `print(...)`,
  - made steam cookie/access-token extraction explicit and validated.
- `logout(...)` now also clears `_access_token`.
- `_get_session_id(...)` now raises `ApiException` when cookie is missing instead of returning `None`.
- `get_profile(...)` now validates non-empty players list.
- `get_friend_list(...)` now safely reads nested fields.
- `get_wallet_balance(...)` now raises `ApiException` with clear reason when parsing fails.
- General cleanup:
  - removed unused imports,
  - improved typing and consistency,
  - removed hard-coded/implicit failure paths.

### `steampy/market.py`
- Added unified HTTP helper `_request(...)` and JSON helper `_json_or_raise(...)`.
- Removed all debug `print(...)` statements from library runtime.
- Changed default market country from `'TR'` to `'US'` in `fetch_price(...)` and `fetch_price_history(...)` (override still supported by parameter).
- `create_buy_order(...)`:
  - now has deterministic contract: always returns valid response or raises `ApiException`,
  - validates presence of `need_confirmation` and `confirmation_id`,
  - validates second attempt result after mobile confirmation,
  - added informational logger entry for confirmed order flow.
- `buy_item(...)`:
  - removed broad `except Exception`,
  - explicit validation of `wallet_info.success`,
  - returns precise error context.

### `steampy/login.py`
- Reworked JSON parsing and API error reporting with `_parse_json(...)`.
- Added request timeout usage across login API calls.
- Replaced recursive RSA key retrieval with bounded loop (`MAX_RSA_ATTEMPTS = 5`).
- Added explicit checks for missing fields in finalize/poll steps.
- Removed dead/unused logic that was not part of the active login flow.
- Improved cookie propagation robustness in `set_sessionid_cookies(...)`.

## 2) Confirmation Safety Fixes

### `steampy/confirmation.py`
- Fixed critical bug in `confirm_by_id(...)`:
  - previous code used `conf` outside loop and could use `result` before assignment,
  - now properly iterates, matches by `creator_id`, returns boolean deterministically.
- Removed dangerous behavior in `_select_sell_listing_confirmation(...)`:
  - no longer auto-confirms unrelated confirmations.
- Removed debug prints and replaced with logger debug/warning.
- `_send_confirmation(...)` now sends `'op'` as scalar value (not tuple).
- Added parsing guards for malformed confirmation detail pages.

## 3) Types and Models

### `steampy/models.py`
- Migrated `GameOptions` and `Asset` to `@dataclass(frozen=True)` for cleaner model semantics.
- Preserved compatibility by re-defining predefined options:
  - `GameOptions.STEAM`, `GameOptions.DOTA2`, `GameOptions.CS`, etc.
- Kept enum values and URL constants unchanged.

## 4) Utilities and Decorators

### `steampy/utils.py`
- `login_required` now uses `functools.wraps` to preserve function metadata.
- `ping_proxy(...)` now:
  - uses timeout,
  - catches `RequestException` specifically,
  - preserves original exception via chaining.

## 5) Packaging Modernization

### `setup.py`
- Fixed Python version check bug:
  - from incorrect boolean condition to `sys.version_info < (3, 8)`.
- Replaced static package list with `find_packages(include=['steampy', 'steampy.*'])`.
- Removed accidental runtime packaging of `test` and `examples`.

### `setup.cfg`
- Fixed metadata key from `description-file` to `description_file`.

### `pyproject.toml` (new)
- Added modern build-system config for setuptools/wheel.

## 6) Tests

### New unit tests
- `test/test_client_unit.py`
  - active-offer filter behavior,
  - retry failure behavior in `get_trade_offers(...)`,
  - web-token requirement validation,
  - missing session id handling.
- `test/test_market_unit.py`
  - deterministic failure in `create_buy_order(...)` without confirmation path,
  - error behavior in `buy_item(...)` for unsuccessful wallet response.
- `test/test_confirmation_unit.py`
  - successful and unsuccessful `confirm_by_id(...)` flows.

### Existing integration tests cleanup
- `test/test_client.py`
  - fixed invalid assertion in `test_get_steam_id`,
  - aligned inventory structure usage in skipped URL-offer integration test.

## 7) Verification

- Executed:
  - `python -m unittest discover -s test -p "test_*.py"`
- Result:
  - `Ran 61 tests`
  - `OK (skipped=26)`

Skipped tests are existing integration tests that require real Steam secrets/environment.

## 8) Refresh Token Session Restore

### `steampy/login.py`
- Added constructor support for optional `refresh_token`.
- Implemented `refresh_session()`:
  - calls `jwt/finalizelogin` with refresh nonce,
  - performs transfer redirects,
  - normalizes cookies for store/community domains,
  - warms up community/store pages.
- Added `_check_steam_session()` validation using `/account/` page content.
- `login()` now:
  - first tries refresh flow when `refresh_token` is provided,
  - falls back to full credential login when refresh fails or session check does not pass.

### `steampy/client.py`
- Added optional constructor argument `refresh_token`.
- Added optional constructor argument `steam_id` for cookies-first initialization.
- `login()` now passes stored refresh token into `LoginExecutor`.
- After successful login/refresh, client stores possibly rotated token from executor.
- Added `get_refresh_token()` helper to retrieve the current refresh token for persistence.
- `set_login_cookies(...)` now uses `steam_id` from constructor (if provided) and avoids HTML parsing dependency.

## 9) Network Retries for Proxy and Connector Errors

### `steampy/client.py`
- Added network retry policy for all HTTP requests in `_request(...)`:
  - `NETWORK_RETRIES = 3`,
  - linear backoff `1s`, `2s`,
  - retries on `requests` network exceptions (proxy/connect/timeout classes),
  - raises `ApiException` only after retries are exhausted.
- Added safer access token behavior:
  - `steamLoginSecure`/access token absence no longer crashes login,
  - warning is logged and API-key mode remains available.
- Added robust session id lookup fallback:
  - checks community domain,
  - then store domain,
  - then generic cookie lookup.
- `accept_trade_offer(...)` now converts unknown trade state `ValueError` into explicit `ApiException`.

### `steampy/market.py`
- Added network retry policy in `_request(...)` with the same attempt/backoff strategy.
- All market operations now benefit from automatic retry on temporary network/proxy failures.

### `steampy/login.py`
- Added network retry policy in `_request(...)`.
- Login API calls, RSA fetch, redirects, finalize-login, session checks, and refresh warm-up use retry path.
- Improved cookie normalization in `set_sessionid_cookies(...)` for partially present cookie sets.
- Improved missing-refresh-token diagnostics in `_poll_session_status(...)` to include full Steam payload.

### `steampy/confirmation.py`
- Added retry-enabled request wrapper for mobile confirmation endpoints:
  - `/mobileconf/getlist`,
  - `/mobileconf/details/...`,
  - `/mobileconf/ajaxop`.

### `steampy/utils.py`
- `ping_proxy(...)` now retries proxy connectivity check (3 attempts, linear backoff) before raising `ProxyConnectionError`.
- Error message now includes proxy config and root network exception for faster production debugging.

### Tests
- Extended unit coverage for retry/error hardening:
  - `test/test_client_unit.py`: network retry in `_request(...)`, session-id fallback, unknown trade state handling, access-token extraction guard.
  - `test/test_login_unit.py`: explicit missing refresh-token failure in poll-session flow.
  - `test/test_utils.py`: proxy ping retry path and final `ProxyConnectionError`.

## 10) Removed Steam Guard File Dependency in Client API

### `steampy/client.py`
- Reworked constructor to accept secrets directly:
  - `steam_id`,
  - `shared_secret`,
  - `identity_secret`.
- Removed dependency on `steam_guard` file/string parsing in `SteamClient`.
- Reworked `login(...)` signature to use direct secrets:
  - `login(username, password, shared_secret, steam_id=None, identity_secret=None)`.
- Added sync helper to maintain internal credentials dict from constructor/login arguments.
- Added steam-id extraction from `steamLoginSecure` cookie as fallback when using cookies-only flow.
- Kept compatibility for downstream code by preserving `client.steam_guard` as a runtime dict built from provided secrets.
- Added explicit validation errors for mobile-confirmation flows when `identity_secret` or `steam_id` is missing.

### `steampy/market.py`
- Improved guards for operations requiring confirmation:
  - clear errors when `steam_id`/`identity_secret` are not present.

### Tests
- Added unit coverage for new constructor/login contract:
  - steam id extraction from `steamLoginSecure`,
  - enforcement that credentials login requires `shared_secret`.

## 11) Refresh-Only Login Mode

### `steampy/client.py`
- `SteamClient.login()` now accepts refresh-token-only flow:
  - if `refresh_token` exists, client may login without username/password/shared_secret,
  - credentials are required only when refresh fails and fallback credentials login is needed.
- Improved internal steam-id retrieval during login by using a non-decorated parser helper, avoiding login-state dependency.

### `steampy/login.py`
- `LoginExecutor.login()` now clearly separates flows:
  - tries refresh first when token exists,
  - if refresh fails and credentials are missing, raises explicit `InvalidCredentials`,
  - proceeds with credentials flow only when required fields are present.
- `_check_steam_session()` now works when username is absent by checking account page URL/status instead of username text only.

### Tests
- Added coverage for refresh-only mode:
  - `test/test_client_unit.py`: login without credentials using refresh token.
  - `test/test_login_unit.py`: explicit failure when refresh fails and no credentials exist.
