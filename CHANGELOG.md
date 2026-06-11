# Changelog

## [Unreleased] — 2026-06-11

### Changed
- **Authentication**: replaced SSWS API token with OAuth 2.0 on-behalf-of-user flow. The user's access token (obtained at login with scope `okta.logs.read`) is now used for all Okta System Log API calls — no long-lived API key required.
- **OIDC client authentication**: switched from `client_secret` to **Private Key JWT** (`private_key_jwt`, RS256). `OKTA_CLIENT_SECRET` is no longer needed.
- **Authorization Server**: migrated from the custom AS (`/oauth2/default`) to the **Org Authorization Server** (`https://your-domain.okta.com`). Required for `okta.logs.read` scope and accurate `roles` claim delivery.
- `fetchLogsIncremental` now receives the access token as a parameter instead of calling an internal token function.

### Added
- OIDC scope `okta.logs.read` requested at login so the user's access token can read System Logs on their behalf.
- `OKTA_PRIVATE_KEY_PATH` and `OKTA_PRIVATE_KEY_ID` env vars for the private key JWT setup.
- `keys/` directory added to `.gitignore` to prevent accidental private key commits.

### Removed
- `OKTA_API_TOKEN` — no longer used.
- `OKTA_CLIENT_SECRET` — replaced by private key JWT.
- `OKTA_SERVICE_CLIENT_ID` — M2M client credentials flow removed in favour of on-behalf-of-user.
- `jsonwebtoken` npm dependency — no longer needed.
- `@okta/okta-sdk-nodejs` client instance — was instantiated but never called; removed.

---

## 1e7fa15 — Add configurable cache TTL, admin role gate, and auto-load

### Added
- `CACHE_DURATION_HOURS` env var to configure cache lifetime (default: 1 hour).
- Role-based access gate: **Refresh Data** and **Clear Cache** buttons are only shown to users whose OIDC token contains `admin_access` in the `roles` claim.
- Dashboard auto-loads cached metrics on page load and on app selector change.

---

## 5eb5e31 — Add login-step abandonment metric

### Added
- Tracks MFA/password step abandonments (user started but did not complete authentication).

---

## ea304e2 — Add M2M token grants metric

### Added
- Tracks `app.oauth2.token.grant.access_token` events with `client_credentials` grant type.
- Daily M2M token count displayed in dashboard, covering service-to-service OAuth activity.
- Per-app scoping supported: M2M grants are matched against the requesting app actor rather than the target (since the requesting app is the actor in client credentials flows).
