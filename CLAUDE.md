# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm start          # Start production server
npm run dev        # Start development server with nodemon (auto-restart on changes)
```

No test suite exists in this project.

## Environment Setup

Copy the variables below into a `.env` file at the project root:

```
OKTA_ORG_URL=https://your-domain.okta.com
OKTA_API_TOKEN=your-api-token-here
OKTA_CLIENT_ID=your-client-id
OKTA_CLIENT_SECRET=your-client-secret
APP_BASE_URL=http://localhost:3000
REDIRECT_URI=http://localhost:3000/authorization-code/callback
POST_LOGOUT_REDIRECT_URI=http://localhost:3000
SESSION_SECRET=your-random-secret-key
PORT=3000
NODE_ENV=development
OKTA_APPS=[{"name":"Salesforce","id":"0oa..."},{"name":"Office 365","id":"0oa..."}]
CACHE_DURATION_HOURS=1
```

`OKTA_APPS` is optional. When set, a dropdown appears in the dashboard allowing metrics to be scoped per application. `CACHE_DURATION_HOURS` defaults to `1` if unset.

**Role-based access:** The Refresh Data and Clear Cache actions require the user to have `admin_access` in the `roles` claim of their OIDC token. Add a custom `roles` claim to the Okta app's ID token/userinfo that returns the user's roles as a string or array. Users without `admin_access` see a read-only dashboard (no Refresh / Clear Cache buttons). Each entry needs a display `name` and an Okta application `id` (the `0oa...` client ID visible in the Okta Admin Console). Omitting this variable (or leaving it empty) shows only the "All Apps" scope.

## Architecture

This is a single-file Node.js/Express application (`server.js`) that reads Okta System Logs via the Okta REST API and displays authentication analytics on a dashboard.

**Authentication flow:** All routes are protected by Okta OIDC (`@okta/oidc-middleware`). Users must log in via Okta SSO before accessing the dashboard. The `requireAuth` middleware checks `req.userContext.userinfo`. The OIDC router is mounted before static files, so unauthenticated requests to any path are redirected to `/login`.

**Data pipeline (server.js):**
1. `POST /api/fetch-metrics` — returns immediately and triggers background processing
2. `fetchLogsIncremental()` — paginates through 31 days of Okta System Logs (1000 entries/page), calling `processLogsBatch()` on each page as it arrives (streaming, not buffered)
3. `processLogsBatch()` — classifies each log entry by `eventType` and `outcome`, updating in-memory `metrics` object (uses `Set` for unique counting of users/devices)
4. `calculateFinalMetrics()` — converts the in-memory metrics into serializable chart data
5. `saveCache()` — writes result to `./cache/metrics-cache.json` with a 1-hour TTL

**Progress tracking:** A module-level `progressData` object holds processing state (pages fetched, logs processed, elapsed time). `GET /api/progress` exposes this; the frontend polls it every 2 seconds during active processing.

**Frontend:** `public/dashboard.html` is a self-contained single-page app (inline CSS + JS, Chart.js from CDN). It calls the API endpoints directly and renders charts using Chart.js. `public/index.html` is the unauthenticated landing/marketing page; authenticated users are redirected away from `/` to `/dashboard`.

**Key event types tracked in processLogsBatch:**
- `user.session.start` — successful logins and unique users (All Apps scope only)
- `user.authentication.sso` — successful logins and unique users (app-scoped only; covers both SP and IDP-initiated flows; `user.session.start` is used for All Apps because SSO events would inflate counts across apps)
- `user.authentication.authenticate` / `user.mfa.*` — failed passwords, failed MFA, FastPass
- `user.mfa.factor.activate` with reason `"User set up SIGNED_NONCE factor"` — FastPass enrollments
- `system.email.delivery` — email delivery success/failure/dropped/bounced/spam/unsubscribed
- FastPass detection uses `debugContext.debugData.behaviors` containing `"New Device=NEGATIVE"` or `"SIGNED_NONCE"`
- Biometric detection uses `debugContext.debugData.keyTypeUsedForAuthentication === "USER_VERIFYING_BIO_OR_PIN"`

**Cache:** One JSON file per scope: `./cache/metrics-all.json` for "All Apps", `./cache/metrics-app-{appId}.json` per application. Each file holds `{ metrics, logsProcessed, timestamp }`. The directory is auto-created on first write. Cache age is checked on every `GET /api/cached-metrics` call.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/apps` | Return configured app list from `OKTA_APPS` |
| GET | `/api/debug/app-targets` | Scan last 7 days of logs and return all `AppInstance` target IDs found (useful for finding the correct app IDs to put in `OKTA_APPS`) |
| GET | `/api/cached-metrics?appId=` | Return cached metrics for scope (`all` or app ID) |
| POST | `/api/fetch-metrics` | Trigger background log processing (`{ appId }` in body) |
| GET | `/api/progress` | Poll processing progress |
| POST | `/api/clear-cache` | Delete cache file (`{ appId }` in body) |
| GET | `/api/userinfo` | Return logged-in user's name/email |
| GET | `/dashboard` | Serve `public/dashboard.html` |
| GET | `/logout` | Okta Single Logout (SLO) |

## Key Configuration Constants (server.js)

- `CACHE_DURATION` — derived from `CACHE_DURATION_HOURS` env var (defaults to 1 hour)
- Date range for log fetch — hardcoded to 31 days back from `now` in `POST /api/fetch-metrics`
- Request delay — `100ms` between paginated API calls (`sleep(100)`) to avoid rate limits
- Rate limit retry — up to 5 retries with backoff based on `x-rate-limit-reset` header
