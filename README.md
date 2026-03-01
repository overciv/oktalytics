# Okta Authentication Analytics Dashboard

A Node.js/Express web application that reads 31 days of Okta System Logs and displays authentication analytics on a protected dashboard. Access requires logging in with an Okta account.
<p align="center">
<img width="740" height="735" alt="screenshot" src="https://github.com/user-attachments/assets/04f9be24-e770-4988-a82a-870b4b9f2dc6" />
</p>

## Features

- **Authentication overview** — unique users, successful logins, failed passwords, failed MFA, MFA abandonments, inactive users, avg auth time
- **FastPass metrics** — enrollments, users, devices, authentications
- **Biometric usage** — adoption rates
- **Email delivery** — success, failure, bounced, spam, dropped, unsubscribed
- **Per-app scoping** — optional dropdown to scope all metrics to a specific application
- **Single fetch, all scopes** — refreshing "All Apps" calculates metrics for every configured app in one Okta API pass
- **Foldable sections** — each metric category is collapsible; Expand All / Fold All controls
- **Smart caching** — 1-hour cache per scope, auto-loaded on page load and app switch
- **Streaming processing** — logs processed page-by-page as they arrive (constant memory usage)
- **Rate limit handling** — automatic retry with backoff on 429 responses

## Prerequisites

- Node.js v14+
- An Okta tenant with API access
- An Okta OIDC application (for dashboard login)

## Installation

```bash
npm install
```

## Configuration

Create a `.env` file at the project root:

```
# Okta tenant
OKTA_ORG_URL=https://your-domain.okta.com
OKTA_API_TOKEN=your-api-token-here

# OIDC app credentials (for dashboard login)
OKTA_CLIENT_ID=your-client-id
OKTA_CLIENT_SECRET=your-client-secret
APP_BASE_URL=http://localhost:3000
REDIRECT_URI=http://localhost:3000/authorization-code/callback
POST_LOGOUT_REDIRECT_URI=http://localhost:3000
SESSION_SECRET=your-random-secret-key

PORT=3000
NODE_ENV=development

# Optional: scope metrics per application
# OKTA_APPS=[{"name":"Salesforce","id":"0oa..."},{"name":"Office 365","id":"0oa..."}]
OKTA_APPS=
```

### Setting up the OIDC application in Okta

1. In the Okta Admin Console, go to **Applications → Create App Integration**
2. Choose **OIDC - OpenID Connect** → **Web Application**
3. Set Sign-in redirect URI to `http://localhost:3000/authorization-code/callback`
4. Set Sign-out redirect URI to `http://localhost:3000`
5. Copy the **Client ID** and **Client Secret** into `.env`

### Getting an API token

In the Okta Admin Console, go to **Security → API → Tokens → Create Token**. Copy the token into `OKTA_API_TOKEN`.

### Configuring per-app scoping (optional)

Set `OKTA_APPS` to a JSON array of `{"name", "id"}` pairs. The `id` is the application's instance ID (the `0oa…` value in the URL when viewing the app in the Okta Admin Console).

To find the correct IDs from your actual system logs, use the diagnostic endpoint after starting the server:

```
GET /api/debug/app-targets
```

This scans the last 7 days of logs and returns all `AppInstance` target IDs found, flagging which ones match your current `.env`.

## Running

```bash
npm start        # production
npm run dev      # development (nodemon, auto-restarts on source changes)
```

Navigate to `http://localhost:3000`. You will be redirected to Okta to log in.

## Usage

### First run
1. Select a scope from the dropdown (if apps are configured), or leave it on **All Apps**
2. Click **Refresh Data** — processing runs in the background
3. Progress (logs processed, pages fetched, elapsed time) updates every second
4. Metrics and charts display automatically when complete

When **All Apps** is refreshed and `OKTA_APPS` is configured, metrics for every app are calculated in the same fetch. Switching the selector after that is instant.

### Subsequent visits
Cached data for the selected scope loads automatically. The cache banner shows the age and a Refresh link.

### Cache management
- **Clear Cache** on **All Apps** deletes all scope caches at once
- Cache expires after 1 hour; stale cache is not served

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/apps` | Configured app list from `OKTA_APPS` |
| GET | `/api/cached-metrics?appId=` | Cached metrics for a scope (`all` or app ID) |
| POST | `/api/fetch-metrics` | Start background processing (`{ appId }` in body) |
| GET | `/api/progress` | Real-time processing progress |
| POST | `/api/clear-cache` | Delete cache (`{ appId }` in body; `all` clears everything) |
| GET | `/api/userinfo` | Logged-in user name and email |
| GET | `/api/debug/app-targets` | App IDs found in the last 7 days of logs |

## Architecture

All application logic lives in `server.js`. The frontend is `public/dashboard.html` (self-contained, Chart.js from CDN).

```
Browser → Okta OIDC login → /dashboard
                                │
                POST /api/fetch-metrics
                                │
                fetchLogsIncremental()   ← one Okta API fetch for all scopes
                        │
                processLogsBatch()       ← in-memory filter per scope per page
                        │
                calculateFinalMetrics()
                        │
                saveCache()              ← ./cache/metrics-{scope}.json per scope
```

Cache files: `./cache/metrics-all.json` for All Apps, `./cache/metrics-app-{id}.json` per application.

## Troubleshooting

**Login loop / OIDC errors** — verify `OKTA_CLIENT_ID`, `OKTA_CLIENT_SECRET`, `REDIRECT_URI`, and `APP_BASE_URL` match the Okta application configuration exactly.

**All metrics show 0 for an app** — the app may not have authentication events in the last 31 days, or the ID in `OKTA_APPS` may be wrong. Use `/api/debug/app-targets` to verify the correct ID.

**Processing takes a long time** — expected for large tenants. Increase `CACHE_DURATION` in `server.js` to reduce how often a full fetch is needed.
