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
- **M2M tokens** — client credentials token grants per day (tracks service-to-service OAuth activity)
- **Per-app scoping** — optional dropdown to scope all metrics to a specific application
- **Single fetch, all scopes** — refreshing "All Apps" calculates metrics for every configured app in one Okta API pass
- **Foldable sections** — each metric category is collapsible; Expand All / Fold All controls
- **Smart caching** — configurable TTL per scope, auto-loaded on page load and app switch
- **Streaming processing** — logs processed page-by-page as they arrive (constant memory usage)
- **Rate limit handling** — automatic retry with backoff on 429 responses
- **Role-based access** — Refresh Data and Clear Cache require `admin_access` in the user's `roles` claim

## Prerequisites

- Node.js v18+
- An Okta tenant
- An Okta OIDC Web Application configured with **Private Key JWT** as the token endpoint authentication method
- The user's Okta account must have the `okta.logs.read` OAuth scope granted (requires Okta admin permissions)

## Installation

```bash
npm install
```

## Configuration

Create a `.env` file at the project root:

```
# Okta tenant (Org Authorization Server)
OKTA_ORG_URL=https://your-domain.okta.com

# OIDC app — private key JWT authentication (no client secret needed)
OKTA_CLIENT_ID=your-client-id
OKTA_PRIVATE_KEY_PATH=./keys/private.pem
OKTA_PRIVATE_KEY_ID=my-key-id

APP_BASE_URL=http://localhost:3000
REDIRECT_URI=http://localhost:3000/authorization-code/callback
POST_LOGOUT_REDIRECT_URI=http://localhost:3000
SESSION_SECRET=your-random-secret-key

PORT=3000
NODE_ENV=development

# Optional: scope metrics per application
# OKTA_APPS=[{"name":"Salesforce","id":"0oa..."},{"name":"Office 365","id":"0oa..."}]
OKTA_APPS=

# Optional: cache duration in hours (default: 1)
CACHE_DURATION_HOURS=1
```

### Setting up the OIDC application in Okta

1. In the Okta Admin Console, go to **Applications → Create App Integration**
2. Choose **OIDC - OpenID Connect** → **Web Application**
3. Set Sign-in redirect URI to `http://localhost:3000/authorization-code/callback`
4. Set Sign-out redirect URI to `http://localhost:3000`
5. Under **Client authentication**, select **Public key / Private key**
6. Add your public key (JWK or PEM). The matching private key goes in `./keys/private.pem`
7. Copy the **Client ID** and the **Key ID** into `.env`

> **Authorization Server**: this app uses the **Org Authorization Server** (`https://your-domain.okta.com`), not a custom AS. The `okta.logs.read` scope is only available on the Org AS.

### Generating a key pair

```bash
mkdir -p keys
openssl genrsa -out keys/private.pem 2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem
```

Upload `keys/public.pem` to the Okta app. The `keys/` directory is gitignored — never commit the private key.

### Granting `okta.logs.read` access

The dashboard reads System Logs via the logged-in user's access token. The token must carry the `okta.logs.read` scope, which requires the user to have Okta admin privileges. Only users with that scope will be able to trigger a data refresh.

### Role-based admin gate

The **Refresh Data** and **Clear Cache** buttons are only shown to users whose OIDC token includes `admin_access` in a `roles` claim. To set this up:

1. In the Okta Admin Console, go to your OIDC app → **Sign On** → edit the ID token claims
2. Add a custom claim named `roles` mapped to the user's group or profile attribute
3. The value must be the string `"admin_access"` or an array containing it
4. Ensure the claim is included in the **userinfo** endpoint response, not just the ID token
5. Use the **Org Authorization Server** — custom AS claims are on a separate endpoint

### Configuring per-app scoping (optional)

Set `OKTA_APPS` to a JSON array of `{"name", "id"}` pairs. The `id` is the application's instance ID (the `0oa…` value visible in the Okta Admin Console URL when viewing the app).

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
2. Click **Refresh Data** — processing runs in the background (admin users only)
3. Progress (logs processed, pages fetched, elapsed time) updates every second
4. Metrics and charts display automatically when complete

When **All Apps** is refreshed and `OKTA_APPS` is configured, metrics for every app are calculated in the same fetch. Switching the selector after that is instant.

### Subsequent visits
Cached data for the selected scope loads automatically. The cache banner shows the age and a Refresh link.

### Cache management
- **Clear Cache** on **All Apps** deletes all scope caches at once
- Cache expires after `CACHE_DURATION_HOURS` (default: 1 hour); stale cache is not served

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/apps` | Configured app list from `OKTA_APPS` |
| GET | `/api/cached-metrics?appId=` | Cached metrics for a scope (`all` or app ID) |
| POST | `/api/fetch-metrics` | Start background processing (`{ appId }` in body) — admin only |
| GET | `/api/progress` | Real-time processing progress |
| POST | `/api/clear-cache` | Delete cache (`{ appId }` in body; `all` clears everything) — admin only |
| GET | `/api/userinfo` | Logged-in user name, email, and admin status |
| GET | `/api/debug/app-targets` | App IDs found in the last 7 days of logs |

## Architecture

All application logic lives in `server.js`. The frontend is `public/dashboard.html` (self-contained, Chart.js from CDN).

```
Browser → Okta OIDC login (pkjwt) → ID token (roles claim) + access token (okta.logs.read)
                                          │
                POST /api/fetch-metrics   │ access token passed through
                                          │
                fetchLogsIncremental()   ←┘  one Okta API fetch for all scopes
                        │
                processLogsBatch()       ← in-memory filter per scope per page
                        │
                calculateFinalMetrics()
                        │
                saveCache()              ← ./cache/metrics-{scope}.json per scope
```

Cache files: `./cache/metrics-all.json` for All Apps, `./cache/metrics-app-{id}.json` per application.

## Troubleshooting

**Login loop / `invalid_client`** — verify `OKTA_CLIENT_ID`, `OKTA_PRIVATE_KEY_PATH`, `OKTA_PRIVATE_KEY_ID`, `REDIRECT_URI`, and `APP_BASE_URL` match the Okta application configuration. Ensure the app uses **Private Key JWT** as token endpoint auth and the correct key ID is registered.

**Refresh button not visible** — the logged-in user's token does not contain `admin_access` in the `roles` claim. Verify the claim is configured on the **Org Authorization Server** and included in the userinfo endpoint response (not just the ID token).

**`okta.logs.read` 403 / empty data** — the logged-in user does not have Okta admin permissions required for that scope. Grant the user a suitable Okta admin role.

**All metrics show 0 for an app** — the app may not have authentication events in the last 31 days, or the ID in `OKTA_APPS` may be wrong. Use `/api/debug/app-targets` to verify the correct ID.

**Processing takes a long time** — expected for large tenants. Increase `CACHE_DURATION_HOURS` to reduce how often a full fetch is needed.
