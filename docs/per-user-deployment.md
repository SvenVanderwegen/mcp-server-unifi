# Per-user deployment (`MCP_AUTH_MODE=user_key`)

This fork adds one auth mode to upstream: every person who connects logs in with
**their own UniFi Site Manager API key**, and every tool call they make runs on
that key. They see exactly the consoles their UniFi account can see and can do
exactly what that account may do. The server holds no UniFi key of its own.

It works with Claude (custom connectors) and Microsoft 365 Copilot (custom
federated connector), both over OAuth 2.1 with PKCE.

## How it works

```
client ──/authorize──▶ server ──302──▶ /oauth/login        (the user pastes their key)
login page ──GET api.ui.com/v1/hosts with that key──▶ accepted?
server ──302──▶ client redirect_uri?code=…
client ──/token──▶ access + refresh token
client ──/mcp, Bearer token──▶ tools run with that user's key
```

- The server is its own OAuth authorization server (FastMCP `OAuthProvider`):
  `/.well-known/oauth-authorization-server`, `/authorize`, `/token`,
  `/register` (dynamic client registration), `/revoke`. Scope: `unifi`.
- Keys are stored Fernet-encrypted under `MCP_SECRET_KEY` in SQLite on the
  `/data` volume; tokens are stored only as SHA-256 digests.
- A stored key is re-checked against `api.ui.com` every
  `MCP_OAUTH_REVALIDATE_INTERVAL` seconds (default 900). A key that was deleted
  in UniFi is forgotten and the client is sent back to the login page. An
  outage at `api.ui.com` does not log anyone out.
- Per request, the key is placed in a context variable (`user_keys.py`) that
  `Settings.get_key_configs()` returns as the only configured key. The HTTP
  client and the host/site cache are keyed per user, so people never share a
  connection or a cached host list.
- The server refuses to start in this mode when `UNIFI_API_KEY` or
  `UNIFI_API_KEYS` is set.

## Deploy with Portainer + Traefik

1. Create a stack from this repository (git), compose file `docker-compose.yml`.
2. Environment variables (see `.env.example`):
   - `SUBDOMAIN`, `DOMAIN_NAME` for the Traefik host rule
   - `MCP_PUBLIC_URL=https://<subdomain>.<domain>` (no `/mcp`)
   - `MCP_SECRET_KEY` from `openssl rand -hex 32`
3. Deploy, then check:

   ```bash
   curl -s https://unifi.example.com/health                                   # {"status":"ok"}
   curl -s -o /dev/null -w '%{http_code}\n' -X POST https://unifi.example.com/mcp  # 401
   ```

   A `401` on `/mcp` is the point: nothing is reachable without logging in.

## Connect Claude

Settings → Connectors → Add custom connector, URL `https://<host>/mcp`.
Claude registers itself and opens the login page.

## Connect Microsoft 365 Copilot

Copilot does not register dynamically, so configure a fixed client:

1. Teams Developer Portal → Tools → OAuth client registration:
   - Authorization endpoint `https://<host>/authorize`
   - Token and refresh endpoint `https://<host>/token`
   - Scope `unifi`, PKCE enabled
   - Client ID and secret: pick them yourself (secret: `openssl rand -hex 32`)
2. Put the same values in the stack:

   ```
   MCP_OAUTH_CLIENT_ID=m365-copilot
   MCP_OAUTH_CLIENT_SECRET=<the secret>
   MCP_OAUTH_CLIENT_REDIRECT_URIS=https://teams.microsoft.com/api/platform/v1.0/oAuthRedirect
   ```

   If the token exchange fails with `invalid_client`, set
   `MCP_OAUTH_CLIENT_AUTH_METHOD=client_secret_basic`.
3. Microsoft 365 admin center → Copilot → Connectors → Create a new connector →
   Connect to MCP server, URL `https://<host>/mcp`, with the OAuth registration
   ID from step 1.

## Where users find their key

unifi.ui.com → **API** in the left menu (or Settings → API Keys) →
**Create API Key**. The key belongs to that person's UI account.
