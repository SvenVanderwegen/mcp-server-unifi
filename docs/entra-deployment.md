# Microsoft 365 sign-in with shared keys (`MCP_AUTH_MODE=entra`)

A UniFi Site Manager API key is created inside one Fabric and has admin rights
there. With per-user keys (`user_key` mode, see
[per-user-deployment.md](per-user-deployment.md)) that means every colleague has
to create a key in every Fabric. In `entra` mode the server holds **one key per
Fabric** itself, and people sign in with their **Microsoft 365 account**.

Everyone who can sign in uses all of the server's keys, with the admin rights
those keys carry. The tenant (and, if you set it up, an Entra group) is the
access boundary, so restrict sign-in in Entra (step 1.5 below).

## How it works

```
client ──/authorize──▶ server ──302──▶ login.microsoftonline.com/<tenant>  (Microsoft sign-in)
Entra ──302──▶ /oauth/entra/callback?code=…   server redeems it, checks tenant + app
server ──302──▶ client redirect_uri?code=…
client ──/token──▶ access + refresh token
client ──/mcp, Bearer token──▶ tools run on UNIFI_API_KEYS
```

- Towards Claude and Copilot nothing changes: the server is still its own OAuth
  server (`/authorize`, `/token`, `/register`, `/revoke`, scope `unifi`), and the
  Copilot client registration works exactly as in `user_key` mode.
- Only an ID token from your tenant (`tid`, `iss`) for your app (`aud`) is
  accepted. `MCP_ENTRA_TENANT_ID` must be a tenant GUID; `common`,
  `organizations` and `consumers` are refused at startup.
- The user's Entra refresh token is stored Fernet-encrypted under
  `MCP_SECRET_KEY` and redeemed every `MCP_OAUTH_REVALIDATE_INTERVAL` seconds
  (default 900). Once Entra refuses it (account disabled or deleted, sessions
  revoked) the user and all their tokens are dropped. An Entra outage or an
  expired app secret is logged as an error but does not log anyone out.
- UniFi only ever sees the shared key, so the server logs every tool call with
  the user's name and e-mail: `Tool call get_host by Jan Peeters <jan@…>`.
- Inside a request the keys behave like the upstream multi-key setup:
  `list_hosts` / `list_sites` aggregate across all keys, per-console tools use
  the key of the Fabric that owns the console. The fleet tools
  (`list_all_devices`, `list_all_clients`, `get_fleet_summary`,
  `search_device_fleet`, `list_devices`) also cover every key, unless given a
  `key_label` to scope to one Fabric.

## 1. Register the app in Microsoft Entra

entra.microsoft.com → Identity → Applications → App registrations → New registration:

1. Name `UniFi MCP`, supported account types **Accounts in this organizational
   directory only**.
2. Redirect URI: platform **Web**, `https://<host>/oauth/entra/callback`.
3. Certificates & secrets → New client secret. Copy the value (not the ID).
4. API permissions: the default `User.Read` is enough; `openid`, `profile`,
   `email` and `offline_access` are requested at sign-in.
5. Optional, recommended: Enterprise applications → `UniFi MCP` → Properties →
   **Assignment required = Yes**, then Users and groups → add the group that may
   use UniFi. Everyone else gets "not assigned" from Microsoft.

From the Overview page note the **Application (client) ID** and the
**Directory (tenant) ID**.

6. App roles → Create app role: display name `UniFi admin`, allowed member
   types Users/Groups, value **`UniFi.Admin`** (or set `MCP_ENTRA_ADMIN_ROLE` to
   your own value). Then Enterprise applications → `UniFi MCP` → Users and
   groups → assign that role to the people who manage the keys.

## 2. Create the Fabric keys

For each Fabric: unifi.ui.com → pick the Fabric in the top-left selector →
**API Keys** → **Create API Key**. Ideally create them with a dedicated service
account, so the keys do not depend on one person's account.

Add them on the admin page (next section) or in `UNIFI_API_KEYS`; both work
together.

## Managing keys on `/admin`

`https://<host>/admin` signs you in with Microsoft and opens only for accounts
with the `UniFi.Admin` app role. It lists every key (masked to the last four
characters), and lets you:

- **add** a key with a name for its Fabric: it is tested against `/v1/hosts`
  first, then stored Fernet-encrypted (`MCP_SECRET_KEY`) in the SQLite store on
  the `/data` volume, and used from the very next request. No redeploy.
- **test** a key: shows how many consoles it sees, or that UniFi refuses it.
- **remove** a key: it stops being used on the next request.

Keys from `UNIFI_API_KEYS` are listed too but can only be changed in the stack.
Every change is logged with the admin's name. The admin session is an
encrypted, HttpOnly cookie on `/admin`, valid for 8 hours; forms carry a CSRF
token. The server starts fine with no keys at all and logs a reminder to add
them on `/admin`.

## 3. Stack environment

```
MCP_AUTH_MODE=entra
MCP_PUBLIC_URL=https://<host>
MCP_SECRET_KEY=<openssl rand -hex 32>
MCP_ENTRA_TENANT_ID=<Directory (tenant) ID>
MCP_ENTRA_CLIENT_ID=<Application (client) ID>
MCP_ENTRA_CLIENT_SECRET=<client secret value>
# Optional: keys can also (or only) be managed on /admin
UNIFI_API_KEYS=[{"key":"<key fabric 1>","label":"vbc"},{"key":"<key fabric 2>","label":"klant-x"}]
# MCP_ENTRA_ADMIN_ROLE=UniFi.Admin
```

`UNIFI_API_KEYS` is a JSON list; the labels show up as `_keyLabel` on hosts and
sites (keys added on `/admin` get their name plus a short digest). The Copilot client (`MCP_OAUTH_CLIENT_*`) is configured as in
[per-user-deployment.md](per-user-deployment.md#connect-microsoft-365-copilot).

Switching from `user_key` mode: existing logins stop working (they hold UniFi
keys, not a Microsoft account), so everyone reconnects once.

## 4. Check

```bash
curl -s https://<host>/health                                    # {"status":"ok"}
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://<host>/mcp   # 401
```

Then connect Claude (Settings → Connectors → Add custom connector,
`https://<host>/mcp`): it opens the Microsoft sign-in page.

When the client secret expires (Entra's default is 6 to 24 months), sign-in
fails with "Microsoft is momenteel niet bereikbaar" and the log shows
`invalid_client`: create a new secret and update `MCP_ENTRA_CLIENT_SECRET`.
