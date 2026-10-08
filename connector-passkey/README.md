# Passkey connector

[English](./README.md) | [中文](./README_CN.md)

> Sign in to Apache Answer with passkeys (WebAuthn / FIDO2): fingerprint, face, screen lock or a security key instead of a password.

The plugin is a connector (it appears next to the other sign-in buttons and under **Settings > Account > My logins**) and a route plugin (it serves the page `/connector-passkey-auth` where the WebAuthn ceremonies run).

## Build

```bash
./answer build --with github.com/apache/answer-plugins/connector-passkey
```

The UI is built with pnpm 9.7.0, the version pinned by the Answer core (`packageManager` in `ui/package.json`). Newer pnpm releases may refuse to install until the esbuild and @swc/core build scripts are approved (`pnpm approve-builds`).

## Quick start

For administrators:

1. Build Answer with the plugin (see Build) and restart it.
2. Make sure **Admin > Settings > General > Site URL** is the HTTPS address users open in their browser. Passkeys do not work over plain HTTP, except on `http://localhost`.
3. Enable **Passkey Connector** under **Admin > Plugins > Installed Plugins**. Nothing else needs to be configured; see Configuration for the optional fields.

For users:

1. Sign in as usual, for example with your password.
2. Open **Settings > Passkey Connector > Manage passkeys** (avatar menu > **Settings**), optionally enter a name, click **Add a passkey**, then **Create a new passkey**. Your browser or device asks you to confirm with your fingerprint, face, screen lock or security key.
3. Next time, click **Connect with Passkey** on the login page and choose your passkey, or pick it from the username autofill.

## Requirements

- Apache Answer 2.0.2 or later. The plugin relies on the connector OAuth `state` (login and bind intents) introduced in 2.0.2; on older cores every sign-in fails with a missing-state error.
- An HTTPS Site URL. Browsers only allow WebAuthn on secure origins; `http://localhost` is the only exception, for development.
- A browser with passkey support. Conditional UI (passkeys offered in the username autofill) is used when the browser supports it.

## Configuration

Every field is optional. Empty fields are derived from the Site URL (**Admin > Settings > General**), so a site with a correct Site URL works without any configuration.

| Field | Default when empty | Rules |
| --- | --- | --- |
| Relying party name (`rp_name`) | Host name of the Site URL | Shown by the browser or password manager when a passkey is created. |
| Relying party ID (`rp_id`) | Host name of the Site URL | A bare domain such as `example.com`, or `localhost`. No scheme, port, path or IP address. |
| Allowed origins (`rp_origins`) | Origin of the Site URL (`scheme://host[:port]`) | Comma- or newline-separated. Each origin must use `https` (`http` only for `localhost`), have no path, query or fragment, and be on the RP ID or one of its subdomains. |

Notes:

- A Site URL with a sub-path works: `https://example.com/community` gives the RP ID `example.com` and the origin `https://example.com`.
- Behind a reverse proxy, the Site URL must be the public URL users see in their browser, otherwise origin checks fail.
- Invalid settings are rejected when saved. Settings that no longer validate (for example after a Site URL change) are kept in the admin form, and the API answers `503 not_configured` until they are fixed.
- **Changing the RP ID makes every existing passkey unusable.** Passkeys are bound to the RP ID by the authenticator; users would have to create new ones.

## How it works

- **Sign in.** **Connect with Passkey** on the login page opens `/connector-passkey-auth`, where the user picks a passkey (button or autofill). The server verifies it and hands the core a one-time token, and the core signs the user in.
- **Link.** A passkey signs in to an account only after it has been linked to it. **Add a passkey** on the manage page (or **Settings > Account > My logins > Connect**) creates or proves a passkey and links it to the signed-in account. Signing in with a passkey that is not linked yet starts the core's new-account flow for external logins instead. All passkeys of a user share one identity, so linking is per account, not per passkey.
- **Manage.** **Settings > Passkey Connector > Manage passkeys** lists the user's passkeys and lets them add, rename and delete them, up to 20 per user. The last passkey of a linked account cannot be deleted until Passkey is unbound under **My logins**; the core refuses that unbind when passkeys are a passwordless account's only way to sign in.

## Security

- The connector sends the core only an opaque random ID, never an email or profile data, so accounts are linked only through the core's bind flow.
- A crafted link cannot bind a passkey to another account: linking always uses a bind state the core minted for the signed-in user, and sign-in requires a server-side proof that the core generated the state for that sign-in.
- User verification and discoverable credentials are required, attestation is `none`, and a signature counter that goes backwards rejects the sign-in.
- Ceremony state is sealed and short-lived, login tokens are one-time and bound to the core state, and redirects are built on the server.

[SECURITY.md](./SECURITY.md) describes the design in detail, together with the residual risks, the KV storage layout and the core changes that would remove the limitations below.

## Limitations

- On sites with **Login required** enabled, the core route guard blocks anonymous access to `/connector-passkey-auth`, so passkey sign-in is not available there.
- An expired bind state is treated by the core as a login state: a link attempt that took longer than the core state lifetime ends as a sign-in attempt. Start the link again.
- The page derives the UI base path from its own URL and expects the API under the same prefix (`<base>/answer/api/v1`), as the core does for all connector URLs; a separate API base path is not supported. Sub-path deployments have not been tested end to end.
- When the UI is served from a CDN (for example the `cdn-s3` or `cdn-aliyun` plugins), the CDN must send `Access-Control-Allow-Origin` for the site, because the plugin's module script is loaded in CORS mode. See the CORS section of the [cdn-s3](../cdn-s3/README.md) and [cdn-aliyun](../cdn-aliyun/README.md) READMEs.
- Single use and uniqueness checks are serialized within one process. Deployments with several Answer instances keep some narrow races; see SECURITY.md.
- The plugin API has no helper for the signed-in user, so the plugin reads the user ID that the core's auth middleware stores in the request context. If a future core renames or reshapes it, the management endpoints answer `401` and the plugin logs one error pointing at the cause.
