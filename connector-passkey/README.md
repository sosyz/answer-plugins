# Passkey connector

> Sign in to Apache Answer with passkeys (WebAuthn / FIDO2): fingerprint, face, screen lock or a security key instead of a password.

The plugin is a connector (it appears next to the other sign-in buttons and under **Account > My Logins**) and a route plugin (it serves the page `/connector-passkey-auth` where the WebAuthn ceremonies run).

## Build

```bash
./answer build --with github.com/apache/answer-plugins/connector-passkey
```

The UI is built with pnpm 9.7.0, the version pinned by the Answer core (`packageManager` in `ui/package.json`). Newer pnpm releases may refuse to install until the esbuild and @swc/core build scripts are approved (`pnpm approve-builds`).

## Requirements

- Apache Answer 2.0.2 or later. The plugin relies on the connector OAuth `state` (login and bind intents), which the core introduced in 2.0.2; on older cores every sign-in fails with a missing-state error. (The `github.com/apache/answer` version in `go.mod` is only what the plugin compiles against.) Sign-in also relies on how the core's `ConnectorLogin` hands a freshly generated state to the connector (see Sign in; identical from 2.0.2 to the current core). Most changes there make sign-in fail closed with `state_unverified`. A core that wrote a caller-supplied state into the URL after an empty `state` query read would defeat the check, so re-verify this when upgrading the core; the robust fix is upstream (see Residual risks).
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

- The RP ID and origin are derived correctly from a Site URL with a sub-path: `https://example.com/community` gives the RP ID `example.com` and the origin `https://example.com`. The page derives its base path from its own URL (see Limitations).
- Behind a reverse proxy, the Site URL must be the public URL users see in their browser, otherwise origin checks fail.
- The settings are validated when saved; invalid settings are rejected. If they cannot be resolved at request time (for example, no Site URL and no explicit values), the API answers `503 not_configured`. Stored settings that no longer validate at start-up (for example after a Site URL change) are kept and shown in the admin form, and the API answers `503 not_configured` until they are corrected and saved again.
- **Changing the RP ID makes every existing passkey unusable.** Passkeys are bound to the RP ID by the authenticator; users would have to create new ones.

## Flows

### Sign in

1. On the Answer login page the user clicks **Passkey**. The core creates a login `state` and the connector redirects to `/connector-passkey-auth?state=…&state_proof=…`.
2. The user picks a passkey (button, or the browser's autofill suggestion).
3. The server verifies the assertion, mints a one-time token bound to that state and returns the core redirect URL `/answer/api/v1/connector/redirect/passkey?state=…&token=…`.
4. The core redeems the token through the connector and signs the user in.

`state_proof` is an HMAC over the state, keyed with a key derived (HKDF-SHA256) from the plugin's stored secret. The connector adds it only when the core has just generated the state for this request, and never to a state the caller supplied, such as a bind state or a state copied from a link. `login/begin` refuses a state without a valid proof (`400 state_unverified`), so a crafted link carrying another account's bind state cannot be used to sign in and thereby link the visitor's passkey to that account. The check is on the server and does not depend on browser storage. A proof has no expiry of its own and stays valid after its state is consumed; that is harmless because it only ever covers a login-intent state.

A passkey signs in to an existing account only after it has been linked to it (below). Signing in with a passkey that is not linked yet starts the core's new-account flow for external logins instead. To use passkeys with an existing account, link them from **My Logins** first.

All passkeys of an Answer user share one identity (the user handle), so linking is per account, not per passkey. If an unlinked passkey completes the core's new-account flow, that identity is linked to the new account: from then on all of the original user's passkeys sign in to the new account, and linking them to the original account is refused until the new account unbinds Passkey.

### Link a passkey to an account

Linking always goes through the core bind intent. The page ignores the `state` in its own URL when linking: before each ceremony it asks the core for a bind state minted for the signed-in user (`GET /answer/api/v1/connector/user/info`). A signed-out visitor can only sign in with a state that carries a valid `state_proof` (see Sign in). A crafted link carrying a bind state of another account therefore cannot bind the visitor's passkey to that account.

1. **Link passkeys** / **Add a passkey** on the manage page open `/connector-passkey-auth?mode=bind` (with the typed name, which is used for a new passkey). **Account > My Logins > Connect** next to Passkey arrives with the core's `?state=…` instead, which the page ignores. Either way the page removes `state`, `state_proof` and `name` from the address bar.
2. The user creates a new passkey, or proves one of their existing passkeys. Right before the ceremony the page fetches a bind state minted by the core for the logged-in user.
3. The server verifies the ceremony and returns the core redirect URL with a one-time token bound to that state.
4. The core redeems the token and binds the passkey identity to the account, then returns to the account settings.

### Manage

**Account > Settings > Passkey Connector > Manage passkeys** (or `/connector-passkey-auth?mode=manage`) lists the passkeys of the logged-in user and lets them add, rename and delete passkeys. Up to 20 passkeys per user. The page does not delete the last passkey of an account that is linked to passkeys, or while it cannot check the link status: unbind Passkey under **My Logins** first. The core refuses that unbind when passkeys are a passwordless account's only way to sign in, so the account cannot be locked out this way. This rule is enforced by the page; the plugin API gives the server no way to read the core binding.

## Security notes

- **No email or profile data is sent to the core.** The connector returns only an opaque external ID (the WebAuthn user handle, 32 random bytes), so the core can never auto-bind an account by email. Accounts are linked only through the bind state.
- **The redirect is server-built.** The page never takes a redirect target from the query string; the finish endpoints return the core receiver URL built from the Site URL.
- **Login tokens** are random, deleted on first redemption, valid for 2 minutes, stored only as a SHA-256 hash, and redeemable only together with the core state they were minted for (constant-time comparison).
- **Ceremony state is stateless.** Begin endpoints return an opaque session sealed with AES-256-GCM (key derived from a secret stored once in the plugin KV). It expires after 5 minutes and is bound to its purpose, the user and the user handle. The secret is created at start-up (or on first use if that fails), so unauthenticated requests write nothing to the database until a successful cryptographic verification. (Authenticated requests do: `register/begin` creates the user handle, and rename and delete write directly.)
- **Replay protection.** A used challenge is recorded until the session expires, in the same transaction as the credential update and the token. A replay that arrives after the first request has finished is rejected; see the residual risks for replays that race the first request.
- **User verification and discoverable credentials are required** for every ceremony; the server enforces the ceremony timeouts.
- **Attestation is `none`.** No attestation statement is requested because there is no metadata (MDS) policy to evaluate it.
- **Clone detection rejects.** A signature counter that goes backwards rejects the sign-in and nothing is persisted. Backup flags and the counter are updated on every use.
- **Credential IDs are checked for uniqueness across users** (WebAuthn §7.1 step 22) before the credential is written; see the residual risks for concurrent registrations. The owner of a credential is taken from the verified record, never from client input.
- **Unlinking and deleting are independent.** Unbinding Passkey in **My Logins** does not delete the passkeys, and deleting passkeys does not unbind (except that the page refuses to delete the last passkey of a linked account; see Manage). To use passkeys again after unbinding, link again from **My Logins**.
- **Residual risks.**
  - Concurrent requests across instances: within one process, finish and redeem calls for the same challenge or token are serialized (exactly one succeeds), and so are the credential-ID uniqueness and 20-passkey checks with the save, and rename or delete with a sign-in of the same passkey; a sign-in re-reads the passkey right before writing, so a deleted passkey is not resurrected and a rename or a newer counter is not rolled back. Across several Answer instances these races remain, because the consumed-challenge and uniqueness checks run before the transaction and `KVOperator.Set` is an upsert: a replayed finish request that races the first one on another instance can mint a second login token on PostgreSQL and SQLite (MySQL's unique index rejects one of them), two simultaneous redemptions of one token can both succeed, and concurrent registrations of one user can exceed the 20-passkey limit. A losing transaction that is detected is reported as `session_invalid` (or `credential_exists` for a duplicate registration).
  - User handle creation: two simultaneous first-time `register/begin` calls for the same user can overwrite each other's user handle (last writer wins); the losing ceremony fails with `session_invalid` and the user retries.
  - Two instances starting for the first time at the same moment can both create the ceremony secret (last writer wins); ceremonies begun on the losing instance fail with `session_invalid` and are retried.
  - Exploiting any of these needs the victim's own assertion, token or requests within milliseconds. The multi-instance cases cannot be closed inside the plugin because the core `KVOperator` has no conditional insert, compare-and-delete or row lock. Upstream proposal: add an insert-only `Set` (fail when the key exists) and a compare-and-delete `Del` (report whether a row was removed) to `KVOperator`.
  - Leaked bind state: the plugin cannot see who owns a state, and the core binds to the state's user without checking the browser session. Anyone who obtains a user's live bind state (5 minutes) can link their own passkey to that user's account. The plugin's own linking flow never puts a bind state in a URL: it fetches one right before each ceremony. The core's **My Logins > Connect** link still carries one; the bind view removes it from the address bar and history and never uses it, but it can still leak elsewhere (for example a proxy log). Every connector has the same exposure; the root fix is for the core `ConnectorRedirect` to compare the state's user with the signed-in user, or to pass the state's intent and owner to connectors.
  - Login CSRF inherent to the core state flow: the core state is not tied to the browser that started the flow, so an attacker can complete a sign-in with their own passkey and get a signed-out victim to open the resulting redirect URL, signing the victim in to the attacker's account. This is shared by every connector; closing it needs the core to bind the state to the browser session (for example with a cookie).

## KV storage layout

All rows live in `plugin_kv_storage` under the slug `passkey_connector`. The KV cache is disabled; every read goes to the database.

| Group | Key | Value |
| --- | --- | --- |
| `secret` | `ceremony_key` | base64url of 32 random bytes. The AES-256-GCM session key and the `state_proof` HMAC key are each derived from it with HKDF-SHA256. Created at start-up, or on first use if that fails. |
| `user_handle` | Answer user ID | base64url of 32 random bytes: the WebAuthn `user.id` and the core external ID. Created on the first `register/begin`, even if that ceremony is not finished. |
| `credential` | base64url(SHA-256(credential ID)) | JSON: `user_handle`, `name`, `created_at`, `last_used_at`, and the full go-webauthn `credential` record (public key, flags, counter, transports, attestation). Also the global credential-ID uniqueness index. |
| `user_credential:<handle>` | base64url(SHA-256(credential ID)) | `1` (membership, used for listing). A credential exists only if both rows exist. |
| `consumed_challenge` | challenge | Expiry (unix seconds). Purged after expiry (at most once per minute per process, up to 1000 rows per group per run). |
| `login_token` | base64url(SHA-256(token)) | JSON: `external_id`, `state`, `expires_at`. Deleted when redeemed, purged after expiry like `consumed_challenge`. |

Credential IDs are hashed so that keys fit the 128-character key column (raw IDs can be up to 1023 bytes).

## Limitations

- On sites with **Login required** enabled, the core route guard blocks anonymous access to `/connector-passkey-auth`, so passkey sign-in is not available there.
- An expired or unknown bind state is treated by the core as a login state: a link attempt that took longer than the core state lifetime ends as a sign-in attempt instead. Start the link again from **My Logins**.
- The page derives the UI base path from its own URL (everything before `/connector-passkey-auth`) and expects the API under the same prefix (`<base>/answer/api/v1`), as the core does for all connector URLs. `ui.base_url`, the API base path and the Site URL path must agree; a separate API base path is not supported by the core's connectors. Sub-path deployments are handled but have not been tested end to end.
- When the UI is served from a CDN (for example the `cdn-s3` or `cdn-aliyun` plugins) the plugin's module script is loaded in CORS mode; the CDN must send `Access-Control-Allow-Origin` for the site. See the CORS section of the [cdn-s3](../cdn-s3/README.md) and [cdn-aliyun](../cdn-aliyun/README.md) READMEs.
- The plugin API has no helper for the signed-in user, so the authenticated endpoints read the user ID that the core's auth middleware stores in the request context (an internal key). If a future core renames or reshapes it, those endpoints answer `401` and the plugin logs one error pointing at the cause.

### Proposed core changes

These would remove the remaining limitations and residual risks above:

- A public `plugin` helper that returns the signed-in user ID, and one that tells a connector whether a user is linked to it (so the server, not only the page, can refuse deleting the last passkey of a linked account).
- `ConnectorRedirect` comparing a bind state's user with the signed-in user, or passing the state's intent and owner to connectors, and tying states to the browser session to close login CSRF.
- An insert-only `Set` and a compare-and-delete `Del` on `KVOperator` for multi-instance deployments.
