# Passkey (WebAuthn) Connector Plugin

This plugin enables passwordless authentication for Answer using FIDO2/WebAuthn passkeys.

## Features

- **Passwordless Authentication**: Users can sign in using biometrics, security keys, or platform authenticators
- **Discoverable Credentials**: Supports usernameless login flow
- **Credential Management**: Users can register multiple passkeys and manage them from their profile
- **Secure by Default**: Requires user verification and uses single-use tokens with short TTLs

## Configuration

### Admin Configuration

Navigate to Admin Panel > Plugins > Passkey Connector to configure:

1. **RP Name** (Relying Party Name)
   - Display name shown during passkey registration
   - Example: "My Answer Community"
   - Maximum 255 characters

2. **RP ID** (Relying Party ID)
   - Must be a valid domain name matching your site's domain
   - Example: "example.com" or "answer.example.com"
   - Must match the domain users access (without protocol or port)
   - Maximum 253 characters

3. **Allowed Origins**
   - Comma-separated list of allowed origins
   - Must include the full URL with protocol
   - Example: "https://answer.example.com" or "https://example.com,https://www.example.com"
   - Each origin must be a valid HTTPS URL (HTTP only for localhost development)

4. **Attestation Type**
   - `none`: No attestation (default, recommended for most deployments)
   - `indirect`: Anonymized attestation
   - `direct`: Full attestation from authenticator

### RPID and Origins Explained

The RPID and origins must be configured correctly for WebAuthn to work:

- **RPID** is the domain scope for passkeys. Users can only use passkeys on the exact domain specified.
- **Origins** are the full URLs where the WebAuthn ceremony can occur.

Example configurations:

| Deployment | RPID | Origins |
|------------|------|---------|
| Production | `example.com` | `https://example.com` |
| Subdomain | `answer.example.com` | `https://answer.example.com` |
| Multiple domains | `example.com` | `https://example.com,https://www.example.com` |
| Development | `localhost` | `http://localhost:3000` |

## Security Considerations

### Rate Limiting

This plugin does not implement rate limiting at the application level. It is **strongly recommended** to configure rate limiting at your reverse proxy or load balancer:

Recommended limits:
- `/answer/api/v1/passkey/begin-login` - 10 requests/minute per IP
- `/answer/api/v1/passkey/finish-login` - 10 requests/minute per IP
- `/answer/api/v1/passkey/begin-register` - 5 requests/minute per authenticated user
- `/answer/api/v1/passkey/finish-register` - 5 requests/minute per authenticated user

Example nginx configuration:

```nginx
limit_req_zone $binary_remote_addr zone=passkey_auth:10m rate=10r/m;
limit_req_zone $cookie_session zone=passkey_reg:10m rate=5r/m;

location /answer/api/v1/passkey/begin-login {
    limit_req zone=passkey_auth burst=5 nodelay;
    proxy_pass http://backend;
}

location /answer/api/v1/passkey/begin-register {
    limit_req zone=passkey_reg burst=3 nodelay;
    proxy_pass http://backend;
}
```

### Session and Token Management

- **Session TTL**: 5 minutes (WebAuthn ceremony sessions)
- **Token TTL**: 2 minutes (one-time login tokens)
- Sessions and tokens are single-use and deleted after consumption
- Expired sessions/tokens should be cleaned up by your key-value store's TTL mechanism

**Important**: Configure your Answer KV store to support TTL-based expiration. If using Redis, this is automatic. For other stores, ensure expired keys are periodically cleaned up.

### Audit Logging

All passkey operations are logged for security monitoring:
- Registration attempts (success/failure)
- Authentication attempts (success/failure)
- Credential management operations
- Configuration errors

Monitor logs for:
- Repeated authentication failures (potential credential stuffing)
- Unusual registration patterns
- UserID extraction failures (may indicate Answer framework changes)

### Browser Compatibility

Passkeys require WebAuthn support:
- ✅ Chrome/Edge 67+
- ✅ Firefox 60+
- ✅ Safari 13+
- ✅ Mobile browsers (iOS 14+, Android 9+)

The plugin automatically detects browser support and shows appropriate error messages.

## Usage

### For Users

1. **Register a Passkey**:
   - Go to your Profile > Settings
   - Find the Passkey section
   - Click "Manage Passkeys"
   - Click "Add Passkey" and follow your browser's prompts

2. **Login with Passkey**:
   - On the login page, click "Sign in with Passkey"
   - Authenticate using your biometric or security key
   - You'll be logged in without entering a password

3. **Manage Passkeys**:
   - View all registered passkeys
   - See last used date for each passkey
   - Delete passkeys you no longer use
   - Test passkeys to verify they work

### For Developers

#### API Endpoints

**Public (Unauthenticated)**:
- `POST /answer/api/v1/passkey/begin-login` - Start login ceremony
- `POST /answer/api/v1/passkey/finish-login` - Complete login ceremony

**Authenticated**:
- `POST /answer/api/v1/passkey/begin-register` - Start registration ceremony
- `POST /answer/api/v1/passkey/finish-register` - Complete registration ceremony
- `GET /answer/api/v1/passkey/credentials` - List user's passkeys
- `DELETE /answer/api/v1/passkey/credentials/:id` - Delete a passkey

#### Storage Schema

The plugin uses Answer's KV storage with the following groups:
- `credentials`: User credential data
- `cred_index`: Credential ID to user mapping
- `user_map`: Answer user ID to external UUID mapping
- `user_map_rev`: Reverse mapping (external UUID to Answer user ID)
- `session`: WebAuthn ceremony sessions (TTL: 5 minutes)
- `token`: One-time login tokens (TTL: 2 minutes)

## Troubleshooting

### Common Issues

**"Passkey authentication is not properly configured"**
- Verify RPID matches your domain exactly
- Ensure origins include the full HTTPS URL
- Check browser console for WebAuthn errors

**"Authentication session expired"**
- Sessions expire after 5 minutes
- Don't refresh the page during passkey ceremony
- Try starting the process again

**"Not authenticated" error during registration**
- This may indicate the Answer framework's internal user context structure has changed
- Check server logs for "getUserIDFromContext" errors
- Report to plugin maintainers if issue persists

**Passkey works on one device but not another**
- Passkeys are device-specific (unless synced via cloud)
- Register a separate passkey for each device
- Or use a security key that works across devices

### Debug Mode

Enable debug logging in Answer configuration to see detailed passkey operation logs:

```yaml
log:
  level: debug
```

## Technical Details

### Implementation Notes

- Uses `go-webauthn/webauthn` library (v0.11.2)
- Requires resident key support (discoverable credentials)
- Enforces user verification for all ceremonies
- Stores credentials in Answer's plugin KV storage
- User ID extraction uses reflection (see limitations below)

### Known Limitations

1. **Reflection-Based User ID Extraction**: The plugin uses reflection to access Answer's internal user context. If Answer's internal structures change, passkey registration may break (login will continue to work). This is logged and monitored.

2. **No Built-in Rate Limiting**: Rate limiting must be implemented at the reverse proxy level.

3. **No Session Cleanup Job**: Relies on KV store's native TTL support for cleaning up expired sessions.

## Contributing

Report issues at: https://github.com/apache/answer-plugins/issues

## License

Licensed under the Apache License 2.0. See LICENSE file for details.
