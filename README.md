# YeboID for Python

PKCE sign-in, token exchange/rotation, userinfo, revocation and **online access-token verification** for Python 3.10+. No runtime dependencies. Use with FastAPI, Flask, Django or background tools. A coding agent acts for a consenting human; it cannot bypass login or mint client-credentials tokens.

## Install from the source release

```sh
python -m pip install 'yeboid-python @ git+https://github.com/omegathesecond/yeboid-python.git@v0.1.0'
```

This is source installation, not a claim that a PyPI package exists. Read [AGENTS.md](AGENTS.md) and [platform selection](https://docs.yeboid.com/platforms).

## Protect a Python API

```python
import os
from yeboid import YeboID, YeboIDError

identity = YeboID(
    client_id=os.environ['YEBOID_CLIENT_ID'],
    redirect_uri=os.environ['YEBOID_REDIRECT_URI'],
    client_secret=os.environ.get('YEBOID_CLIENT_SECRET'),  # server only, optional
)

# Extract the Bearer access token from the incoming request.
# Run synchronous network calls in the framework's thread pool for async routes.
claims = identity.verify_access_token(access_token, required_scopes=['openid', 'profile'])
yeboid_user_id = claims['sub']
# Now separately enforce ownership of the product resource.
```

`verify_access_token` uses YeboID introspection on each call: it checks active state, the exact client, Bearer token purpose, expiry, subject and actual granted scopes. ID tokens and opaque refresh tokens are rejected. No local JWT decoding is trusted. Your API and frontend must use the same OAuth client ID. The dependency needs network availability; propagate failures.

Catch `YeboIDError`: map `invalid_token` to HTTP 401, `insufficient_scope` to 403, and upstream/transport/malformed-response errors to your normal 5xx error channel. An upstream `invalid_client` means your server configuration failed; do not treat it as anonymous success. Never return raw upstream bodies or credentials. [FastAPI example](examples/fastapi_app.py).

## Server-rendered sign-in

```python
pending = identity.authorize()
# Store pending in an encrypted SERVER-SIDE session, bound to this browser.
# Redirect the browser to pending.url. Do not expose pending.verifier.

# On callback: atomically pop pending from that same server-side session FIRST.
tokens = identity.exchange(full_callback_url, pending)
user = identity.userinfo(tokens['access_token'])
```

The callback rejects mismatched state, wrong routes, duplicate parameters, denials and transactions older than ten minutes. Only save `user['sub']` as `yeboid_user_id` in the product DB. Do not store profile/phone/email/KYC copies. Do not use client-side signed cookies to hold PKCE state or tokens; encryption is required for confidential session data. Protect app session cookies with Secure, HttpOnly and appropriate SameSite/CSRF settings.

## Rotation and logout

```python
# Hold a session/distributed lock across read -> refresh -> durable write.
new_tokens = identity.refresh(stored_refresh_token)
# Atomically save new_tokens (including refresh_token) before releasing the lock.

identity.revoke(new_tokens['refresh_token'])
# Clear your server-side app session only after successful revocation.
```

Refresh does not send extra scopes and is never retried automatically. If rotation or durable storage is uncertain after an error, start a new login; do not reuse the old refresh token. Revocation is app-specific; the browser's shared YeboID SSO cookie remains.

## Registration and checks

Register the callback exactly in [Developer Apps](https://yeboid.com/developer/apps). Defaults request `openid profile offline_access`; extra scopes require explicit registration and new consent. Discovery validates supported scopes. `identity.authorize()` checks the public registration endpoint before generating a URL. You can also run `identity.check_registration()` separately. Mismatched callbacks/scopes and unavailable APIs raise errors; fix the registration explicitly instead of bypassing preflight.

```sh
python -m unittest discover -s tests -v
python -m pip wheel --no-deps . -w dist
```

Tests mock the protocol. They do not prove a real login, app approval or live token lifecycle. CI runs separately in this repository.
