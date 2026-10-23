"""OAuth code/PKCE client. Identity comes from userinfo, never decoded ID tokens."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import secrets
import time
from dataclasses import dataclass
from typing import Callable, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit, quote
from urllib.request import Request, build_opener, HTTPRedirectHandler

DEFAULT_SCOPES = ("openid", "profile", "offline_access")


class YeboIDError(Exception):
    def __init__(self, code: str, status: int = 502):
        # Never echo response bodies, credentials, callback codes or tokens.
        super().__init__(f"YeboID: {code}")
        self.code, self.status = code, status


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _transport(method: str, url: str, headers: dict, body: bytes | None, timeout: float):
    try:
        with build_opener(_NoRedirect()).open(Request(url, body, headers, method=method), timeout=timeout) as res:
            return res.status, res.read()
    except HTTPError as error:
        return error.code, error.read()
    except (URLError, TimeoutError, OSError) as error:
        raise YeboIDError("transport_error", 503) from error


def _https(value: str) -> str:
    if not isinstance(value, str):
        raise YeboIDError("invalid_https_url", 400)
    u = urlsplit(value)
    if u.scheme != "https" or not u.hostname or u.username or u.password or u.fragment:
        raise YeboIDError("invalid_https_url", 400)
    return value


def _pkce(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class Authorization:
    url: str
    state: str
    verifier: str
    created_at: float


class YeboID:
    def __init__(self, client_id: str, redirect_uri: str, *, issuer="https://api.yeboid.com",
                 client_secret: str | None = None, scopes: Iterable[str] = DEFAULT_SCOPES,
                 timeout: float = 10, transport: Callable = _transport):
        self.issuer = _https(issuer).rstrip("/")
        parsed = urlsplit(self.issuer)
        callback = urlsplit(redirect_uri)
        if parsed.path or parsed.query or not client_id or timeout <= 0 or not math.isfinite(timeout):
            raise YeboIDError("invalid_configuration", 400)
        if not callback.scheme or callback.fragment or callback.username or callback.password or callback.query:
            raise YeboIDError("invalid_callback", 400)
        if callback.scheme == "http" and callback.hostname not in ("127.0.0.1", "localhost", "::1"):
            raise YeboIDError("insecure_callback", 400)
        self.client_id, self.redirect_uri, self.client_secret = client_id, redirect_uri, client_secret
        self.scopes = tuple(dict.fromkeys(scopes))
        if "openid" not in self.scopes or any(not s or any(c.isspace() for c in s) for s in self.scopes):
            raise YeboIDError("invalid_scope", 400)
        self.timeout, self.transport = timeout, transport
        self._metadata = None

    def _request(self, method, url, *, form=None, token=None, empty=False):
        headers = {"Accept": "application/json"}
        body = None
        if form is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            body = urlencode(form).encode()
        if token is not None:
            if not token or any(c.isspace() for c in token):
                raise YeboIDError("invalid_token", 401)
            headers["Authorization"] = f"Bearer {token}"
        status, raw = self.transport(method, url, headers, body, self.timeout)
        if not 200 <= status < 300:
            code = f"http_{status}"
            try:
                candidate = json.loads(raw).get("error")
                if isinstance(candidate, str) and candidate.replace("_", "").isalnum():
                    code = candidate
            except (ValueError, AttributeError):
                pass
            raise YeboIDError(code, status)
        if empty:
            return None
        try:
            data = json.loads(raw)
        except ValueError as error:
            raise YeboIDError("invalid_response") from error
        if not isinstance(data, dict):
            raise YeboIDError("invalid_response")
        return data

    def discovery(self):
        if self._metadata is None:
            data = self._request("GET", self.issuer + "/.well-known/openid-configuration")
            if data.get("issuer") != self.issuer or "S256" not in data.get("code_challenge_methods_supported", []):
                raise YeboIDError("invalid_discovery")
            for key in ("authorization_endpoint", "token_endpoint", "userinfo_endpoint", "revocation_endpoint", "introspection_endpoint"):
                _https(data.get(key, ""))
            if not set(self.scopes).issubset(data.get("scopes_supported", [])):
                raise YeboIDError("invalid_scope", 400)
            self._metadata = data
        return self._metadata

    def check_registration(self):
        """Public preflight; any error must be surfaced, never assumed to pass."""
        data = self._request("GET", self.issuer + "/oauth/clients/" + quote(self.client_id, safe="") + "/configuration")
        if data.get("client_id") != self.client_id or self.redirect_uri not in data.get("redirect_uris", []):
            raise YeboIDError("invalid_registration", 400)
        if not set(self.scopes).issubset(data.get("scopes", [])):
            raise YeboIDError("invalid_scope", 400)
        return data

    def authorize(self) -> Authorization:
        self.check_registration()
        verifier, state = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        query = urlencode(dict(response_type="code", client_id=self.client_id, redirect_uri=self.redirect_uri,
                               scope=" ".join(self.scopes), state=state, code_challenge=_pkce(verifier),
                               code_challenge_method="S256"))
        endpoint = self.discovery()["authorization_endpoint"]
        return Authorization(endpoint + ("&" if "?" in endpoint else "?") + query, state, verifier, time.time())

    def exchange(self, callback_url: str, pending: Authorization):
        """The web app MUST atomically consume pending from its server-side session first."""
        uri = urlsplit(callback_url)
        if uri._replace(query="").geturl() != self.redirect_uri or uri.fragment or not 0 <= time.time() - pending.created_at <= 600:
            raise YeboIDError("invalid_callback", 400)
        q = parse_qs(uri.query, keep_blank_values=True)
        if any(len(v) != 1 for v in q.values()) or not hmac.compare_digest(q.get("state", [""])[0], pending.state):
            raise YeboIDError("state_mismatch", 400)
        if "error" in q:
            raise YeboIDError("authorization_denied", 401)
        code = q.get("code", [""])[0]
        if not code:
            raise YeboIDError("missing_code", 400)
        return self._tokens(dict(grant_type="authorization_code", code=code, redirect_uri=self.redirect_uri,
                                 code_verifier=pending.verifier))

    def _client_form(self, form):
        values = {**form, "client_id": self.client_id}
        if self.client_secret:
            values["client_secret"] = self.client_secret
        return values

    def _tokens(self, form):
        data = self._request("POST", self.discovery()["token_endpoint"], form=self._client_form(form))
        expiry = data.get("expires_in")
        if (not isinstance(data.get("access_token"), str) or not data["access_token"] or
            str(data.get("token_type")).lower() != "bearer" or type(expiry) not in (int, float) or
            not math.isfinite(expiry) or expiry <= 0 or not isinstance(data.get("scope"), str) or
            (form.get("grant_type") == "refresh_token" and not data.get("refresh_token"))):
            raise YeboIDError("invalid_token_response")
        return data

    def refresh(self, refresh_token: str):
        """Serialize per session across workers; durably replace the rotated token before reuse. No retry."""
        return self._tokens(dict(grant_type="refresh_token", refresh_token=refresh_token))

    def userinfo(self, access_token: str):
        data = self._request("GET", self.discovery()["userinfo_endpoint"], token=access_token)
        if not isinstance(data.get("sub"), str) or not data["sub"]:
            raise YeboIDError("invalid_userinfo")
        return data

    def introspect(self, token: str):
        return self._request("POST", self.discovery()["introspection_endpoint"],
                             form=self._client_form(dict(token=token, token_type_hint="access_token")))

    def verify_access_token(self, token: str, required_scopes: Iterable[str] = ()):
        """Online validation, bound to this client, with fresh revocation state. No unverified JWT decoding."""
        data = self.introspect(token)
        expiry = data.get("exp")
        if (data.get("active") is not True or data.get("client_id") != self.client_id or
            str(data.get("token_type")).lower() != "bearer" or not isinstance(data.get("sub"), str) or not data["sub"] or
            type(expiry) not in (int, float) or not math.isfinite(expiry) or expiry <= time.time()):
            raise YeboIDError("invalid_token", 401)
        if not isinstance(data.get("scope", ""), str):
            raise YeboIDError("invalid_response")
        if not set(required_scopes).issubset(data.get("scope", "").split()):
            raise YeboIDError("insufficient_scope", 403)
        return data

    def revoke(self, refresh_token: str):
        self._request("POST", self.discovery()["revocation_endpoint"], empty=True,
                      form=self._client_form(dict(token=refresh_token, token_type_hint="refresh_token")))
