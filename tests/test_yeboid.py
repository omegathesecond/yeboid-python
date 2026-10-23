import json
import time
import unittest
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch
from yeboid import YeboID, YeboIDError, _pkce


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.response = {}
        self.status = 200
        self.client = YeboID("app", "http://localhost:8000/callback", transport=self.transport)

    def transport(self, method, url, headers, body, timeout):
        self.calls.append((method, url, headers, parse_qs(body.decode()) if body else {}))
        if url.endswith('/configuration') and self.status == 200:
            return 200, json.dumps(dict(client_id='app',redirect_uris=['http://localhost:8000/callback'],scopes=['openid','profile','offline_access'])).encode()
        if url.endswith("openid-configuration"):
            data = dict(issuer="https://api.yeboid.com", code_challenge_methods_supported=["S256"],
                        scopes_supported=["openid", "profile", "offline_access"])
            for name, path in [("authorization", "authorize"), ("token", "token"), ("userinfo", "userinfo"),
                               ("revocation", "revoke"), ("introspection", "introspect")]:
                data[name + "_endpoint"] = ("https://yeboid.com" if name == "authorization" else "https://api.yeboid.com") + "/oauth/" + path
            return 200, json.dumps(data).encode()
        return self.status, json.dumps(self.response).encode()

    def test_pkce_rfc7636_vector(self):
        self.assertEqual(_pkce("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")

    def test_authorization_and_exchange(self):
        pending = self.client.authorize()
        q = parse_qs(urlsplit(pending.url).query)
        self.assertTrue(pending.url.startswith("https://yeboid.com/oauth/authorize?"))
        self.assertEqual(q["code_challenge"], [_pkce(pending.verifier)])
        self.response = dict(access_token="access", token_type="Bearer", expires_in=900, scope="openid")
        result = self.client.exchange(f"http://localhost:8000/callback?code=ok&state={pending.state}", pending)
        self.assertEqual(result["scope"], "openid")
        self.assertNotIn("client_secret", self.calls[-1][3])
        self.assertEqual(self.calls[-1][3]["code_verifier"], [pending.verifier])

    def test_callback_rejection_before_exchange(self):
        pending = self.client.authorize()
        for url in [f"http://evil/callback?code=x&state={pending.state}",
                    "http://localhost:8000/callback?code=x&state=wrong",
                    f"http://localhost:8000/callback?code=x&code=y&state={pending.state}",
                    f"http://localhost:8000/callback?error=access_denied&state={pending.state}"]:
            with self.assertRaises(YeboIDError):
                self.client.exchange(url, pending)
        self.assertEqual(len(self.calls), 2)
        with patch("yeboid.time.time", return_value=pending.created_at + 601):
            with self.assertRaises(YeboIDError):
                self.client.exchange(f"http://localhost:8000/callback?code=x&state={pending.state}", pending)

    def test_access_rejects_refresh_id_wrong_client_expired_and_missing_scope(self):
        valid = dict(active=True, client_id="app", sub="person", token_type="Bearer", exp=time.time() + 900, scope="openid profile")
        self.response = valid
        self.assertEqual(self.client.verify_access_token("access", ["profile"])["sub"], "person")
        for change in [dict(active=False), dict(token_type=None), dict(client_id="other"), dict(exp=0), dict(exp=True), dict(sub="")]:
            self.response = {**valid, **change}
            with self.assertRaises(YeboIDError) as e:
                self.client.verify_access_token("token")
            self.assertEqual(e.exception.status, 401)
        self.response = valid
        with self.assertRaises(YeboIDError) as e:
            self.client.verify_access_token("access", ["email"])
        self.assertEqual(e.exception.status, 403)

    def test_failures_never_become_inactive_or_empty_success(self):
        self.status, self.response = 503, {"error": "unavailable"}
        with self.assertRaises(YeboIDError) as e:
            self.client.verify_access_token("access")
        self.assertEqual(e.exception.status, 503)
        self.status, self.response = 200, dict(access_token="x", expires_in=-1, token_type="Bearer", scope="openid")
        with self.assertRaises(YeboIDError):
            self.client.refresh("rotate-once")

    def test_refresh_and_revoke_do_not_retry_or_expand_scope(self):
        self.response = dict(access_token="x", refresh_token="new", expires_in=900, token_type="Bearer", scope="openid")
        self.client.refresh("old")
        self.assertNotIn("scope", self.calls[-1][3])
        self.client.revoke("new")
        self.assertTrue(self.calls[-1][1].endswith("/oauth/revoke"))

    def test_invalid_configuration(self):
        for kwargs in [dict(issuer="http://evil"), dict(scopes=["profile"]), dict(timeout=0)]:
            with self.assertRaises(YeboIDError):
                YeboID("app", "http://localhost/callback", **kwargs)

    def test_missing_registration_endpoint_is_error(self):
        self.status = 404
        with self.assertRaises(YeboIDError):
            self.client.check_registration()


if __name__ == "__main__":
    unittest.main()
