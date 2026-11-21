import base64
import hashlib
import types
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlencode, urlsplit

from account_privacy.core.models import Account, Provider
from account_privacy.discovery.oauth import CLIENTS, ClientSettings, OAuthSession, connect_destinations
from account_privacy.discovery.scan import Approval, DiscoveryError


class FakeCallbackServer:
    server_port = 49331
    timeout = 0

    def __init__(self, handler):
        self.handler = handler
        self.path = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def handle_request(self):
        request = types.SimpleNamespace(
            path=self.path, send_response=Mock(), send_header=Mock(), end_headers=Mock(), wfile=Mock()
        )
        self.handler.do_GET(request)


class OAuthTests(unittest.TestCase):
    def test_pkce_and_identity_check_gate_token_persistence(self):
        account = Account("a", "owner@example.test", Provider.GMAIL)
        provider = CLIENTS[account.provider]
        for claimed in ("owner@example.test", "wrong@example.test"):
            with self.subTest(claimed=claimed):
                approval = Approval("connect", "a", Provider.GMAIL, provider.read_scope, connect_destinations(Provider.GMAIL, provider.read_scope))
                vault = Mock()
                http = Mock()
                http.request.side_effect = [
                    {"access_token": "synthetic-access", "refresh_token": "synthetic-refresh", "expires_in": 300},
                    {"emailAddress": claimed},
                ]
                session = OAuthSession(account, ClientSettings("synthetic-client"), vault, provider.read_scope, http)
                server = None
                def make_server(address, handler):
                    nonlocal server
                    self.assertEqual(address[0], "127.0.0.1")
                    server = FakeCallbackServer(handler)
                    return server
                def browser(url):
                    params = parse_qs(urlsplit(url).query)
                    self.assertEqual(params["code_challenge_method"], ["S256"])
                    self.assertEqual(params["login_hint"], [account.email])
                    self.challenge = params["code_challenge"][0]
                    server.path = "/oauth/callback?" + urlencode({"code": "test-code", "state": params["state"][0]})
                    return True
                with patch("account_privacy.discovery.oauth.HTTPServer", side_effect=make_server):
                    if claimed == account.email:
                        session.connect(approval, browser)
                        vault.write.assert_called_once()
                    else:
                        with self.assertRaises(DiscoveryError):
                            session.connect(approval, browser)
                        vault.write.assert_not_called()
                form = parse_qs(http.request.call_args_list[0].kwargs["data"].decode())
                hashed = base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"][0].encode()).digest()).decode().rstrip("=")
                self.assertEqual(hashed, self.challenge)
