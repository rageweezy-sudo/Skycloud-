import base64
import hashlib
import secrets
import time
import webbrowser
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

from account_privacy.core.credentials import CredentialVault
from account_privacy.core.models import Account, Provider

from .http import HTTPFailure, JSONClient
from .scan import Approval, DiscoveryError

_GOOGLE_USERINFO = "https://openidconnect.googleapis.com/v1/userinfo"


@dataclass(frozen=True, slots=True)
class OAuthProvider:
    authorization: str
    token: str
    identity: str
    read_scope: str
    send_scope: str
    connect_scopes: tuple[str, ...]

    @staticmethod
    def origin(url: str) -> str:
        parsed = urlsplit(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    @property
    def scan_destinations(self) -> tuple[str, ...]:
        return self.origin(self.token), self.origin(self.identity)

    @property
    def connect_destinations(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys((self.origin(self.authorization), *self.scan_destinations)))


def connect_destinations(provider: Provider, scope: str) -> tuple[str, ...]:
    spec = CLIENTS[provider]
    if provider == Provider.GMAIL and scope == spec.send_scope:
        return spec.origin(spec.authorization), spec.origin(spec.token), spec.origin(_GOOGLE_USERINFO)
    return spec.connect_destinations


CLIENTS = {
    Provider.GMAIL: OAuthProvider(
        "https://accounts.google.com/o/oauth2/v2/auth", "https://oauth2.googleapis.com/token",
        "https://gmail.googleapis.com/gmail/v1/users/me/profile",
        "https://www.googleapis.com/auth/gmail.metadata", "https://www.googleapis.com/auth/gmail.send", (),
    ),
    Provider.GRAPH: OAuthProvider(
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "https://graph.microsoft.com/v1.0/me?$select=mail,userPrincipalName",
        "https://graph.microsoft.com/Mail.ReadBasic", "https://graph.microsoft.com/Mail.Send",
        ("offline_access", "https://graph.microsoft.com/User.Read"),
    ),
}


@dataclass(frozen=True, slots=True)
class ClientSettings:
    client_id: str
    client_secret: str | None = field(default=None, repr=False)


@dataclass(slots=True, repr=False)
class OAuthSession:
    account: Account
    settings: ClientSettings
    vault: CredentialVault
    scope: str
    http: JSONClient = field(default_factory=JSONClient)
    _access: str | None = field(default=None, init=False)
    _expiry: float = field(default=0, init=False)

    def _reference(self) -> str:
        return f"oauth/{self.account.id}/{self.scope}"

    def _token(self, payload: dict[str, str], approval: Approval) -> dict:
        if self.settings.client_secret:
            payload["client_secret"] = self.settings.client_secret
        return self.http.request(
            CLIENTS[self.account.provider].token, approval, data=urlencode(payload).encode("ascii"),
            content_type="application/x-www-form-urlencoded", method="POST",
        )

    def _accept(self, response: dict) -> str:
        access = response.get("access_token")
        expires = response.get("expires_in", 300)
        if not isinstance(access, str) or not access or type(expires) is not int:
            raise DiscoveryError("The provider did not return a usable authorization")
        self._access = access
        self._expiry = time.monotonic() + max(1, expires - 60)
        return access

    def access_token(self, approval: Approval) -> str:
        self._require_account(approval)
        if self._access is not None and self._expiry > time.monotonic():
            return self._access
        refresh = self.vault.read(self._reference())
        if not refresh:
            raise DiscoveryError("Connect this email permission first")
        payload = {
            "grant_type": "refresh_token", "refresh_token": refresh.decode("utf-8"),
            "client_id": self.settings.client_id,
        }
        if self.account.provider == Provider.GRAPH:
            payload["scope"] = self.scope
        try:
            response = self._token(payload, approval)
        except HTTPFailure as error:
            if error.status in (400, 401):
                raise DiscoveryError("Reconnect this email permission") from None
            raise
        access = self._accept(response)
        if isinstance(response.get("refresh_token"), str) and response["refresh_token"]:
            self.vault.write(self._reference(), response["refresh_token"].encode("utf-8"))
        return access

    def _require_account(self, approval: Approval) -> None:
        if approval.account_id != self.account.id or approval.closed:
            raise DiscoveryError("Authorization is for a different account or has ended")

    def connect(self, approval: Approval, open_browser=webbrowser.open) -> None:
        spec = CLIENTS[self.account.provider]
        approval.require("connect", self.account.id, self.account.provider, self.scope)
        if self.scope not in (spec.read_scope, spec.send_scope):
            raise DiscoveryError("This authorization scope is unsupported")
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode().rstrip("=")
        result = {}

        class Callback(BaseHTTPRequestHandler):
            timeout = 2

            def log_message(self, *args):
                pass

            def do_GET(self):
                parsed = urlsplit(self.path)
                params = parse_qs(parsed.query)
                valid = parsed.path == "/oauth/callback" and secrets.compare_digest(
                    params.get("state", [""])[0].encode("utf-8"), state.encode("ascii")
                )
                if valid:
                    result["code"] = params.get("code", [""])[0]
                content = b"Return to Account Privacy to continue." if valid else b"Invalid authorization callback."
                self.send_response(200 if valid else 400)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)

        with HTTPServer(("127.0.0.1", 0), Callback) as server:
            server.timeout = 0.25
            loopback = "localhost" if self.account.provider == Provider.GRAPH else "127.0.0.1"
            redirect = f"http://{loopback}:{server.server_port}/oauth/callback"
            scopes = [self.scope, *spec.connect_scopes]
            google_send = self.account.provider == Provider.GMAIL and self.scope == spec.send_scope
            if google_send:
                scopes.extend(("openid", "email"))
            query = {
                "client_id": self.settings.client_id, "redirect_uri": redirect,
                "response_type": "code", "scope": " ".join(scopes), "state": state,
                "code_challenge": challenge, "code_challenge_method": "S256", "login_hint": self.account.email,
            }
            if self.account.provider == Provider.GMAIL:
                query.update(access_type="offline", prompt="consent")
            url = spec.authorization + "?" + urlencode(query)
            approval.require_destination(url)
            if not open_browser(url):
                raise DiscoveryError("Could not open the authorization page")
            deadline = time.monotonic() + 180
            while not result and not approval.closed and time.monotonic() < deadline:
                server.handle_request()
        if approval.closed or not result.get("code"):
            raise DiscoveryError("Authorization was cancelled or expired")
        response = self._token({
            "grant_type": "authorization_code", "client_id": self.settings.client_id,
            "code": result["code"], "code_verifier": verifier, "redirect_uri": redirect,
        }, approval)
        token = response.get("access_token")
        if not isinstance(token, str) or not token:
            raise DiscoveryError("The provider did not return a usable authorization")
        identity = self.http.request(_GOOGLE_USERINFO if google_send else spec.identity, approval, token=token)
        actual = identity.get("emailAddress") or identity.get("mail") or identity.get("userPrincipalName")
        if google_send and identity.get("email_verified") is True:
            actual = identity.get("email")
        if not isinstance(actual, str) or actual.casefold() != self.account.email.casefold():
            raise DiscoveryError("The signed-in account does not match the approved email address")
        refresh = response.get("refresh_token")
        if not isinstance(refresh, str) or not refresh:
            raise DiscoveryError("The provider did not grant reusable authorization")
        self.vault.write(self._reference(), refresh.encode("utf-8"))
        self._accept(response)
