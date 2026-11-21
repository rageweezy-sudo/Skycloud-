import http.client
import json
import ssl
import urllib.error
import urllib.request

from .scan import Approval, DiscoveryError


class HTTPFailure(DiscoveryError):
    def __init__(self, status: int | None, retry_after: int | None = None) -> None:
        super().__init__(f"Provider returned HTTP {status}" if status is not None else "Provider connection failed")
        self.status = status
        self.retry_after = retry_after


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class JSONClient:
    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirects(), urllib.request.HTTPSHandler(context=ssl.create_default_context())
        )

    def request(
        self, url: str, approval: Approval, *, token: str | None = None, data: bytes | None = None,
        content_type: str = "application/json", method: str = "GET", retry_reads: bool = True,
        headers: dict[str, str] | None = None,
    ) -> dict:
        request_headers = {"Accept": "application/json", **(headers or {})}
        if token is not None:
            request_headers["Authorization"] = f"Bearer {token}"
        if data is not None:
            request_headers["Content-Type"] = content_type
        max_attempts = 4 if method == "GET" and retry_reads else 1
        for attempt in range(max_attempts):
            approval.require_destination(url)
            if not url.startswith("https://"):
                raise DiscoveryError("Provider requests require HTTPS")
            request = urllib.request.Request(url, data=data, headers=request_headers, method=method)
            try:
                with self._opener.open(request, timeout=20) as response:
                    body = response.read(8 * 1024 * 1024 + 1)
                    if len(body) > 8 * 1024 * 1024:
                        raise DiscoveryError("Provider response was too large")
                    decoded = json.loads(body) if body else {}
                    if not isinstance(decoded, dict):
                        raise DiscoveryError("Provider response has an unexpected format")
                    return decoded
            except urllib.error.HTTPError as error:
                status = error.code
                retry_after = error.headers.get("Retry-After", "")
                retry_after = min(int(retry_after), 60) if retry_after.isdecimal() and len(retry_after) < 6 else None
                error.close()
                failure = HTTPFailure(status, retry_after)
                transient = status in (429, 500, 502, 503, 504)
            except (OSError, http.client.HTTPException):
                failure = HTTPFailure(None)
                transient = True
            except (ValueError, UnicodeError):
                raise DiscoveryError("Provider response was invalid") from None
            if not transient or attempt + 1 == max_attempts:
                raise failure from None
            approval.wait(failure.retry_after if failure.retry_after is not None else 2 ** attempt)
        raise AssertionError("Unreachable request state")
