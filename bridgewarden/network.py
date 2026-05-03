"""HTTP helpers used by the optional network backends."""

import urllib.request
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse


class NetworkError(RuntimeError):
    """Raised for network failures or policy violations."""

    pass


@dataclass(frozen=True)
class HttpClient:
    """Minimal HTTP client with a fixed timeout."""

    timeout_seconds: float = 10.0

    def get(self, url: str, max_bytes: int) -> bytes:
        """Fetch bytes from a URL with size limits and redirect checks."""

        if max_bytes <= 0:
            raise NetworkError("max_bytes must be positive")

        request = urllib.request.Request(
            url,
            headers={"User-Agent": "BridgeWarden/0.1"},
        )
        opener = urllib.request.build_opener(_SameHostRedirectHandler)
        with opener.open(request, timeout=self.timeout_seconds) as response:
            final_url = response.geturl()
            if urlparse(final_url).netloc != urlparse(url).netloc:
                raise NetworkError("redirected to different host")
            return _read_limited(response, max_bytes)


@dataclass(frozen=True)
class WebFetcher:
    """Callable adapter that returns decoded text for web fetches."""

    http_client: HttpClient

    def __call__(self, url: str, max_bytes: int) -> str:
        """Fetch and decode a URL to UTF-8 text."""

        payload = self.http_client.get(url, max_bytes)
        return payload.decode("utf-8", errors="replace")


class _SameHostRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject cross-host redirects before urllib follows them."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        resolved_url = urljoin(req.full_url, newurl)
        if urlparse(resolved_url).netloc != urlparse(req.full_url).netloc:
            raise NetworkError("redirected to different host")
        return super().redirect_request(req, fp, code, msg, headers, resolved_url)


def _read_limited(response: urllib.request.addinfourl, max_bytes: int) -> bytes:
    """Read up to max_bytes from a response stream."""

    buffer = bytearray()
    remaining = max_bytes
    while remaining > 0:
        chunk = response.read(min(8192, remaining))
        if not chunk:
            break
        buffer.extend(chunk)
        remaining -= len(chunk)
    return bytes(buffer)
