"""HTTP helpers used by the optional network backends."""

import urllib.request
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse


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
        with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
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
