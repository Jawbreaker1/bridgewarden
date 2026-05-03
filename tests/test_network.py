import unittest
import urllib.request

from bridgewarden.network import NetworkError, _SameHostRedirectHandler


class NetworkTests(unittest.TestCase):
    def test_redirect_handler_rejects_cross_host_redirects_before_following(self) -> None:
        handler = _SameHostRedirectHandler()
        request = urllib.request.Request("https://example.com/start")

        with self.assertRaises(NetworkError):
            handler.redirect_request(
                request,
                None,
                302,
                "Found",
                {},
                "https://127.0.0.1/private",
            )

    def test_redirect_handler_allows_same_host_redirects(self) -> None:
        handler = _SameHostRedirectHandler()
        request = urllib.request.Request("https://example.com/start")

        redirected = handler.redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "https://example.com/next",
        )

        self.assertEqual(redirected.full_url, "https://example.com/next")

    def test_redirect_handler_allows_relative_redirects(self) -> None:
        handler = _SameHostRedirectHandler()
        request = urllib.request.Request("https://example.com/start")

        redirected = handler.redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "/next",
        )

        self.assertEqual(redirected.full_url, "https://example.com/next")
