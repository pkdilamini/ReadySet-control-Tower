"""Tests for the basic security layer. Run from the security-layer folder:  python3 -I -m unittest discover -s tests -v"""
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))                  # so `control_tower` imports from the folder above

from control_tower import security                          # noqa: E402
from control_tower.webserver import make_server             # noqa: E402


class FakeHandler:
    """Just enough of a request handler for guard(): headers, command, path, and a place to record the refusal."""
    def __init__(self, command, path, headers):
        self.command, self.path, self.headers = command, path, headers
        self.sent = None

    def _json(self, status, obj):
        self.sent = status


class GuardUnitTests(unittest.TestCase):
    TOKEN = "secret-token-123"

    def check(self, command, path, headers):
        h = FakeHandler(command, path, headers)
        return security.guard(h, self.TOKEN), h.sent

    def test_localhost_with_token_is_allowed(self):
        ok, _ = self.check("GET", "/api/state", {"Host": "localhost:8010", "X-Control-Token": self.TOKEN})
        self.assertTrue(ok)

    def test_127_0_0_1_is_allowed(self):
        ok, _ = self.check("GET", "/api/state", {"Host": "127.0.0.1:8010", "X-Control-Token": self.TOKEN})
        self.assertTrue(ok)

    def test_foreign_host_is_refused_even_with_token(self):          # DNS rebinding
        ok, status = self.check("GET", "/api/state", {"Host": "evil.example:8010", "X-Control-Token": self.TOKEN})
        self.assertFalse(ok)
        self.assertEqual(status, 403)

    def test_missing_host_is_refused(self):
        ok, status = self.check("GET", "/", {})
        self.assertFalse(ok)
        self.assertEqual(status, 403)

    def test_api_get_without_token_is_refused(self):
        ok, status = self.check("GET", "/api/findings", {"Host": "localhost"})
        self.assertFalse(ok)
        self.assertEqual(status, 401)

    def test_wrong_token_is_refused(self):
        ok, status = self.check("GET", "/api/findings", {"Host": "localhost", "X-Control-Token": "guess"})
        self.assertFalse(ok)
        self.assertEqual(status, 401)

    def test_post_without_token_is_refused(self):
        ok, status = self.check("POST", "/api/reviews", {"Host": "localhost", "Origin": "http://localhost:8010"})
        self.assertFalse(ok)
        self.assertEqual(status, 401)

    def test_health_needs_no_token(self):
        ok, _ = self.check("GET", "/api/health", {"Host": "localhost"})
        self.assertTrue(ok)

    def test_static_page_needs_no_token(self):
        ok, _ = self.check("GET", "/", {"Host": "localhost"})
        self.assertTrue(ok)

    def test_new_tokens_are_long_and_different(self):
        a, b = security.new_token(), security.new_token()
        self.assertGreaterEqual(len(a), 30)
        self.assertNotEqual(a, b)


class ServerIntegrationTests(unittest.TestCase):
    """Start the real server on a free port and send it real HTTP requests."""

    @classmethod
    def setUpClass(cls):
        cls.httpd = make_server(host="127.0.0.1", port=0, quiet=True)
        cls.port = cls.httpd.server_address[1]
        cls.token = cls.httpd.token
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def request(self, method, path, host=None, token=None, origin=None):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", method=method,
                                     data=b"{}" if method == "POST" else None)
        if host is not None:
            req.add_header("Host", host)
        if token is not None:
            req.add_header("X-Control-Token", token)
        if origin is not None:
            req.add_header("Origin", origin)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers)

    def test_health_is_open(self):
        status, _ = self.request("GET", "/api/health", host=f"localhost:{self.port}")
        self.assertEqual(status, 200)

    def test_api_without_token_is_401(self):
        status, _ = self.request("GET", "/api/state", host=f"localhost:{self.port}")
        self.assertEqual(status, 401)

    def test_api_with_token_is_200(self):
        status, _ = self.request("GET", "/api/state", host=f"localhost:{self.port}", token=self.token)
        self.assertEqual(status, 200)

    def test_rebinding_host_is_403_even_with_token(self):
        status, _ = self.request("GET", "/api/state", host="evil.example", token=self.token)
        self.assertEqual(status, 403)

    def test_cross_site_post_is_refused(self):
        status, _ = self.request("POST", "/api/reviews", host=f"localhost:{self.port}",
                                 origin="http://evil.example")
        self.assertIn(status, (401, 403))

    def test_post_without_token_is_401(self):
        status, _ = self.request("POST", "/api/reviews", host=f"localhost:{self.port}",
                                 origin=f"http://localhost:{self.port}")
        self.assertEqual(status, 401)

    def test_no_wildcard_cors_header(self):
        _, headers = self.request("GET", "/api/health", host=f"localhost:{self.port}")
        self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_page_loads_without_token(self):
        status, _ = self.request("GET", "/", host=f"localhost:{self.port}")
        self.assertEqual(status, 200)


if __name__ == "__main__":
    unittest.main()
