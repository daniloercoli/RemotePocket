"""Security headers must survive errors, redirects, static files and shutdown."""

from fastapi.testclient import TestClient
import pytest


@pytest.mark.parametrize("scheme", ["http", "https"])
@pytest.mark.parametrize(
    "case",
    ["page", "static", "redirect", "401", "404", "422", "429", "500", "shutdown"],
)
def test_security_headers_cover_all_http_response_paths(client, scheme, case):
    @client.app.get("/test/unexpected-failure")
    def fail():
        raise RuntimeError("private diagnostic")

    with TestClient(client.app, base_url=scheme + "://testserver") as browser:
        if case == "422":
            response = browser.post("/api/auth/login", json={})
        elif case == "429":
            settings = client.app.state.settings
            settings.rate_limit_enabled = True
            settings.rate_limit_login = 1
            payload = {"username": "missing", "password": "wrong-password"}
            assert browser.post("/api/auth/login", json=payload).status_code == 401
            response = browser.post("/api/auth/login", json=payload)
        elif case == "shutdown":
            client.app.state.shutdown_handler.begin_shutdown()
            response = browser.get("/")
        else:
            response = browser.get(
                {
                    "page": "/",
                    "static": "/static/console.js",
                    "redirect": "/api/health/",
                    "401": "/api/auth/me",
                    "404": "/missing",
                    "500": "/test/unexpected-failure",
                }[case],
                follow_redirects=False,
            )
        assert (
            response.status_code
            == {
                "page": 200,
                "static": 200,
                "redirect": 307,
                "401": 401,
                "404": 404,
                "422": 422,
                "429": 429,
                "500": 500,
                "shutdown": 503,
            }[case]
        )
        expected = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Content-Security-Policy": client.app.state.settings.content_security_policy,
        }
        if scheme == "https":
            expected["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        else:
            assert "Strict-Transport-Security" not in response.headers
        for header, value in expected.items():
            assert response.headers.get_list(header) == [value]
