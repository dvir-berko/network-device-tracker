import socket

import app as tracker_app


def test_validate_requested_subnets_accepts_private_small():
    subnets, err = tracker_app.validate_requested_subnets(["10.0.0.0/24", "192.168.1.0/24"])
    assert err == ""
    assert len(subnets) == 2


def test_validate_requested_subnets_rejects_large_network():
    subnets, err = tracker_app.validate_requested_subnets(["10.0.0.0/16"])
    assert subnets == []
    assert "subnet too large" in err


def test_validate_webhook_url_rejects_localhost():
    ok, reason = tracker_app.validate_webhook_url("http://localhost/hook")
    assert ok is False
    assert "localhost" in reason.lower()


def test_validate_webhook_url_rejects_private_ip(monkeypatch):
    monkeypatch.setattr(tracker_app, "ALLOW_PRIVATE_WEBHOOKS", False)

    def fake_getaddrinfo(*_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.25", 443))]

    monkeypatch.setattr(tracker_app.socket, "getaddrinfo", fake_getaddrinfo)
    ok, reason = tracker_app.validate_webhook_url("https://example.com/hook")
    assert ok is False
    assert "blocked" in reason.lower()


def test_validate_webhook_url_accepts_public_ip(monkeypatch):
    monkeypatch.setattr(tracker_app, "ALLOW_PRIVATE_WEBHOOKS", False)
    monkeypatch.setattr(tracker_app, "WEBHOOK_ALLOWLIST", [])

    def fake_getaddrinfo(*_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    monkeypatch.setattr(tracker_app.socket, "getaddrinfo", fake_getaddrinfo)
    ok, reason = tracker_app.validate_webhook_url("https://example.com/hook")
    assert ok is True
    assert reason == ""
