# Tests for webhook alerts: payload shapes, validation, failure safety.
"""Webhook tests: Discord, Slack and generic payloads, mocked network."""

from __future__ import annotations

import json
from unittest import mock

import pytest

from fim_core import (
    Change,
    ConfigError,
    build_webhook_payload,
    mask_webhook_url,
    send_webhook_alert,
    validate_webhook_url,
)


def _changes() -> list[Change]:
    return [Change("MODIFIED", "a.txt"), Change("ADDED", "new.txt")]


def _config(webhook_type: str = "discord") -> dict:
    return {
        "webhook_url": "https://example.com/hooks/abc123",
        "webhook_type": webhook_type,
        "alert_channels": ["webhook"],
    }


def test_discord_payload_has_embed() -> None:
    """Discord payloads must be an embed-style message with the changes."""
    payload = build_webhook_payload(_changes(), _config("discord"))
    assert payload["embeds"][0]["title"] == "File Integrity Monitor"
    assert "[MODIFIED] a.txt" in payload["embeds"][0]["description"]
    assert "[ADDED] new.txt" in payload["embeds"][0]["description"]


def test_slack_payload_has_blocks() -> None:
    """Slack payloads must carry text and blocks with the changes."""
    payload = build_webhook_payload(_changes(), _config("slack"))
    assert "2 change(s)" in payload["text"]
    assert any(
        "a.txt" in block["text"]["text"]
        for block in payload["blocks"]
        if "text" in block
    )


def test_generic_payload_has_counts_and_changes() -> None:
    """Generic payloads must be plain JSON with counts and change dicts."""
    payload = build_webhook_payload(
        _changes(), _config("generic"), scanned_at_utc="2026-01-01T00:00:00+00:00"
    )
    assert payload["change_count"] == 2
    assert payload["scanned_at_utc"] == "2026-01-01T00:00:00+00:00"
    assert payload["changes"][0]["kind"] == "MODIFIED"
    assert payload["changes"][0]["relative_path"] == "a.txt"


def test_mass_change_flag_in_payload() -> None:
    """A mass change must be flagged in the webhook summary and payload."""
    payload = build_webhook_payload(_changes(), _config("generic"), mass_change=True)
    assert payload["mass_change"] is True
    discord = build_webhook_payload(_changes(), _config("discord"), mass_change=True)
    assert discord["content"].startswith("MASS CHANGE DETECTED")


def test_invalid_webhook_url_rejected() -> None:
    """Non-http URLs and URLs with credentials must be rejected."""
    with pytest.raises(ConfigError, match="webhook_url"):
        validate_webhook_url("file:///etc/passwd")
    with pytest.raises(ConfigError, match="webhook_url"):
        validate_webhook_url("https://user:secret@example.com/hooks/x")


def test_webhook_url_is_masked_in_logs() -> None:
    """Masking must hide the path/query (where a token would live)."""
    masked = mask_webhook_url("https://discord.com/api/webhooks/123/secret-token")
    assert "secret-token" not in masked
    assert masked.startswith("https://discord.com")
    assert masked.endswith("/***")


def test_webhook_send_posts_json_and_returns_true() -> None:
    """A successful POST must send JSON to the configured URL."""
    seen: dict = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b"ok"

    def fake_urlopen(request, timeout=10):
        seen["url"] = request.full_url
        seen["body"] = json.loads(request.data.decode("utf-8"))
        seen["content_type"] = request.headers.get("Content-type")
        return FakeResponse()

    with mock.patch("urllib.request.urlopen", fake_urlopen):
        assert send_webhook_alert(_changes(), _config("discord")) is True
    assert seen["url"] == "https://example.com/hooks/abc123"
    assert seen["content_type"] == "application/json"
    assert "a.txt" in json.dumps(seen["body"])


def test_webhook_failure_does_not_raise() -> None:
    """A dead webhook must return False, never crash a scan."""

    def failing_urlopen(request, timeout=10):
        raise OSError("network down")

    with mock.patch("urllib.request.urlopen", failing_urlopen):
        assert send_webhook_alert(_changes(), _config("discord")) is False


def test_webhook_env_override_wins(monkeypatch) -> None:
    """FIM_WEBHOOK_URL must override the config file value."""
    from fim_core import get_webhook_url

    monkeypatch.setenv("FIM_WEBHOOK_URL", "https://example.com/hooks/from-env")
    assert (
        get_webhook_url({"webhook_url": "https://example.com/hooks/from-config"})
        == "https://example.com/hooks/from-env"
    )
    monkeypatch.delenv("FIM_WEBHOOK_URL")
    assert (
        get_webhook_url({"webhook_url": "https://example.com/hooks/from-config"})
        == "https://example.com/hooks/from-config"
    )
