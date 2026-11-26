# Tests for the update check: version comparison and network failure.
"""Update-check tests: mocked GitHub Releases API, no real network."""

from __future__ import annotations

import json
from unittest import mock

from fim_core import VERSION, check_for_update


def _fake_response(payload: dict):
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps(payload).encode("utf-8")

    return FakeResponse()


def test_update_available_when_newer() -> None:
    """A newer tag must report an update with a download URL."""
    payload = {
        "tag_name": "v9.9.9",
        "html_url": "https://github.com/Shark00O/file-integrity-monitor/releases/tag/v9.9.9",
        "assets": [
            {
                "name": "FileIntegrityMonitor.exe",
                "browser_download_url": "https://example.com/FileIntegrityMonitor.exe",
            }
        ],
    }
    with mock.patch("urllib.request.urlopen", return_value=_fake_response(payload)):
        result = check_for_update("1.1.0")
    assert result["latest_version"] == "v9.9.9"
    assert result["is_update_available"] is True
    assert result["download_url"].endswith("FileIntegrityMonitor.exe")


def test_no_update_when_current() -> None:
    """The same tag must report up to date."""
    payload = {"tag_name": f"v{VERSION}", "html_url": "", "assets": []}
    with mock.patch("urllib.request.urlopen", return_value=_fake_response(payload)):
        result = check_for_update(VERSION)
    assert result["is_update_available"] is False


def test_older_tag_is_not_an_update() -> None:
    """An older tag must not be reported as an update."""
    payload = {"tag_name": "v1.0.0", "html_url": "", "assets": []}
    with mock.patch("urllib.request.urlopen", return_value=_fake_response(payload)):
        result = check_for_update("1.1.0")
    assert result["is_update_available"] is False


def test_network_failure_returns_error_not_exception() -> None:
    """A failed request must return an error dict, never raise."""

    def failing_urlopen(request, timeout=10):
        raise OSError("network down")

    with mock.patch("urllib.request.urlopen", failing_urlopen):
        result = check_for_update("1.1.0")
    assert result["error"]
    assert result["is_update_available"] is False


def test_version_constant_is_1_1_0() -> None:
    """The version constant must match the v1.1 release."""
    assert VERSION == "1.1.0"
