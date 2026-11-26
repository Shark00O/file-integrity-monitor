# Tests for v1.1 features 5-8: mass change, multi-folder, dark mode,
# encrypted baseline and key rotation, plus scheduled-scan config.
"""v1.1 tests: mass change, multi-folder, theme, encryption, rotation."""

from __future__ import annotations

import json

import pytest

from fim_core import (
    BaselineError,
    Change,
    ConfigError,
    create_baseline,
    export_scan_results,
    get_theme_colours,
    is_mass_change,
    load_baseline,
    load_config,
    resolve_baseline_dir,
    rotate_baseline_key,
    verify_baseline,
)


def _config(**overrides) -> dict:
    config = {
        "mass_change_threshold": 10,
        "mass_change_percent": 20,
        "gui_theme": "light",
        "scheduled_scan_interval_minutes": 0,
    }
    config.update(overrides)
    return config


# --- 5. Mass change -------------------------------------------------


def test_mass_change_by_count() -> None:
    """Ten changes must trip the mass-change rule, nine must not."""
    changes = [Change("MODIFIED", f"f{i}.txt") for i in range(9)]
    assert is_mass_change(changes, 100, _config()) is False
    changes.append(Change("MODIFIED", "f9.txt"))
    assert is_mass_change(changes, 100, _config()) is True


def test_mass_change_by_percent() -> None:
    """Three changes out of five files (60%) must trip the 20% rule."""
    changes = [
        Change("MODIFIED", "a.txt"),
        Change("MODIFIED", "b.txt"),
        Change("MODIFIED", "c.txt"),
    ]
    assert is_mass_change(changes, 5, _config()) is True
    assert is_mass_change(changes, 100, _config()) is False
    # Fewer than 3 changes never trips the percentage branch.
    assert is_mass_change(changes[:2], 5, _config()) is False


def test_mass_change_flag_on_verify_result(
    monitored_dir, baseline_dir, key_path
) -> None:
    """Changing most files in one verify must set mass_change on the result."""
    create_baseline(monitored_dir, baseline_dir, key_path)
    for name in ("a.txt", "sub/b.txt", "empty.txt"):
        (monitored_dir / name).write_text("changed\n", encoding="utf-8")
    result = verify_baseline(monitored_dir, baseline_dir, key_path)
    assert len(result.changes) == 3
    assert result.mass_change is True


def test_small_change_is_not_mass_change(monitored_dir, baseline_dir, key_path) -> None:
    """One changed file out of many must not be a mass change."""
    create_baseline(monitored_dir, baseline_dir, key_path)
    (monitored_dir / "a.txt").write_text("changed\n", encoding="utf-8")
    result = verify_baseline(monitored_dir, baseline_dir, key_path)
    assert result.mass_change is False


def test_invalid_mass_change_config_rejected(tmp_path) -> None:
    """Bad mass-change thresholds must be rejected with the field named."""
    bad = tmp_path / "config.json"
    bad.write_text(json.dumps({"mass_change_threshold": 0}), encoding="utf-8")
    with pytest.raises(ConfigError, match="mass_change_threshold"):
        load_config(bad)
    bad.write_text(json.dumps({"mass_change_percent": 101}), encoding="utf-8")
    with pytest.raises(ConfigError, match="mass_change_percent"):
        load_config(bad)


# --- 6. Multi-folder ------------------------------------------------


def test_resolve_baseline_dir_single_folder(tmp_path) -> None:
    """One folder must keep the legacy baseline/ directory."""
    root = tmp_path / "docs"
    root.mkdir()
    assert resolve_baseline_dir(tmp_path / "baseline", root) == tmp_path / "baseline"


def test_resolve_baseline_dir_multi_folder(tmp_path) -> None:
    """Two folders must get different, safe subfolders."""
    first = tmp_path / "docs"
    second = tmp_path / "other" / "docs"
    first.mkdir()
    second.mkdir(parents=True)
    base = tmp_path / "baseline"
    one = resolve_baseline_dir(base, first, single_folder=False)
    two = resolve_baseline_dir(base, second, single_folder=False)
    assert one != two
    assert one.parent == base
    assert ".." not in str(one) and "/" not in one.name


def test_multi_folder_init_and_verify(tmp_path) -> None:
    """Init and verify must work independently for two folders."""
    first = tmp_path / "one"
    second = tmp_path / "two"
    for root in (first, second):
        root.mkdir()
        (root / "a.txt").write_text("hello\n", encoding="utf-8")
    base = tmp_path / "baseline"
    key_path = tmp_path / "fim.key"
    for root in (first, second):
        sub = resolve_baseline_dir(base, root, single_folder=False)
        create_baseline(root, sub, key_path)
        result = verify_baseline(root, sub, key_path)
        assert result.changes == []
    (second / "a.txt").write_text("changed\n", encoding="utf-8")
    sub_first = resolve_baseline_dir(base, first, single_folder=False)
    sub_second = resolve_baseline_dir(base, second, single_folder=False)
    assert verify_baseline(first, sub_first, key_path).changes == []
    assert verify_baseline(second, sub_second, key_path).changes != []


# --- 7. Dark mode ---------------------------------------------------


def test_theme_colours_dark_and_light() -> None:
    """Dark and light themes must return different, readable maps."""
    dark = get_theme_colours("dark")
    light = get_theme_colours("light")
    assert dark["background"] != light["background"]
    assert dark["background"].startswith("#")
    assert dark["text"] != dark["background"]
    assert light["text"] != light["background"]
    for colours in (dark, light):
        assert {"background", "surface", "text", "field", "heading"} <= set(colours)


def test_invalid_gui_theme_rejected(tmp_path) -> None:
    """A theme that is not light/dark must be rejected."""
    bad = tmp_path / "config.json"
    bad.write_text(json.dumps({"gui_theme": "blue"}), encoding="utf-8")
    with pytest.raises(ConfigError, match="gui_theme"):
        load_config(bad)


def test_scheduled_scan_config_validation(tmp_path) -> None:
    """Scheduled intervals must be 0 or 5-1440 minutes."""
    bad = tmp_path / "config.json"
    bad.write_text(json.dumps({"scheduled_scan_interval_minutes": 3}), encoding="utf-8")
    with pytest.raises(ConfigError, match="scheduled_scan_interval_minutes"):
        load_config(bad)
    good = tmp_path / "good.json"
    good.write_text(
        json.dumps({"scheduled_scan_interval_minutes": 60}), encoding="utf-8"
    )
    assert load_config(good)["scheduled_scan_interval_minutes"] == 60


# --- 8. Encrypted baseline + key rotation ---------------------------


def test_baseline_json_is_encrypted(monitored_dir, baseline_dir, key_path) -> None:
    """Plaintext file names and hashes must not appear in baseline.json."""
    create_baseline(monitored_dir, baseline_dir, key_path)
    raw = (baseline_dir / "baseline.json").read_text(encoding="utf-8")
    assert "a.txt" not in raw
    assert "hello world" not in raw
    loaded = load_baseline(baseline_dir, key_path)
    assert [r.relative_path for r in loaded] == ["a.txt", "empty.txt", "sub/b.txt"]


def test_old_plain_baseline_still_loads(monitored_dir, baseline_dir, key_path) -> None:
    """A v1.0 plain signed baseline must load and then migrate on update."""
    from fim_core import BASELINE_VERSION, sign_baseline, write_file_atomic

    create_baseline(monitored_dir, baseline_dir, key_path)
    key = key_path.read_bytes()
    payload = {
        "version": BASELINE_VERSION,
        "created_utc": "2026-01-01T00:00:00+00:00",
        "monitored_path": str(monitored_dir.resolve()),
        "files": [r.to_dict() for r in load_baseline(baseline_dir, key_path)],
    }
    signed = sign_baseline(payload, key)
    json_path = baseline_dir / "baseline.json"
    write_file_atomic(
        json_path, json.dumps(signed, indent=2, sort_keys=True).encode("utf-8")
    )
    from fim_core import write_sha256_sidecar

    write_sha256_sidecar(json_path)
    loaded = load_baseline(baseline_dir, key_path)
    assert len(loaded) == 3


def test_key_rotation(monitored_dir, baseline_dir, key_path) -> None:
    """Rotation must re-encrypt with a new key; the old key must fail."""
    create_baseline(monitored_dir, baseline_dir, key_path)
    old_key = key_path.read_bytes()
    count = rotate_baseline_key(baseline_dir, key_path)
    assert count == 3
    new_key = key_path.read_bytes()
    assert new_key != old_key and len(new_key) == 32
    # New key loads the same records.
    loaded = load_baseline(baseline_dir, key_path)
    assert [r.relative_path for r in loaded] == ["a.txt", "empty.txt", "sub/b.txt"]
    # Old key must no longer verify: swap it back in a temp key file.
    old_key_path = key_path.parent / "old.key"
    old_key_path.write_bytes(old_key)
    with pytest.raises(BaselineError):
        load_baseline(baseline_dir, old_key_path)


def test_key_rotation_refuses_tampered_baseline(
    monitored_dir, baseline_dir, key_path
) -> None:
    """Rotation must refuse a tampered baseline and keep the old key."""
    create_baseline(monitored_dir, baseline_dir, key_path)
    old_key = key_path.read_bytes()
    json_path = baseline_dir / "baseline.json"
    data = json.loads(json_path.read_text(encoding="utf-8"))
    encoded = data["data"]
    data["data"] = ("A" if encoded[0] != "A" else "B") + encoded[1:]
    json_path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(BaselineError):
        rotate_baseline_key(baseline_dir, key_path)
    assert key_path.read_bytes() == old_key


def test_export_scan_results_lists_all_files(
    monitored_dir, baseline_dir, key_path, report_dir
) -> None:
    """Export must list every file as JSON + CSV, not just changes."""
    create_baseline(monitored_dir, baseline_dir, key_path)
    (monitored_dir / "a.txt").write_text("changed\n", encoding="utf-8")
    result = verify_baseline(monitored_dir, baseline_dir, key_path)
    json_path, csv_path = export_scan_results(report_dir, monitored_dir, result)
    assert json_path.exists() and csv_path.exists()
    data = json.loads(json_path.read_text(encoding="utf-8"))
    statuses = {f["relative_path"]: f["status"] for f in data["files"]}
    assert statuses == {
        "a.txt": "MODIFIED",
        "empty.txt": "OK",
        "sub/b.txt": "OK",
    }
    assert "a.txt,MODIFIED" in csv_path.read_text(encoding="utf-8")


def test_tray_fallback_when_pystray_missing(monkeypatch) -> None:
    """Without pystray installed, the tray must report unavailable."""
    import sys

    import fim_tray

    # Simulate pystray being missing, even on a machine where it is
    # installed (like Windows). Setting sys.modules["pystray"] to
    # None makes `import pystray` raise ImportError. The old test
    # only skipped when pystray was already imported, so on Windows
    # it ran with pystray present and failed for the wrong reason:
    # the tray was correctly available, the test was wrong.
    monkeypatch.setitem(sys.modules, "pystray", None)
    assert fim_tray.tray_available() is False
    controller = fim_tray.TrayController(
        on_show=lambda: None,
        on_verify=lambda: None,
        on_start_monitoring=lambda: None,
        on_stop_monitoring=lambda: None,
        on_quit=lambda: None,
    )
    assert controller.start() is False
    assert controller.running is False


def test_find_baseline_dir_falls_back_to_multi(tmp_path) -> None:
    """A single-folder lookup must find a baseline made with several."""
    from fim_core import find_baseline_dir

    root = tmp_path / "docs"
    root.mkdir()
    (root / "a.txt").write_text("hello\n", encoding="utf-8")
    base = tmp_path / "baseline"
    key_path = tmp_path / "fim.key"
    multi = resolve_baseline_dir(base, root, single_folder=False)
    create_baseline(root, multi, key_path)
    assert find_baseline_dir(base, root) == multi
    # And with no baseline at all it returns the legacy single location.
    assert find_baseline_dir(tmp_path / "empty-base", root) == tmp_path / "empty-base"
