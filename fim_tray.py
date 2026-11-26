# File Integrity Monitor - optional system tray support.
# pystray is optional: without it the GUI works normally and this
# module just reports that the tray is unavailable.
"""System tray icon for the GUI.

The tray lives in its own module so it can be imported and tested
without a display or a tray library installed. All callbacks are
handed back to the GUI thread through the callbacks given at
construction time; this module never touches Tkinter directly.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

LOGGER = logging.getLogger("fim_tray")


def tray_available() -> bool:
    """Return True only when pystray (and Pillow, for the icon) import."""
    try:
        import pystray  # noqa: F401
        from PIL import Image  # noqa: F401
    except Exception:
        # ImportError is the usual case, but pystray can also fail
        # while initialising its backend (e.g. Xlib DisplayNameError
        # on a headless Linux box with no display). Either way the
        # tray is unavailable and the GUI must carry on without it.
        LOGGER.debug("System tray unavailable.", exc_info=True)
        return False
    return True


def _make_icon_image() -> Any:
    """Draw a small blue square with a white shield mark for the tray."""
    from PIL import Image, ImageDraw

    image = Image.new("RGB", (64, 64), (30, 80, 160))
    draw = ImageDraw.Draw(image)
    draw.rectangle([18, 12, 46, 52], outline="white", width=4)
    draw.line([24, 32, 30, 38, 42, 24], fill="white", width=4)
    return image


class TrayController:
    """Own a pystray icon, or do nothing when pystray is missing."""

    def __init__(
        self,
        on_show: Callable[[], None],
        on_verify: Callable[[], None],
        on_start_monitoring: Callable[[], None],
        on_stop_monitoring: Callable[[], None],
        on_quit: Callable[[], None],
    ) -> None:
        """Store the GUI callbacks; nothing is shown yet."""
        self._callbacks = {
            "show": on_show,
            "verify": on_verify,
            "start": on_start_monitoring,
            "stop": on_stop_monitoring,
            "quit": on_quit,
        }
        self._icon: Any = None
        self._running = False

    @property
    def running(self) -> bool:
        """Return True while the tray icon is shown."""
        return self._running

    def start(self) -> bool:
        """Show the tray icon; return False when pystray is unavailable."""
        if self._running:
            return True
        if not tray_available():
            LOGGER.info("Tray not available: install pystray and Pillow to enable it.")
            return False
        try:
            import pystray

            menu = pystray.Menu(
                pystray.MenuItem("Show", lambda: self._callbacks["show"]()),
                pystray.MenuItem("Verify Now", lambda: self._callbacks["verify"]()),
                pystray.MenuItem(
                    "Start Monitoring", lambda: self._callbacks["start"]()
                ),
                pystray.MenuItem("Stop Monitoring", lambda: self._callbacks["stop"]()),
                pystray.MenuItem("Quit", lambda: self._callbacks["quit"]()),
            )
            self._icon = pystray.Icon(
                "File Integrity Monitor",
                _make_icon_image(),
                "File Integrity Monitor",
                menu,
            )
            # run_detached keeps the icon alive without blocking the GUI.
            self._icon.run_detached()
            self._running = True
            return True
        except Exception:
            LOGGER.warning("Could not start the system tray icon.", exc_info=True)
            self._icon = None
            return False

    def stop(self) -> None:
        """Hide the tray icon, if one is shown."""
        if self._icon is not None:
            try:
                self._icon.stop()
            except Exception:
                LOGGER.debug("Could not stop the tray icon.", exc_info=True)
        self._icon = None
        self._running = False
