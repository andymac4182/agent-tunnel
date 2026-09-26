"""Print the macOS guest's on-screen window stack as JSON. Guest only, read-only.

Run by scripts/m5-cua-vm-macos.sh through `launchctl asuser <cua uid>` so it
reaches cua's WindowServer session. It needs no TCC permission: window owner
names, PIDs, layers and bounds are not protected (window *titles* are, and are
not read). It is how the host script decides that the fixture is up and in
front before any probe, since without a Screen Recording grant nothing in the
guest can check the markers by capture.
"""

import json
import sys

from AppKit import NSScreen  # type: ignore[import-not-found]
from Quartz import (  # type: ignore[import-not-found]
    CGWindowListCopyWindowInfo,
    kCGNullWindowID,
    kCGWindowListExcludeDesktopElements,
    kCGWindowListOptionOnScreenOnly,
)


def main() -> int:
    if sys.platform != "darwin":
        print("guest only", file=sys.stderr)
        return 2
    screen = NSScreen.mainScreen().frame().size
    windows = []
    # Front to back.
    for w in CGWindowListCopyWindowInfo(
        kCGWindowListOptionOnScreenOnly | kCGWindowListExcludeDesktopElements, kCGNullWindowID
    ) or []:
        b = w.get("kCGWindowBounds", {})
        windows.append(
            {
                "owner": str(w.get("kCGWindowOwnerName", "")),
                "pid": int(w.get("kCGWindowOwnerPID", 0)),
                "layer": int(w.get("kCGWindowLayer", 0)),
                "alpha": float(w.get("kCGWindowAlpha", 1.0)),
                "bounds": [int(b.get("X", 0)), int(b.get("Y", 0)), int(b.get("Width", 0)), int(b.get("Height", 0))],
            }
        )
    print(json.dumps({"screen_points": [int(screen.width), int(screen.height)], "windows": windows}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
