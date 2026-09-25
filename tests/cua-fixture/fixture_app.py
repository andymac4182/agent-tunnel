#!/usr/bin/env python3
"""Deterministic M5-03 CUA fixture GUI. Runs INSIDE the disposable guest VM only.

Never run this on a contributor's desktop: it is the target that a real
cua-computer-server clicks and types into, and it exists so that those
clicks land on synthetic content in a VM nobody minds.

What it draws, all at fixed screen coordinates because the window is
fullscreen on an undecorated root:

* four solid corner markers, MARKER_SIZE px square, in fixed colours, so a
  screenshot can be checked for dimensions and orientation by pixel reads;
* a centre marker whose centre is the screen centre;
* a text field and a button with a click counter.

Every change is written atomically to STATE_PATH as JSON, so a test can read
what the application actually received rather than trusting the transport's
acknowledgement. The content is synthetic; nothing here reads user data.
"""

import json
import os
import sys
import tempfile
import tkinter as tk

TITLE = "agentuplink-cua-fixture"
MARKER_SIZE = 40
# Corner markers, in the order top-left, top-right, bottom-left, bottom-right.
CORNER_COLOURS = ("#ff0000", "#00ff00", "#0000ff", "#ff00ff")
CENTRE_COLOUR = "#ffff00"
BACKGROUND = "#202020"
STATE_PATH = os.environ.get("CUA_FIXTURE_STATE", "/tmp/cua-fixture/state.json")


def activate_on_macos(root: tk.Tk) -> None:
    """Bring the fixture in front of Finder's desktop in the macOS guest.

    launchd starts the fixture in the background, and a fullscreen window of
    an app that is not active may sit behind Finder or under the menu bar,
    where two of the corner markers are. Activating the app is meant to
    prevent that; whether it is needed was not isolated. Measured 2026-09-26
    with it: the fixture's window is the only on-screen window, at layer 19,
    covering the whole screen. PyObjC is present in the guest's server venv,
    which runs the fixture on macOS; elsewhere this is never called.
    """
    root.attributes("-topmost", True)
    root.lift()
    try:
        from AppKit import NSApplication  # type: ignore[import-not-found]

        NSApplication.sharedApplication().activateIgnoringOtherApps_(True)
    except ImportError:
        pass


class Fixture:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.clicks = 0
        root.title(TITLE)
        root.configure(background=BACKGROUND)
        root.attributes("-fullscreen", True)
        if sys.platform == "darwin":
            activate_on_macos(root)
        root.update_idletasks()
        self.width = root.winfo_screenwidth()
        self.height = root.winfo_screenheight()

        canvas = tk.Canvas(
            root,
            width=self.width,
            height=self.height,
            background=BACKGROUND,
            highlightthickness=0,
            borderwidth=0,
        )
        canvas.place(x=0, y=0)
        self.canvas = canvas

        s = MARKER_SIZE
        corners = (
            (0, 0),
            (self.width - s, 0),
            (0, self.height - s),
            (self.width - s, self.height - s),
        )
        for (x, y), colour in zip(corners, CORNER_COLOURS):
            canvas.create_rectangle(x, y, x + s - 1, y + s - 1, fill=colour, width=0)
        cx, cy = self.width // 2, self.height // 2
        canvas.create_rectangle(
            cx - s // 2, cy - s // 2, cx + s // 2 - 1, cy + s // 2 - 1,
            fill=CENTRE_COLOUR, width=0,
        )

        # Text field and click button at fixed offsets from the top-left.
        self.text = tk.StringVar(value="")
        self.text.trace_add("write", lambda *_: self.save())
        entry = tk.Entry(root, textvariable=self.text, font=("DejaVu Sans Mono", 14))
        entry.place(x=100, y=100, width=400, height=32)
        self.entry = entry

        self.button = tk.Button(root, text="Click me", command=self.on_click)
        self.button.place(x=100, y=160, width=160, height=40)
        self.counter = tk.Label(
            root, text="clicks: 0", background=BACKGROUND, foreground="#ffffff",
            font=("DejaVu Sans Mono", 14),
        )
        self.counter.place(x=280, y=160, height=40)

        entry.focus_set()
        self.save()

    def on_click(self) -> None:
        self.clicks += 1
        self.counter.configure(text=f"clicks: {self.clicks}")
        self.save()

    def widget_geometry(self, widget: tk.Widget) -> dict:
        widget.update_idletasks()
        return {
            "x": widget.winfo_rootx(),
            "y": widget.winfo_rooty(),
            "width": widget.winfo_width(),
            "height": widget.winfo_height(),
        }

    def save(self) -> None:
        state = {
            "title": TITLE,
            "screen": {"width": self.width, "height": self.height},
            "marker_size": MARKER_SIZE,
            "corner_colours": list(CORNER_COLOURS),
            "centre_colour": CENTRE_COLOUR,
            "text": self.text.get() if hasattr(self, "text") else "",
            "clicks": self.clicks,
            "entry": self.widget_geometry(self.entry) if hasattr(self, "entry") else None,
            "button": self.widget_geometry(self.button) if hasattr(self, "button") else None,
        }
        directory = os.path.dirname(STATE_PATH)
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".state.")
        os.fchmod(fd, 0o644)  # readable by the probe user; content is synthetic
        with os.fdopen(fd, "w") as f:
            json.dump(state, f, sort_keys=True)
        os.replace(tmp, STATE_PATH)


def main() -> int:
    root = tk.Tk()
    fixture = Fixture(root)
    # The fullscreen request is honoured asynchronously by the WM; re-record
    # geometry once it has settled so the state file matches the screen.
    root.after(1000, fixture.save)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
