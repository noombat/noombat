#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

"""Measure the contrast of every semantic colour pair the theme defines.

A palette that names a colour "danger" says nothing about whether the
text set in it can be read. This resolves the tokens the way a browser
does, across all four combinations of theme and contrast setting, and
fails when a pair falls under its threshold.

The high-contrast mode is the reason this exists: advertising WCAG AAA
without measuring it is a claim the code does not keep. The standard
palette is held to AA by the same run, so it cannot regress quietly.

Usage: check-contrast.py [CSS]
       Defaults to frontend/src/main.css.
Exit 0 all pairs pass, 1 a pair fails, 2 nothing was measured.
"""

import re
import sys
from pathlib import Path

# Foreground, background, and whether the pair carries body text.
# A border is non-text: WCAG asks 3:1 of it, and 4.5:1 once the reader
# has asked for high contrast.
PAIRS = [
    ("--color-text-primary", "--color-bg-primary", "text"),
    ("--color-text-primary", "--color-bg-raised", "text"),
    ("--color-text-primary", "--color-bg-sunken", "text"),
    ("--color-text-secondary", "--color-bg-primary", "text"),
    ("--color-text-secondary", "--color-bg-raised", "text"),
    ("--color-text-brand", "--color-bg-primary", "text"),
    ("--color-text-brand", "--color-bg-raised", "text"),
    ("--color-text-accent", "--color-bg-primary", "text"),
    ("--color-text-on-brand", "--color-bg-brand", "text"),
    ("--color-text-on-brand", "--color-bg-brand-hover", "text"),
    ("--color-text-on-brand", "--color-bg-brand-press", "text"),
    ("--color-text-on-danger", "--color-bg-danger", "text"),
    ("--color-text-danger", "--color-bg-danger-subtle", "text"),
    ("--color-text-danger", "--color-bg-primary", "text"),
    ("--color-text-warning", "--color-bg-warning-subtle", "text"),
    ("--color-text-warning", "--color-bg-primary", "text"),
    ("--color-text-success", "--color-bg-success-subtle", "text"),
    ("--color-text-success", "--color-bg-primary", "text"),
    ("--color-text-info", "--color-bg-primary", "text"),
    ("--color-border-strong", "--color-bg-primary", "non-text"),
    ("--color-border-strong", "--color-bg-raised", "non-text"),
    ("--color-border-focus", "--color-bg-primary", "non-text"),
    ("--color-border-danger", "--color-bg-danger-subtle", "non-text"),
    ("--color-border-warning", "--color-bg-warning-subtle", "non-text"),
    ("--color-border-success", "--color-bg-success-subtle", "non-text"),
]

THRESHOLDS = {
    ("standard", "text"): 4.5,
    ("standard", "non-text"): 3.0,
    ("high", "text"): 7.0,
    ("high", "non-text"): 4.5,
}

DECLARATION = re.compile(r"(--[\w-]+)\s*:\s*([^;]+);")
HIGH_CONTRAST_BLOCK = re.compile(
    r':root\[data-contrast="high"\]\s*\{(.*?)\n\}', re.DOTALL
)


def parse(css):
    """Return (base, high): token name to declared value, per layer."""
    high_match = HIGH_CONTRAST_BLOCK.search(css)
    high_text = high_match.group(1) if high_match else ""
    base_text = css.replace(high_text, "") if high_text else css
    base = dict(DECLARATION.findall(base_text))
    high = dict(DECLARATION.findall(high_text))
    return base, high


def resolve(token, base, high, scheme, contrast, seen=None):
    """Resolve a token to `#rrggbb` or `rgb(r g b / a)`, as a browser would."""
    seen = seen or set()
    if token in seen:
        raise ValueError(f"{token} resolves through itself")
    seen = seen | {token}

    layers = (high, base) if contrast == "high" else (base,)
    value = next((layer[token] for layer in layers if token in layer), None)
    if value is None:
        raise KeyError(token)
    value = " ".join(value.split())

    # light-dark(a, b) picks by scheme. Split on the comma that separates
    # its two arguments, which is the one at nesting depth zero.
    match = re.fullmatch(r"light-dark\((.*)\)", value)
    if match:
        depth, split = 0, None
        for i, ch in enumerate(match.group(1)):
            depth += (ch == "(") - (ch == ")")
            if ch == "," and depth == 0:
                split = i
                break
        if split is None:
            raise ValueError(f"malformed light-dark in {token}")
        arg = match.group(1)[:split] if scheme == "light" else match.group(1)[split + 1 :]
        value = arg.strip()

    match = re.fullmatch(r"var\((--[\w-]+)\)", value)
    if match:
        return resolve(match.group(1), base, high, scheme, contrast, seen)
    return value


def to_rgba(value):
    """`#rrggbb` or `rgb(r g b / a)` to (r, g, b, alpha)."""
    if value.startswith("#"):
        h = value[1:]
        if len(h) == 3:
            h = "".join(c * 2 for c in h)
        return (int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16), 1.0)
    match = re.fullmatch(
        r"rgba?\(\s*(\d+)[\s,]+(\d+)[\s,]+(\d+)(?:\s*/\s*([\d.]+))?\s*\)", value
    )
    if not match:
        raise ValueError(f"unrecognised colour: {value}")
    r, g, b, a = match.groups()
    return (int(r), int(g), int(b), float(a) if a else 1.0)


def over(fg, bg):
    """Composite a translucent foreground onto an opaque background."""
    r, g, b, a = fg
    br, bg_, bb, _ = bg
    return (a * r + (1 - a) * br, a * g + (1 - a) * bg_, a * b + (1 - a) * bb, 1.0)


def luminance(colour):
    def channel(c):
        c /= 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b, _ = colour
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def ratio(fg, bg):
    a, b = luminance(fg), luminance(bg)
    lighter, darker = max(a, b), min(a, b)
    return (lighter + 0.05) / (darker + 0.05)


def main():
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "frontend/src/main.css")
    if not path.is_file():
        print(f"::error::stylesheet not found: {path}", file=sys.stderr)
        return 1

    base, high = parse(path.read_text())
    if not high:
        print(
            "::error::no [data-contrast=\"high\"] block found, so the "
            "high-contrast mode is unmeasured",
            file=sys.stderr,
        )
        return 2

    failures, measured = [], 0
    for contrast in ("standard", "high"):
        for scheme in ("light", "dark"):
            for fg_token, bg_token, kind in PAIRS:
                try:
                    fg = to_rgba(resolve(fg_token, base, high, scheme, contrast))
                    bg = to_rgba(resolve(bg_token, base, high, scheme, contrast))
                except (KeyError, ValueError) as error:
                    print(f"::error::{error}", file=sys.stderr)
                    return 1
                value = ratio(over(fg, bg), bg)
                measured += 1
                need = THRESHOLDS[(contrast, kind)]
                if value < need:
                    failures.append(
                        f"{contrast}/{scheme}: {fg_token} on {bg_token} "
                        f"is {value:.2f}:1, needs {need}:1 ({kind})"
                    )

    # A pair list that reached nothing would otherwise read as a pass.
    if measured == 0:
        print("::error::no pairs measured, so this check proves nothing", file=sys.stderr)
        return 2

    for failure in failures:
        print(f"::error::{failure}", file=sys.stderr)
    if failures:
        print(
            f"::error::{len(failures)} of {measured} pair(s) below threshold",
            file=sys.stderr,
        )
        return 1

    print(f"Measured {measured} colour pair(s) across four modes: all meet WCAG.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
