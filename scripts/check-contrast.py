#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

"""Measure the contrast of every semantic colour pair a palette defines.

A palette that names a colour "danger" says nothing about whether the
text set in it can be read. This resolves the tokens the way a browser
does, across all four combinations of theme and contrast setting, and
fails when a pair falls under its threshold.

The high-contrast mode is the reason this exists: advertising WCAG AAA
without measuring it is a claim the code does not keep. The standard
palette is held to AA by the same run, so it cannot regress quietly.

Two shapes are understood, because a palette arrives before it is
adopted and both have to be checkable:

  the served stylesheet   `@theme` plus `:root[data-contrast="high"]`,
                          with each token stated once as light-dark()
  a design system         `:root`, `.theme-dark`, `.contrast-high` and
                          `.theme-dark.contrast-high`, each restating
                          the tokens it overrides

Usage: check-contrast.py [CSS]
           Defaults to frontend/src/main.css.
       check-contrast.py --design-system CSS
           Audits a candidate palette in the second shape. The default
           mode runs in CI; this one cannot, because the palette it takes
           is not part of this repository and is not there to be checked
           out. Run it by hand before adopting a revision.

Exit 0 all pairs pass, 1 a pair fails, 2 nothing was measured.
"""

import contextlib
import io
import re
import sys
from pathlib import Path

# Foreground, background, and whether the pair carries body text.
# A border is non-text: WCAG asks 3:1 of it, and 4.5:1 once the reader
# has asked for high contrast.
PROJECT_PAIRS = [
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

# The same question asked of an upstream palette, in its own vocabulary.
DESIGN_SYSTEM_PAIRS = [
    (fg, bg, "text")
    for bg in ("--bg", "--bg-raised", "--bg-sunken")
    for fg in ("--fg", "--fg-muted", "--fg-subtle", "--primary-text")
] + [
    ("--fg-inverse", "--bg-inverse", "text"),
    ("--accent-on-inverse", "--bg-inverse", "text"),
    ("--fg-on-fill", "--primary-fill", "text"),
    ("--fg-on-fill", "--primary-fill-hover", "text"),
    ("--fg-on-fill", "--primary-fill-press", "text"),
    ("--fg-on-fill", "--accent-fill", "text"),
    ("--fg-on-fill", "--accent-fill-hover", "text"),
    ("--highlight-fg", "--highlight", "text"),
    # Absent from the file's own pairing rule, which names only the three
    # text-bearing fills, but the kit sets an active icon button as
    # --primary-text on --primary-soft. A tint that carries content needs
    # measuring whether or not a pairing was declared for it.
    #
    # Its siblings --accent-soft and --highlight-soft are deliberately not
    # here: nothing sets text on either, and a pairing invented to fill the
    # symmetry would fail on colours no reader ever sees together.
    ("--primary-text", "--primary-soft", "text"),
    ("--border-strong", "--bg", "non-text"),
    ("--border-strong", "--bg-raised", "non-text"),
    ("--border-focus", "--bg", "non-text"),
    ("--input-border", "--input-bg", "non-text"),
] + [
    (f"--chip-{kind}-fg", f"--chip-{kind}-bg", "text")
    for kind in ("default", "primary", "accent", "gold",
                 "success", "warning", "danger", "info", "inverse")
] + [("--avatar-fg", f"--avatar-{n}", "text") for n in range(1, 7)]

THRESHOLDS = {
    ("standard", "text"): 4.5,
    ("standard", "non-text"): 3.0,
    ("high", "text"): 7.0,
    ("high", "non-text"): 4.5,
}

DECLARATION = re.compile(r"(--[\w-]+)\s*:\s*([^;]+);")


def strip_comments(css):
    return re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)


def rule_blocks(css):
    """selector -> declarations, merging blocks that share a selector.

    Walks brace depth rather than matching a closing brace by pattern,
    because a media query or a nested rule would end the match early.
    """
    css = strip_comments(css)
    blocks, i, n = {}, 0, len(css)
    while i < n:
        open_brace = css.find("{", i)
        if open_brace == -1:
            break
        selector = css[i:open_brace].strip().split("}")[-1].strip().split("\n")[-1].strip()
        depth, j = 1, open_brace + 1
        while j < n and depth:
            depth += (css[j] == "{") - (css[j] == "}")
            j += 1
        declarations = dict(DECLARATION.findall(css[open_brace + 1:j - 1]))
        if declarations:
            blocks.setdefault(selector, {}).update(
                {k: v.strip() for k, v in declarations.items()}
            )
        i = j
    return blocks


def project_modes(css):
    """The served stylesheet: one base layer, one high-contrast override."""
    css = strip_comments(css)
    blocks = rule_blocks(css)
    base = {}
    for selector, declarations in blocks.items():
        if selector in (":root", "@theme") or selector.endswith("@theme"):
            base.update(declarations)
    high = blocks.get(':root[data-contrast="high"]', {})
    if not high:
        raise LookupError(
            'no :root[data-contrast="high"] block, so the high-contrast '
            "mode is unmeasured"
        )
    return {
        ("standard", "light"): ([base], "light"),
        ("standard", "dark"): ([base], "dark"),
        ("high", "light"): ([high, base], "light"),
        ("high", "dark"): ([high, base], "dark"),
    }


def design_system_modes(css):
    """A candidate palette: one block per combination, each restating."""
    blocks = rule_blocks(css)
    try:
        root = blocks[":root"]
        dark = blocks[".theme-dark"]
        high = blocks[".contrast-high"]
        both = blocks[".theme-dark.contrast-high"]
    except KeyError as missing:
        raise LookupError(f"no {missing} block, so that combination is unmeasured")
    return {
        ("standard", "light"): ([root], "light"),
        ("standard", "dark"): ([dark, root], "dark"),
        ("high", "light"): ([high, root], "light"),
        ("high", "dark"): ([both, high, dark, root], "dark"),
    }


def resolve(token, layers, scheme, seen=()):
    """Resolve a token to a colour the way a browser would."""
    if token in seen:
        raise ValueError(f"{token} resolves through itself")
    seen = seen + (token,)

    value = next((layer[token] for layer in layers if token in layer), None)
    if value is None:
        raise KeyError(token)
    value = " ".join(value.split())

    # light-dark(a, b) picks by scheme. Split on the comma that separates
    # its two arguments, which is the one at nesting depth zero.
    match = re.fullmatch(r"light-dark\((.*)\)", value)
    if match:
        depth, split = 0, None
        for index, character in enumerate(match.group(1)):
            depth += (character == "(") - (character == ")")
            if character == "," and depth == 0:
                split = index
                break
        if split is None:
            raise ValueError(f"malformed light-dark in {token}")
        argument = match.group(1)[:split] if scheme == "light" else match.group(1)[split + 1:]
        value = argument.strip()

    match = re.fullmatch(r"var\((--[\w-]+)\)", value)
    if match:
        return resolve(match.group(1), layers, scheme, seen)
    return value


def to_rgba(value):
    """`#rrggbb` or `rgb(r g b / a)` to (r, g, b, alpha)."""
    if value.startswith("#"):
        digits = value[1:]
        if len(digits) == 3:
            digits = "".join(c * 2 for c in digits)
        return (
            int(digits[0:2], 16),
            int(digits[2:4], 16),
            int(digits[4:6], 16),
            1.0,
        )
    match = re.fullmatch(
        r"rgba?\(\s*(\d+)[\s,]+(\d+)[\s,]+(\d+)(?:\s*[/,]\s*([\d.]+))?\s*\)", value
    )
    if not match:
        raise ValueError(f"unrecognised colour: {value}")
    red, green, blue, alpha = match.groups()
    return (int(red), int(green), int(blue), float(alpha) if alpha else 1.0)


def over(foreground, background):
    """Composite a translucent foreground onto an opaque background."""
    red, green, blue, alpha = foreground
    back_red, back_green, back_blue, _ = background
    return (
        alpha * red + (1 - alpha) * back_red,
        alpha * green + (1 - alpha) * back_green,
        alpha * blue + (1 - alpha) * back_blue,
        1.0,
    )


def luminance(colour):
    def channel(value):
        value /= 255
        return value / 12.92 if value <= 0.03928 else ((value + 0.055) / 1.055) ** 2.4

    red, green, blue, _ = colour
    return 0.2126 * channel(red) + 0.7152 * channel(green) + 0.0722 * channel(blue)


def ratio(foreground, background):
    a, b = luminance(foreground), luminance(background)
    lighter, darker = max(a, b), min(a, b)
    return (lighter + 0.05) / (darker + 0.05)


def audit(modes, pairs, label, page_token):
    """Measure every pair in every mode.

    `page_token` is the surface a translucent background sits on. A tint
    declared as `rgba(...)` is not the colour a reader sees: measuring it
    as though it were opaque reports a ratio that occurs nowhere.
    """
    failures, measured = [], 0
    for (contrast, scheme), (layers, resolution) in modes.items():
        page = to_rgba(resolve(page_token, layers, resolution))
        for fg_token, bg_token, kind in pairs:
            try:
                fg = to_rgba(resolve(fg_token, layers, resolution))
                bg = over(to_rgba(resolve(bg_token, layers, resolution)), page)
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

    print(f"Measured {measured} colour pair(s) across four modes in {label}: all meet WCAG.")
    return 0


def self_test():
    """Exercise the --design-system mode against committed fixtures.

    That mode's real input is not in this repository, so without this
    nothing here would show it still works. The fixtures use the same
    four-block shape and the same token vocabulary, and cover all three
    exit paths: a palette that conforms, one that does not, and one whose
    blocks are incomplete.
    """
    here = Path(__file__).resolve().parent / "fixtures"
    conforming = here / "design-system-conforming.css"
    names = ["design-system-conforming.css"] + [
        f"design-system-failing-{mode}.css"
        for mode in ("light", "dark", "high-light", "high-dark")
    ]
    for name in names:
        if not (here / name).is_file():
            print(f"::error::fixture missing: {here / name}", file=sys.stderr)
            return 2

    # One failing fixture per mode, each spoiled in that mode's block
    # alone, so a checker that stopped consulting one block would report
    # that fixture clean and be caught here.
    cases = [("conforming", conforming.read_text(), 0)] + [
        (name.removeprefix("design-system-failing-").removesuffix(".css"),
         (here / name).read_text(), 1)
        for name in names[1:]
    ]
    # A palette missing a block cannot be audited across four modes, and
    # must say so rather than measure the three it has.
    truncated = re.sub(
        r"\.theme-dark\.contrast-high \{.*?\n\}", "", conforming.read_text(), flags=re.DOTALL
    )
    cases.append(("truncated", truncated, 2))

    failures = 0
    for name, css, expected in cases:
        # The failing case reports its failures, which is the point of it.
        # Emitting them here would annotate a passing run with errors, so
        # only the verdict escapes.
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
            try:
                modes = design_system_modes(css)
            except LookupError:
                got = 2
            else:
                got = audit(modes, DESIGN_SYSTEM_PAIRS, name, "--bg")
        verdict = "ok" if got == expected else "WRONG"
        failures += got != expected
        print(f"  {name:<11} exit {got}, expected {expected}  {verdict}")

    if failures:
        print(f"::error::the design-system mode failed {failures} of its own cases", file=sys.stderr)
        return 1
    print("The --design-system mode behaves on all three of its exit paths.")
    return 0


def main():
    arguments = sys.argv[1:]
    if "--self-test" in arguments:
        return self_test()
    upstream = "--design-system" in arguments
    if upstream:
        arguments.remove("--design-system")
        if not arguments:
            print("::error::--design-system needs a stylesheet path", file=sys.stderr)
            return 2
        path = Path(arguments[0])
    else:
        path = Path(arguments[0] if arguments else "frontend/src/main.css")

    if not path.is_file():
        print(f"::error::stylesheet not found: {path}", file=sys.stderr)
        return 1

    css = path.read_text()
    try:
        modes = design_system_modes(css) if upstream else project_modes(css)
    except LookupError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 2

    pairs = DESIGN_SYSTEM_PAIRS if upstream else PROJECT_PAIRS
    page = "--bg" if upstream else "--color-bg-primary"
    return audit(modes, pairs, path.name, page)


if __name__ == "__main__":
    sys.exit(main())
