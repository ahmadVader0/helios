"""Tests for the Helios golden banner (radiating sun art + HELIOS lettering)."""

from __future__ import annotations

from io import StringIO

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

import helios.display as display
from helios.display import HELIOS_ART, build_banner_text, generate_sun

# Allowed glyphs: block elements (U+2580–U+259F) and space. Explicitly no
# emoji, pictographic characters, or line-drawing ray characters.
_SUN_CHARS = set(" █▓▒░")
_TITLE_CHARS = set(" █▄▀▐▌\\/▒▓░")


def _render_panel(text: Text) -> str:
    buffer = StringIO()
    test_console = Console(file=buffer, width=120, force_terminal=True, color_system="truecolor")
    test_console.print(Panel(text))
    return buffer.getvalue()


# ── Sun generation ─────────────────────────────────────────────────────────

def test_generate_sun_grid_is_rectangular() -> None:
    lines = generate_sun()
    assert lines
    assert len({len(line) for line in lines}) == 1


def test_generate_sun_is_round_shaded_sphere() -> None:
    text = "".join(generate_sun())
    for shade in "█▓▒░":
        assert shade in text, f"sphere shade {shade!r} missing"
    for ray_char in "│─╱╲·":
        assert ray_char not in text, f"ray character {ray_char!r} should not be in a round ball"


def test_generate_sun_is_circular_symmetric() -> None:
    lines = generate_sun(radius=5)
    height = 2 * 5 + 1
    width = 4 * 5 + 1
    assert len(lines) == height and len(lines[0]) == width
    for line in lines:
        filled = [i for i, ch in enumerate(line) if ch != " "]
        if filled:
            assert filled[0] + filled[-1] == width - 1, f"circle not symmetric: {line!r}"


def test_generate_sun_scales_with_radius() -> None:
    small = generate_sun(radius=4)
    large = generate_sun(radius=6)
    assert len(large) > len(small)
    assert len(large[0]) > len(small[0])
    assert len(small[0]) == 4 * 4 + 1
    assert len(large[0]) == 4 * 6 + 1


def test_generate_sun_uses_no_emoji() -> None:
    for line in generate_sun():
        for ch in line:
            assert ch in _SUN_CHARS, f"non-Unicode-block character {ch!r} (U+{ord(ch):04X})"


# ── HELIOS lettering ───────────────────────────────────────────────────────

def test_helios_art_is_well_formed() -> None:
    lines = HELIOS_ART.split("\n")
    assert len(lines) == 6
    assert len({len(line) for line in lines}) == 1
    for line in lines:
        for ch in line:
            assert ch in _TITLE_CHARS, f"unexpected character {ch!r} in title art"


def test_helios_art_spells_six_letters() -> None:
    from helios.display import _HELIOS_GLYPHS

    lines = HELIOS_ART.split("\n")
    expected = "HELIOS"
    for col, letter in enumerate(expected):
        glyph = "\n".join(lines[row][col * 6 : col * 6 + 5] for row in range(6))
        assert glyph == "\n".join(_HELIOS_GLYPHS[letter]), f"letter {letter!r} mismatch"


# ── Banner composition ─────────────────────────────────────────────────────

def test_build_banner_text_contains_sun_and_title() -> None:
    text = build_banner_text(radius=5)
    assert isinstance(text, Text)
    rendered = _render_panel(text)
    assert "█" in rendered
    assert "Data Movement Forensics" in rendered


def test_build_banner_text_places_helios_right_of_sun() -> None:
    text = build_banner_text(radius=5)
    lines = text.plain.split("\n")
    sun_width = 4 * 5 + 1
    title_lines = [l for l in lines if len(l) > sun_width + 5 and any(c in l[sun_width + 3 :] for c in "█")]
    assert len(title_lines) >= 6, "HELIOS block title should sit right of the sun"


def test_build_banner_text_renders_without_emoji() -> None:
    import string

    plain = build_banner_text(radius=5).plain
    allowed = _SUN_CHARS | _TITLE_CHARS | set(string.ascii_letters + string.digits + " ")
    for ch in plain:
        if ch in allowed or ch in "\n":
            continue
        raise AssertionError(f"unexpected glyph {ch!r} (U+{ord(ch):04X})")


def test_print_banner_runs() -> None:
    buffer = StringIO()
    original_console = display.console
    display.console = Console(file=buffer, width=100, force_terminal=True, color_system="truecolor")
    try:
        display.print_banner()
    finally:
        display.console = original_console
    rendered = buffer.getvalue()
    assert "█" in rendered
    assert "Data Movement Forensics" in rendered
