"""
Dark colour palette & style constants.

Central place for every colour, font, and size used across the UI.
"""

from __future__ import annotations

# ── Backgrounds ──────────────────────────────────────────────
BG_DARKEST   = "#0d0f12"   # window / root
BG_DARK      = "#141720"   # panels / cards
BG_MEDIUM    = "#1a1e2e"   # inputs / secondary panels
BG_HOVER     = "#252a3a"   # hover state
BG_SELECTED  = "#2c3250"   # active/selected state

# ── Accent colours ───────────────────────────────────────────
CYAN         = "#00e5ff"
CYAN_DIM     = "#007c8a"
MAGENTA      = "#d946ef"
MAGENTA_DIM  = "#8b1fa3"
GREEN        = "#22c55e"
GREEN_DIM    = "#15803d"
RED          = "#ef4444"
RED_DIM      = "#991b1b"
YELLOW       = "#eab308"
YELLOW_DIM   = "#a16207"
BLUE         = "#3b82f6"
BLUE_DIM     = "#1e3a8a"
ORANGE       = "#f97316"

# ── Text ─────────────────────────────────────────────────────
TEXT_PRIMARY   = "#e2e8f0"
TEXT_SECONDARY = "#94a3b8"
TEXT_MUTED     = "#64748b"
TEXT_DARK      = "#1e293b"

# ── Borders ──────────────────────────────────────────────────
BORDER         = "#2d3348"
BORDER_FOCUS   = CYAN
BORDER_SUCCESS = GREEN
BORDER_ERROR   = RED

# ── Fonts ────────────────────────────────────────────────────
FONT_FAMILY    = "Segoe UI"
FONT_MONO      = "Cascadia Code"
FONT_SIZE_SM   = 11
FONT_SIZE_MD   = 13
FONT_SIZE_LG   = 16
FONT_SIZE_XL   = 22
FONT_SIZE_TITLE = 28

# ── Dimensions ───────────────────────────────────────────────
CORNER_RADIUS  = 10
BUTTON_RADIUS  = 8
INPUT_HEIGHT   = 38
PAD_XS         = 4
PAD_SM         = 8
PAD_MD         = 16
PAD_LG         = 24
PAD_XL         = 32
