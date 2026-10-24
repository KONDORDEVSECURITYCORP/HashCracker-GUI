"""
Custom reusable widgets for the dark theme.
"""

from __future__ import annotations

import customtkinter as ctk
from . import theme as T


class GlowLabel(ctk.CTkLabel):
    """Label that optionally pulses with the accent colour."""

    def __init__(self, master, text: str = "", accent: bool = False, **kw):
        colour = T.CYAN if accent else T.TEXT_PRIMARY
        super().__init__(
            master,
            text=text,
            text_color=colour,
            font=kw.pop("font", (T.FONT_FAMILY, T.FONT_SIZE_MD)),
            **kw,
        )


class SectionTitle(ctk.CTkLabel):
    """Big section header with accent underline effect."""

    def __init__(self, master, text: str, **kw):
        super().__init__(
            master,
            text=text,
            text_color=T.CYAN,
            font=(T.FONT_FAMILY, T.FONT_SIZE_LG, "bold"),
            anchor="w",
            **kw,
        )


class DarkEntry(ctk.CTkEntry):
    """Styled text input with dark background."""

    def __init__(self, master, placeholder: str = "", **kw):
        super().__init__(
            master,
            placeholder_text=placeholder,
            font=(T.FONT_MONO, T.FONT_SIZE_MD),
            height=T.INPUT_HEIGHT,
            corner_radius=T.BUTTON_RADIUS,
            fg_color=T.BG_MEDIUM,
            border_color=T.BORDER,
            text_color=T.TEXT_PRIMARY,
            placeholder_text_color=T.TEXT_MUTED,
            **kw,
        )

    def set_text(self, text: str) -> None:
        self.delete(0, "end")
        self.insert(0, text)


class AccentButton(ctk.CTkButton):
    """Primary action button with accent gradient feel."""

    def __init__(self, master, text: str = "", **kw):
        super().__init__(
            master,
            text=text,
            font=(T.FONT_FAMILY, T.FONT_SIZE_MD, "bold"),
            height=40,
            corner_radius=T.BUTTON_RADIUS,
            fg_color=T.CYAN_DIM,
            hover_color=T.CYAN,
            text_color=T.BG_DARKEST,
            **kw,
        )


class SecondaryButton(ctk.CTkButton):
    """Ghost-style button."""

    def __init__(self, master, text: str = "", **kw):
        super().__init__(
            master,
            text=text,
            font=(T.FONT_FAMILY, T.FONT_SIZE_MD),
            height=36,
            corner_radius=T.BUTTON_RADIUS,
            fg_color="transparent",
            hover_color=T.BG_HOVER,
            border_width=1,
            border_color=T.BORDER,
            text_color=T.TEXT_SECONDARY,
            **kw,
        )


class MagentaButton(ctk.CTkButton):
    """Magenta accent button for secondary actions."""

    def __init__(self, master, text: str = "", **kw):
        super().__init__(
            master,
            text=text,
            font=(T.FONT_FAMILY, T.FONT_SIZE_MD, "bold"),
            height=40,
            corner_radius=T.BUTTON_RADIUS,
            fg_color=T.MAGENTA_DIM,
            hover_color=T.MAGENTA,
            text_color=T.TEXT_PRIMARY,
            **kw,
        )


class DarkCard(ctk.CTkFrame):
    """Rounded card container with dark background."""

    def __init__(self, master, **kw):
        super().__init__(
            master,
            fg_color=T.BG_DARK,
            corner_radius=T.CORNER_RADIUS,
            border_width=1,
            border_color=T.BORDER,
            **kw,
        )


class StatusBadge(ctk.CTkLabel):
    """Small coloured badge for status indicators."""

    def __init__(self, master, text: str = "", colour: str = T.TEXT_MUTED, **kw):
        super().__init__(
            master,
            text=f"  {text}  ",
            text_color=T.BG_DARKEST,
            fg_color=colour,
            corner_radius=4,
            font=(T.FONT_FAMILY, T.FONT_SIZE_SM, "bold"),
            **kw,
        )

    def set_status(self, text: str, colour: str) -> None:
        self.configure(text=f"  {text}  ", fg_color=colour)


class OutputConsole(ctk.CTkTextbox):
    """Read-only dark console-style text area."""

    def __init__(self, master, **kw):
        super().__init__(
            master,
            font=(T.FONT_MONO, T.FONT_SIZE_SM),
            fg_color=T.BG_DARKEST,
            text_color=T.TEXT_SECONDARY,
            border_width=1,
            border_color=T.BORDER,
            corner_radius=T.BUTTON_RADIUS,
            wrap="word",
            state="disabled",
            **kw,
        )
        # Colour tags
        self.tag_config("success", foreground=T.GREEN)
        self.tag_config("error", foreground=T.RED)
        self.tag_config("info", foreground=T.BLUE)
        self.tag_config("accent", foreground=T.CYAN)
        self.tag_config("speed", foreground=T.MAGENTA)
        self.tag_config("warning", foreground=T.YELLOW)
        self.tag_config("cracked", foreground=T.GREEN, underline=True)

    def append(self, text: str, tag: str = "") -> None:
        self.configure(state="normal")
        if tag:
            self.insert("end", text + "\n", tag)
        else:
            self.insert("end", text + "\n")
        self.see("end")
        self.configure(state="disabled")

    def clear(self) -> None:
        self.configure(state="normal")
        self.delete("1.0", "end")
        self.configure(state="disabled")

    def append_coloured(self, line: str) -> None:
        """Auto-colour a hashcat output line."""
        lower = line.lower()
        if "cracked" in lower or "recovered" in lower:
            self.append(line, "cracked")
        elif "speed" in lower:
            self.append(line, "speed")
        elif "status" in lower or "progress" in lower:
            self.append(line, "info")
        elif "error" in lower or "failed" in lower:
            self.append(line, "error")
        elif "session" in lower:
            self.append(line, "accent")
        else:
            self.append(line)
