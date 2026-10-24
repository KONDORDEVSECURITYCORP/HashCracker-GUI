"""
HashCracker GUI — main application window.
"""

from __future__ import annotations

import threading
from pathlib import Path
from tkinter import filedialog

import customtkinter as ctk

from . import theme as T
from .config import AppConfig
from .auto_attack import (
    AttackStage,
    AutoAttackResult,
    StageStatus,
    build_stages,
    run_auto_attack,
)
from .smart_attack import build_smart_stages
from .hybrid_attack import build_hybrid_stages
from .core import AttackMode, CrackJob, hashcat_version, run_hashcat
from .detector import detect_hash
from .results import CrackResult, ResultsStore
from .dump_parser import DumpResult, parse_dump_file, write_hashcat_file, map_results
from .widgets import (
    AccentButton,
    DarkCard,
    DarkEntry,
    GlowLabel,
    MagentaButton,
    OutputConsole,
    SecondaryButton,
    SectionTitle,
    StatusBadge,
)


# ── CustomTkinter global appearance ─────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


class HashCrackerApp(ctk.CTk):
    """Root window — single-window layout with sidebar + main area."""

    def __init__(self) -> None:
        super().__init__()

        self.cfg = AppConfig.load()

        # Window setup
        self.title("HashCracker")
        self.geometry(f"{self.cfg.window_width}x{self.cfg.window_height}")
        self.minsize(900, 650)
        self.configure(fg_color=T.BG_DARKEST)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self._running = False
        self._stop_auto = False
        self._proc_ref: list = []
        self._thread: threading.Thread | None = None
        self._results = ResultsStore()
        self._detected_algo: str = ""
        self._dump_data: DumpResult | None = None  # active when SQL dump mode

        self._build_ui()
        self._restore_state()

    # ── UI construction ──────────────────────────────────────

    def _build_ui(self) -> None:
        # Grid: sidebar (fixed) | main (expand)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main()

    # ── Sidebar ──────────────────────────────────────────────

    def _build_sidebar(self) -> None:
        sidebar = ctk.CTkFrame(self, fg_color=T.BG_DARK, corner_radius=0, width=310)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)

        pad = {"padx": T.PAD_MD, "pady": (T.PAD_XS, T.PAD_XS)}

        # ── Title ────────────────────────────────────────────
        title_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        title_frame.pack(fill="x", padx=T.PAD_MD, pady=(T.PAD_LG, T.PAD_SM))

        ctk.CTkLabel(
            title_frame,
            text="⚡ HASH",
            font=(T.FONT_FAMILY, T.FONT_SIZE_TITLE, "bold"),
            text_color=T.CYAN,
        ).pack(side="left")
        ctk.CTkLabel(
            title_frame,
            text="CRACK",
            font=(T.FONT_FAMILY, T.FONT_SIZE_TITLE, "bold"),
            text_color=T.MAGENTA,
        ).pack(side="left")

        ctk.CTkLabel(
            sidebar,
            text="Modern Hashcat Frontend  v1.0",
            font=(T.FONT_FAMILY, T.FONT_SIZE_SM),
            text_color=T.TEXT_MUTED,
        ).pack(padx=T.PAD_MD, anchor="w")

        # Separator
        ctk.CTkFrame(sidebar, fg_color=T.BORDER, height=1).pack(
            fill="x", padx=T.PAD_MD, pady=T.PAD_MD
        )

        # ── Hashcat path ─────────────────────────────────────
        SectionTitle(sidebar, text="🔧  Hashcat").pack(fill="x", **pad)

        path_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        path_frame.pack(fill="x", padx=T.PAD_MD, pady=T.PAD_XS)

        self.entry_hc_path = DarkEntry(path_frame, placeholder="Ruta a hashcat.exe")
        self.entry_hc_path.pack(side="left", fill="x", expand=True, padx=(0, T.PAD_SM))

        SecondaryButton(
            path_frame, text="📂", width=40, command=self._browse_hashcat
        ).pack(side="right")

        self.lbl_hc_version = GlowLabel(sidebar, text="", accent=True)
        self.lbl_hc_version.pack(padx=T.PAD_MD, anchor="w")

        # ── Hash input ───────────────────────────────────────
        ctk.CTkFrame(sidebar, fg_color=T.BORDER, height=1).pack(
            fill="x", padx=T.PAD_MD, pady=T.PAD_MD
        )
        SectionTitle(sidebar, text="🔑  Hash objetivo").pack(fill="x", **pad)

        hash_buttons = ctk.CTkFrame(sidebar, fg_color="transparent")
        hash_buttons.pack(fill="x", padx=T.PAD_MD, pady=T.PAD_XS)
        SecondaryButton(
            hash_buttons, text="📄 Desde archivo", command=self._load_hash_file
        ).pack(side="left", padx=(0, T.PAD_SM))
        SecondaryButton(
            hash_buttons, text="🔍 Detectar", command=self._detect_algo
        ).pack(side="left")

        self.entry_hash = ctk.CTkTextbox(
            sidebar,
            font=(T.FONT_MONO, T.FONT_SIZE_SM),
            fg_color=T.BG_MEDIUM,
            text_color=T.TEXT_PRIMARY,
            border_width=1,
            border_color=T.BORDER,
            corner_radius=T.BUTTON_RADIUS,
            height=70,
            wrap="char",
        )
        self.entry_hash.pack(fill="x", padx=T.PAD_MD, pady=T.PAD_XS)

        # Multi-hash checkbox
        multi_row = ctk.CTkFrame(sidebar, fg_color="transparent")
        multi_row.pack(fill="x", padx=T.PAD_MD, pady=(T.PAD_XS, 0))
        self.var_multi = ctk.BooleanVar(value=False)
        self.chk_multi = ctk.CTkCheckBox(
            multi_row,
            text="Múltiples hashes (archivo con varios)",
            variable=self.var_multi,
            font=(T.FONT_FAMILY, T.FONT_SIZE_SM),
            text_color=T.TEXT_SECONDARY,
            fg_color=T.MAGENTA_DIM,
            hover_color=T.MAGENTA,
            border_color=T.BORDER,
        )
        self.chk_multi.pack(side="left")
        self.lbl_hash_count = GlowLabel(
            multi_row, text="", font=(T.FONT_FAMILY, T.FONT_SIZE_SM)
        )
        self.lbl_hash_count.pack(side="right")

        # SQL Dump mode (email:hash)
        dump_row = ctk.CTkFrame(sidebar, fg_color="transparent")
        dump_row.pack(fill="x", padx=T.PAD_MD, pady=(T.PAD_XS, 0))
        self.var_dump = ctk.BooleanVar(value=False)
        self.chk_dump = ctk.CTkCheckBox(
            dump_row,
            text="📧 SQL Dump (email:hash)",
            variable=self.var_dump,
            font=(T.FONT_FAMILY, T.FONT_SIZE_SM),
            text_color=T.TEXT_SECONDARY,
            fg_color=T.ORANGE,
            hover_color=T.YELLOW,
            border_color=T.BORDER,
            command=self._on_dump_toggle,
        )
        self.chk_dump.pack(side="left")
        self.lbl_dump_status = GlowLabel(
            dump_row, text="", font=(T.FONT_FAMILY, T.FONT_SIZE_SM)
        )
        self.lbl_dump_status.pack(side="right")

        # Detection result
        self.lbl_detected = GlowLabel(sidebar, text="Algoritmo: —", accent=True)
        self.lbl_detected.pack(padx=T.PAD_MD, anchor="w", pady=(T.PAD_XS, 0))

        # Manual mode
        mode_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        mode_frame.pack(fill="x", padx=T.PAD_MD, pady=T.PAD_XS)
        GlowLabel(mode_frame, text="Modo:", font=(T.FONT_FAMILY, T.FONT_SIZE_SM)).pack(
            side="left", padx=(0, T.PAD_SM)
        )
        self.entry_mode = DarkEntry(mode_frame, placeholder="auto")
        self.entry_mode.pack(side="left", fill="x", expand=True)

        # ── Attack config ────────────────────────────────────
        ctk.CTkFrame(sidebar, fg_color=T.BORDER, height=1).pack(
            fill="x", padx=T.PAD_MD, pady=T.PAD_MD
        )
        SectionTitle(sidebar, text="⚔️  Ataque").pack(fill="x", **pad)

        self.combo_attack = ctk.CTkComboBox(
            sidebar,
            values=[
                "🔥 — Hybrid Smart (dict+mask)",
                "⚡ — Auto (recomendado)",
                "🧠 — Smart (inteligente)",
                "0 — Diccionario",
                "3 — Fuerza bruta / Mask",
                "6 — Híbrido WL + Mask",
                "7 — Híbrido Mask + WL",
            ],
            font=(T.FONT_FAMILY, T.FONT_SIZE_MD),
            dropdown_font=(T.FONT_FAMILY, T.FONT_SIZE_MD),
            fg_color=T.BG_MEDIUM,
            border_color=T.BORDER,
            button_color=T.CYAN_DIM,
            button_hover_color=T.CYAN,
            dropdown_fg_color=T.BG_DARK,
            dropdown_hover_color=T.BG_HOVER,
            text_color=T.TEXT_PRIMARY,
            dropdown_text_color=T.TEXT_PRIMARY,
            corner_radius=T.BUTTON_RADIUS,
            command=self._on_attack_change,
        )
        self.combo_attack.set("🔥 — Hybrid Smart (dict+mask)")
        self.combo_attack.pack(fill="x", padx=T.PAD_MD, pady=T.PAD_XS)

        # Wordlist
        self.frame_wordlist = ctk.CTkFrame(sidebar, fg_color="transparent")
        self.frame_wordlist.pack(fill="x", padx=T.PAD_MD, pady=T.PAD_XS)
        GlowLabel(self.frame_wordlist, text="Wordlist:", font=(T.FONT_FAMILY, T.FONT_SIZE_SM)).pack(
            anchor="w"
        )
        wl_row = ctk.CTkFrame(self.frame_wordlist, fg_color="transparent")
        wl_row.pack(fill="x")
        self.entry_wordlist = DarkEntry(wl_row, placeholder="rockyou.txt …")
        self.entry_wordlist.pack(side="left", fill="x", expand=True, padx=(0, T.PAD_SM))
        SecondaryButton(wl_row, text="📂", width=40, command=self._browse_wordlist).pack(
            side="right"
        )

        # Mask
        self.frame_mask = ctk.CTkFrame(sidebar, fg_color="transparent")
        self.frame_mask.pack(fill="x", padx=T.PAD_MD, pady=T.PAD_XS)
        mask_header = ctk.CTkFrame(self.frame_mask, fg_color="transparent")
        mask_header.pack(fill="x")
        GlowLabel(mask_header, text="Máscara:", font=(T.FONT_FAMILY, T.FONT_SIZE_SM)).pack(
            side="left"
        )
        SecondaryButton(
            mask_header, text="❓", width=30, command=self._show_mask_help
        ).pack(side="right")
        self.entry_mask = DarkEntry(self.frame_mask, placeholder="?a?a?a?a?a?a?a?a")
        self.entry_mask.pack(fill="x", pady=(T.PAD_XS, 0))

        # Increment
        self.var_increment = ctk.BooleanVar(value=False)
        self.chk_increment = ctk.CTkCheckBox(
            self.frame_mask,
            text="Incremento de longitud",
            variable=self.var_increment,
            font=(T.FONT_FAMILY, T.FONT_SIZE_SM),
            text_color=T.TEXT_SECONDARY,
            fg_color=T.CYAN_DIM,
            hover_color=T.CYAN,
            border_color=T.BORDER,
            command=self._toggle_increment,
        )
        self.chk_increment.pack(anchor="w", pady=(T.PAD_XS, 0))

        self.frame_increment = ctk.CTkFrame(self.frame_mask, fg_color="transparent")
        inc_row = self.frame_increment
        GlowLabel(inc_row, text="Min:", font=(T.FONT_FAMILY, T.FONT_SIZE_SM)).pack(side="left")
        self.entry_inc_min = DarkEntry(inc_row, placeholder="1")
        self.entry_inc_min.configure(width=50)
        self.entry_inc_min.pack(side="left", padx=(T.PAD_XS, T.PAD_SM))
        GlowLabel(inc_row, text="Max:", font=(T.FONT_FAMILY, T.FONT_SIZE_SM)).pack(side="left")
        self.entry_inc_max = DarkEntry(inc_row, placeholder="8")
        self.entry_inc_max.configure(width=50)
        self.entry_inc_max.pack(side="left", padx=T.PAD_XS)

        # Start / Stop
        ctk.CTkFrame(sidebar, fg_color=T.BORDER, height=1).pack(
            fill="x", padx=T.PAD_MD, pady=T.PAD_MD
        )

        btn_row = ctk.CTkFrame(sidebar, fg_color="transparent")
        btn_row.pack(fill="x", padx=T.PAD_MD, pady=T.PAD_SM)

        self.btn_start = AccentButton(btn_row, text="▶  INICIAR", command=self._start)
        self.btn_start.pack(side="left", fill="x", expand=True, padx=(0, T.PAD_SM))

        self.btn_stop = MagentaButton(btn_row, text="■  DETENER", command=self._stop)
        self.btn_stop.pack(side="right", fill="x", expand=True)
        self.btn_stop.configure(state="disabled")

        # Initially show hybrid mode layout
        self._on_attack_change("🔥 — Hybrid Smart (dict+mask)")

    # ── Main area ────────────────────────────────────────────

    def _build_main(self) -> None:
        main = ctk.CTkFrame(self, fg_color=T.BG_DARKEST, corner_radius=0)
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_rowconfigure(1, weight=1)
        main.grid_columnconfigure(0, weight=1)

        # Top bar
        topbar = ctk.CTkFrame(main, fg_color=T.BG_DARK, height=50, corner_radius=0)
        topbar.grid(row=0, column=0, sticky="ew")
        topbar.grid_propagate(False)

        self.status_badge = StatusBadge(topbar, text="LISTO", colour=T.CYAN_DIM)
        self.status_badge.pack(side="left", padx=T.PAD_MD, pady=T.PAD_SM)

        self.lbl_command = ctk.CTkLabel(
            topbar,
            text="",
            font=(T.FONT_MONO, T.FONT_SIZE_SM),
            text_color=T.TEXT_MUTED,
            anchor="w",
        )
        self.lbl_command.pack(side="left", fill="x", expand=True, padx=T.PAD_SM)

        SecondaryButton(topbar, text="🗑 Limpiar", width=90, command=self._clear_console).pack(
            side="right", padx=T.PAD_MD, pady=T.PAD_SM
        )

        SecondaryButton(topbar, text="💾 Exportar", width=90, command=self._export_results).pack(
            side="right", padx=(0, T.PAD_SM), pady=T.PAD_SM
        )

        SecondaryButton(topbar, text="📋 Historial", width=100, command=self._show_history).pack(
            side="right", padx=(0, T.PAD_SM), pady=T.PAD_SM
        )

        self.lbl_history_count = GlowLabel(
            topbar, text=f"🔓 {self._results.count()}", accent=True,
            font=(T.FONT_FAMILY, T.FONT_SIZE_SM),
        )
        self.lbl_history_count.pack(side="right", padx=(0, T.PAD_SM), pady=T.PAD_SM)

        # Console
        self.console = OutputConsole(main)
        self.console.grid(row=1, column=0, sticky="nsew", padx=T.PAD_MD, pady=T.PAD_MD)

        # Result bar
        self.result_bar = DarkCard(main)
        self.result_bar.grid(row=2, column=0, sticky="ew", padx=T.PAD_MD, pady=(0, T.PAD_MD))

        self.lbl_result_icon = ctk.CTkLabel(
            self.result_bar,
            text="🔒",
            font=(T.FONT_FAMILY, T.FONT_SIZE_XL),
        )
        self.lbl_result_icon.pack(side="left", padx=T.PAD_MD, pady=T.PAD_SM)

        self.lbl_result_text = ctk.CTkLabel(
            self.result_bar,
            text="Esperando ejecución…",
            font=(T.FONT_MONO, T.FONT_SIZE_LG),
            text_color=T.TEXT_SECONDARY,
            anchor="w",
        )
        self.lbl_result_text.pack(side="left", fill="x", expand=True, pady=T.PAD_SM)

        # Welcome message
        self.console.append("╔═══════════════════════════════════════════════════╗", "accent")
        self.console.append("║        ⚡ HASHCRACK — Modern Hashcat GUI         ║", "accent")
        self.console.append("╚═══════════════════════════════════════════════════╝", "accent")
        self.console.append("")
        self.console.append("  1. Configura la ruta de hashcat en el panel izquierdo", "info")
        self.console.append("  2. Ingresa o carga un hash", "info")
        self.console.append("  3. Haz clic en 'Detectar' para identificar el algoritmo", "info")
        self.console.append("  4. Elige modo de ataque y parámetros", "info")
        self.console.append("  5. Presiona INICIAR", "info")
        self.console.append("")

    # ── Actions ──────────────────────────────────────────────

    def _on_dump_toggle(self) -> None:
        """When dump checkbox changes, re-parse the loaded file."""
        if self.var_dump.get():
            raw = self.entry_hash.get("1.0", "end").strip()
            p = Path(raw)
            if p.is_file():
                self._parse_dump(raw)
            else:
                self.lbl_dump_status.configure(text="Carga un archivo", text_color=T.YELLOW)
        else:
            self._dump_data = None
            self.lbl_dump_status.configure(text="")

    def _parse_dump(self, filepath: str) -> None:
        """Parse dump file and create hashcat-ready file."""
        dump = parse_dump_file(filepath)
        if dump.errors:
            self.console.append(f"⚠ {dump.errors[0]}", "warning")
            self.lbl_dump_status.configure(text="Error", text_color=T.RED)
            self._dump_data = None
            return

        self._dump_data = dump

        # Write pure-hash file for hashcat
        hc_path = self.entry_hc_path.get().strip()
        hashcat_dir = str(Path(hc_path).parent) if hc_path else str(Path(filepath).parent)
        hash_file = str(Path(hashcat_dir) / "dump_hashes.txt")
        write_hashcat_file(dump.hashes, hash_file)

        # Update UI: put the hash file path in the entry
        self.entry_hash.delete("1.0", "end")
        self.entry_hash.insert("1.0", hash_file)
        self.var_multi.set(True)
        self.lbl_hash_count.configure(text=f"{dump.total_records} hashes", text_color=T.MAGENTA)
        self.lbl_dump_status.configure(
            text=f"✔ {dump.total_records} emails ({dump.format_detected})",
            text_color=T.GREEN,
        )
        self.console.append(f"📧 Dump parseado: {dump.total_records} registros ({dump.format_detected})", "success")
        self.console.append(f"   Hashes únicos: {len(dump.hashes)}", "info")
        self.console.append(f"   Archivo hashcat: {hash_file}", "info")

    def _browse_hashcat(self) -> None:
        path = filedialog.askopenfilename(
            title="Selecciona hashcat.exe",
            filetypes=[("Ejecutable", "*.exe"), ("Todos", "*.*")],
        )
        if path:
            self.entry_hc_path.set_text(path)
            ver = hashcat_version(path)
            if ver:
                self.lbl_hc_version.configure(text=f"✔ {ver}", text_color=T.GREEN)
                self.cfg.hashcat_path = path
                self.cfg.save()
            else:
                self.lbl_hc_version.configure(text="⚠ No se pudo verificar", text_color=T.YELLOW)

    def _browse_wordlist(self) -> None:
        path = filedialog.askopenfilename(
            title="Selecciona wordlist",
            filetypes=[("Text", "*.txt"), ("Todos", "*.*")],
        )
        if path:
            self.entry_wordlist.set_text(path)

    def _load_hash_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Selecciona archivo con hash",
            filetypes=[
                ("Hash files", "*.txt *.hash *.hc22000 *.hccapx"),
                ("Todos", "*.*"),
            ],
        )
        if path:
            self.entry_hash.delete("1.0", "end")
            self.entry_hash.insert("1.0", path)
            # Count hashes in file
            try:
                lines = Path(path).read_text(encoding="utf-8", errors="replace").strip().splitlines()
                count = len([l for l in lines if l.strip()])
                if count > 1:
                    self.var_multi.set(True)
                    self.lbl_hash_count.configure(text=f"{count} hashes", text_color=T.MAGENTA)
                else:
                    self.var_multi.set(False)
                    self.lbl_hash_count.configure(text="1 hash", text_color=T.CYAN)
                self.console.append(f"📄 Archivo cargado: {path} ({count} hashes)", "info")
            except Exception:
                self.console.append(f"📄 Archivo cargado: {path}", "info")

            # Auto-detect dump format if checkbox is on
            if self.var_dump.get():
                self._parse_dump(path)
            else:
                # Check if it looks like a dump (has @ in lines)
                try:
                    sample = Path(path).read_text(encoding="utf-8", errors="replace")[:2000]
                    if "@" in sample and ":" in sample:
                        self.var_dump.set(True)
                        self._parse_dump(path)
                        self.console.append("   ℹ Auto-detectado como SQL dump (email:hash)", "info")
                except Exception:
                    pass

    def _detect_algo(self) -> None:
        raw = self.entry_hash.get("1.0", "end").strip()
        if not raw:
            self.console.append("⚠ Ingresa un hash primero.", "warning")
            return

        # If it is a file, read first line
        detect_target = raw
        p = Path(raw)
        if p.is_file():
            lines = p.read_text(encoding="utf-8", errors="replace").strip().splitlines()
            if lines:
                detect_target = lines[0].strip()
                self.console.append(f"📄 Analizando primera línea del archivo…", "info")

        matches = detect_hash(detect_target)

        if not matches:
            self.lbl_detected.configure(text="Algoritmo: No detectado ⚠", text_color=T.YELLOW)
            self.console.append("⚠ No se detectó el algoritmo. Ingresa el modo manualmente.", "warning")
            return

        best = matches[0]
        self._detected_algo = best.name
        self.lbl_detected.configure(
            text=f"Algoritmo: {best.name} (modo {best.mode})", text_color=T.GREEN
        )
        self.entry_mode.set_text(str(best.mode))
        self.console.append(f"🔍 Detectado: {best.name} — modo hashcat {best.mode}", "success")

        if len(matches) > 1:
            self.console.append("   Otros posibles:", "info")
            for m in matches[1:]:
                self.console.append(f"     • {m.name} (modo {m.mode})", "info")

    def _on_attack_change(self, choice: str) -> None:
        is_auto = choice.startswith("⚡") or choice.startswith("🧠") or choice.startswith("🔥")

        if is_auto:
            # Auto mode: show wordlist (optional), hide mask
            self.frame_wordlist.pack(fill="x", padx=T.PAD_MD, pady=T.PAD_XS)
            self.frame_mask.pack_forget()
            return

        mode = int(choice.split("—")[0].strip())
        needs_wordlist = mode in (0, 6, 7)
        needs_mask = mode in (3, 6, 7)

        if needs_wordlist:
            self.frame_wordlist.pack(fill="x", padx=T.PAD_MD, pady=T.PAD_XS)
        else:
            self.frame_wordlist.pack_forget()

        if needs_mask:
            self.frame_mask.pack(fill="x", padx=T.PAD_MD, pady=T.PAD_XS)
        else:
            self.frame_mask.pack_forget()

    def _toggle_increment(self) -> None:
        if self.var_increment.get():
            self.frame_increment.pack(fill="x", pady=(T.PAD_XS, 0))
        else:
            self.frame_increment.pack_forget()

    def _show_mask_help(self) -> None:
        win = ctk.CTkToplevel(self)
        win.title("Referencia de Máscaras")
        win.geometry("520x420")
        win.configure(fg_color=T.BG_DARKEST)
        win.attributes("-topmost", True)
        win.after(200, lambda: win.attributes("-topmost", False))

        ctk.CTkLabel(
            win,
            text="🎭 Máscaras Hashcat",
            font=(T.FONT_FAMILY, T.FONT_SIZE_LG, "bold"),
            text_color=T.CYAN,
        ).pack(pady=(T.PAD_LG, T.PAD_SM))

        data = [
            ("?l", "Minúsculas (a-z)", "?l?l?l?l = aaaa-zzzz"),
            ("?u", "Mayúsculas (A-Z)", "?u?u?u?u = AAAA-ZZZZ"),
            ("?d", "Dígitos (0-9)", "?d?d?d?d = 0000-9999"),
            ("?s", "Especiales (!@#…)", "?s?s = todos los símbolos"),
            ("?a", "Todos imprimibles", "?a?a?a = todo combinado"),
            ("?b", "Bytes 0x00-0xff", "Rango completo"),
            ("?h", "Hex min (0-f)", "?h?h?h?h = 0000-ffff"),
            ("?H", "Hex may (0-F)", "?H?H?H?H = 0000-FFFF"),
        ]

        table = ctk.CTkFrame(win, fg_color=T.BG_DARK, corner_radius=T.CORNER_RADIUS)
        table.pack(fill="both", expand=True, padx=T.PAD_LG, pady=T.PAD_MD)

        # Header
        hdr = ctk.CTkFrame(table, fg_color=T.BG_MEDIUM, corner_radius=0)
        hdr.pack(fill="x", padx=2, pady=(2, 0))
        for col, w in [("Charset", 80), ("Descripción", 200), ("Ejemplo", 200)]:
            ctk.CTkLabel(
                hdr, text=col, font=(T.FONT_FAMILY, T.FONT_SIZE_SM, "bold"),
                text_color=T.MAGENTA, width=w, anchor="w",
            ).pack(side="left", padx=T.PAD_SM, pady=T.PAD_XS)

        for i, (cs, desc, ex) in enumerate(data):
            bg = T.BG_DARK if i % 2 == 0 else T.BG_MEDIUM
            row = ctk.CTkFrame(table, fg_color=bg, corner_radius=0)
            row.pack(fill="x", padx=2)
            ctk.CTkLabel(row, text=cs, font=(T.FONT_MONO, T.FONT_SIZE_SM),
                         text_color=T.CYAN, width=80, anchor="w").pack(side="left", padx=T.PAD_SM, pady=2)
            ctk.CTkLabel(row, text=desc, font=(T.FONT_FAMILY, T.FONT_SIZE_SM),
                         text_color=T.TEXT_PRIMARY, width=200, anchor="w").pack(side="left", padx=T.PAD_SM, pady=2)
            ctk.CTkLabel(row, text=ex, font=(T.FONT_MONO, T.FONT_SIZE_SM),
                         text_color=T.TEXT_MUTED, width=200, anchor="w").pack(side="left", padx=T.PAD_SM, pady=2)

        AccentButton(win, text="Cerrar", command=win.destroy, width=120).pack(pady=T.PAD_MD)

    # ── Hashcat execution ────────────────────────────────────

    def _get_attack_mode(self) -> AttackMode:
        raw = self.combo_attack.get()
        num = int(raw.split("—")[0].strip())
        try:
            return AttackMode(num)
        except ValueError:
            return AttackMode.BRUTE_FORCE

    def _validate(self) -> CrackJob | None:
        hc_path = self.entry_hc_path.get().strip()
        if not hc_path or not Path(hc_path).is_file():
            self.console.append("✖ Ruta de hashcat no válida.", "error")
            return None

        hash_val = self.entry_hash.get("1.0", "end").strip()
        if not hash_val:
            self.console.append("✖ Ingresa un hash.", "error")
            return None

        mode_str = self.entry_mode.get().strip()
        if not mode_str or not mode_str.isdigit():
            self.console.append("✖ Modo de hash inválido. Usa 'Detectar' o ingresa un número.", "error")
            return None
        hash_mode = int(mode_str)

        attack = self._get_attack_mode()
        wordlist = self.entry_wordlist.get().strip()
        mask = self.entry_mask.get().strip()

        increment = self.var_increment.get()
        inc_min = 1
        inc_max = 8
        if increment:
            try:
                inc_min = int(self.entry_inc_min.get().strip() or "1")
                inc_max = int(self.entry_inc_max.get().strip() or "8")
            except ValueError:
                pass

        output_file = str(Path(hc_path).parent / "cracked.txt")

        return CrackJob(
            hashcat_path=hc_path,
            hash_value=hash_val,
            hash_mode=hash_mode,
            attack_mode=attack,
            wordlist=wordlist,
            mask=mask,
            increment=increment,
            increment_min=inc_min,
            increment_max=inc_max,
            output_file=output_file,
            extra_args=["--potfile-disable"],
        )

    def _start(self) -> None:
        if self._running:
            return

        # ── Check if Auto mode selected ──────────────────────
        is_auto = self.combo_attack.get().startswith("⚡")
        is_smart = self.combo_attack.get().startswith("🧠")
        is_hybrid = self.combo_attack.get().startswith("🔥")
        if is_auto or is_smart or is_hybrid:
            self._start_auto(smart=is_smart, hybrid=is_hybrid)
            return

        job = self._validate()
        if job is None:
            return

        self._running = True
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.status_badge.set_status("EJECUTANDO", T.MAGENTA)
        self.lbl_result_icon.configure(text="⏳")
        self.lbl_result_text.configure(text="Procesando…", text_color=T.YELLOW)

        cmd_str = " ".join(job.build_command())
        self.lbl_command.configure(text=cmd_str)
        self.console.append("")
        self.console.append(f"▶ {cmd_str}", "accent")
        self.console.append("─" * 60, "accent")

        self._thread = threading.Thread(target=self._run_worker, args=(job,), daemon=True)
        self._thread.start()

    def _run_worker(self, job: CrackJob) -> None:
        cracked: str | None = None

        try:
            for line in run_hashcat(job, proc_ref=self._proc_ref):
                if not line:
                    continue
                # Schedule UI update on main thread
                self.after(0, self.console.append_coloured, line)

                # Check for cracked result
                if ":" in line and not line.startswith("Session") and not line.startswith("["):
                    parts = line.split(":", 1)
                    if len(parts) == 2 and parts[1]:
                        cracked = line
        except Exception as exc:
            self.after(0, self.console.append, f"✖ Error: {exc}", "error")

        # Check output file
        if job.output_file:
            out_path = Path(job.output_file)
            if out_path.is_file():
                content = out_path.read_text(encoding="utf-8", errors="replace").strip()
                if content:
                    cracked = content

        self.after(0, self._on_finished, cracked)

    # ── Auto-attack methods ──────────────────────────────────

    def _start_auto(self, smart: bool = False, hybrid: bool = False) -> None:
        """Launch the multi-stage auto, smart, or hybrid attack."""
        hc_path = self.entry_hc_path.get().strip()
        if not hc_path or not Path(hc_path).is_file():
            self.console.append("✖ Ruta de hashcat no válida.", "error")
            return

        hash_val = self.entry_hash.get("1.0", "end").strip()
        if not hash_val:
            self.console.append("✖ Ingresa un hash.", "error")
            return

        mode_str = self.entry_mode.get().strip()
        if not mode_str or not mode_str.isdigit():
            self.console.append("✖ Modo de hash inválido. Usa 'Detectar' primero.", "error")
            return

        hash_mode = int(mode_str)
        wordlist = self.entry_wordlist.get().strip()
        hashcat_dir = str(Path(hc_path).parent)

        if hybrid:
            if not wordlist or not Path(wordlist).is_file():
                self.console.append("⚠ Hybrid Smart requiere un wordlist. Cambiando a Smart…", "warning")
                hybrid = False
                smart = True

        if hybrid:
            stages = build_hybrid_stages(wordlist=wordlist, hashcat_dir=hashcat_dir)
            engine_name = "🔥 HYBRID SMART"
            badge_text = "HYBRID 🔥"
        elif smart:
            stages = build_smart_stages(wordlist=wordlist, hashcat_dir=hashcat_dir)
            engine_name = "🧠 SMART ATTACK"
            badge_text = "SMART 🧠"
        else:
            stages = build_stages(wordlist=wordlist, hashcat_dir=hashcat_dir)
            engine_name = "⚡ AUTO-ATTACK"
            badge_text = "AUTO ⚡"

        self._running = True
        self._stop_auto = False
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.status_badge.set_status(badge_text, T.MAGENTA)
        self.lbl_result_icon.configure(text="⚡" if not smart and not hybrid else "🧠" if smart else "🔥")
        self.lbl_result_text.configure(text=f"{engine_name}: {len(stages)} etapas", text_color=T.YELLOW)

        self.console.append("")
        self.console.append("╔═══════════════════════════════════════════════════╗", "accent")
        self.console.append(f"║        {engine_name} ENGINE INICIADO          ║", "accent")
        self.console.append("╚═══════════════════════════════════════════════════╝", "accent")
        self.console.append(f"  Modo hash: {hash_mode}  |  Etapas: {len(stages)}", "info")
        if wordlist:
            self.console.append(f"  Wordlist: {wordlist}", "info")
        else:
            self.console.append("  ⚠ Sin wordlist — se omitirán etapas de diccionario", "warning")
        self.console.append("")

        self._thread = threading.Thread(
            target=self._run_auto_worker,
            args=(hc_path, hash_val, hash_mode, stages),
            daemon=True,
        )
        self._thread.start()

    def _run_auto_worker(
        self,
        hc_path: str,
        hash_val: str,
        hash_mode: int,
        stages: list[AttackStage],
    ) -> None:
        """Worker thread for auto-attack chain."""

        def on_stage_start(idx: int, stage: AttackStage) -> None:
            msg = (
                f"┌─ Etapa {idx + 1}/{len(stages)}: {stage.name}\n"
                f"│  {stage.description}\n"
                f"│  Tiempo estimado: {stage.estimated_time}"
            )
            for line in msg.split("\n"):
                self.after(0, self.console.append, line, "accent")
            self.after(
                0,
                self.lbl_command.configure,
                {"text": f"[{idx + 1}/{len(stages)}] {stage.name}"},
            )
            self.after(
                0,
                self.lbl_result_text.configure,
                {"text": f"Etapa {idx + 1}/{len(stages)}: {stage.name}", "text_color": T.YELLOW},
            )

        def on_line(line: str) -> None:
            self.after(0, self.console.append_coloured, line)

        def on_stage_end(idx: int, stage: AttackStage) -> None:
            status_map = {
                StageStatus.CRACKED: ("CRACKEADO ✔", "success"),
                StageStatus.EXHAUSTED: ("agotado", "warning"),
                StageStatus.STOPPED: ("detenido", "warning"),
                StageStatus.SKIPPED: ("omitido (ya crackeados)", "info"),
            }
            label, tag = status_map.get(stage.status, ("—", "info"))
            self.after(0, self.console.append, f"└─ Resultado: {label}", tag)
            self.after(0, self.console.append, "", "")

        def on_cracked(line: str) -> None:
            """Called in real-time when a hash is cracked."""
            self.after(0, self.console.append, f"  🔓 CRACK: {line}", "success")
            # Save to history immediately
            mode_str = self.entry_mode.get().strip()
            self.after(0, self._save_crack_result, line, mode_str)

        def should_stop() -> bool:
            return self._stop_auto or not self._running

        result = run_auto_attack(
            hashcat_path=hc_path,
            hash_value=hash_val,
            hash_mode=hash_mode,
            stages=stages,
            on_stage_start=on_stage_start,
            on_line=on_line,
            on_stage_end=on_stage_end,
            on_cracked=on_cracked,
            should_stop=should_stop,
            proc_ref=self._proc_ref,
        )

        self.after(0, self._on_auto_finished, result)

    def _save_crack_result(self, line: str, mode_str: str) -> None:
        """Save a single cracked line to history and update counter."""
        line = line.strip()
        if ":" not in line:
            return

        hash_val, password = line.split(":", 1)
        hash_val = hash_val.strip()
        password = password.strip()

        # Map to email if dump mode active
        emails: list[str] = []
        if self._dump_data and self._dump_data.hash_to_emails:
            emails = self._dump_data.hash_to_emails.get(hash_val, [])

        if emails:
            for email in emails:
                self._results.add(CrackResult(
                    hash_value=hash_val,
                    password=password,
                    algorithm=self._detected_algo,
                    hash_mode=int(mode_str) if mode_str.isdigit() else -1,
                    attack_method="Auto/Smart",
                    stage_name=email,  # store email in stage_name for display
                ))
                self.after(0, self.console.append,
                           f"    📧 {email} → {password}", "success")
        else:
            self._results.add_from_line(
                line,
                algorithm=self._detected_algo,
                hash_mode=int(mode_str) if mode_str.isdigit() else -1,
                attack_method="Auto/Smart",
            )

        self.lbl_history_count.configure(text=f"🔓 {self._results.count()}")

    def _on_auto_finished(self, result: AutoAttackResult) -> None:
        """Handle completion of auto-attack."""
        self._running = False
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")

        self.console.append("═" * 60, "accent")

        cracked_n = result.cracked_count
        total_n = result.total_hashes

        if cracked_n > 0 and cracked_n >= total_n:
            # ALL cracked
            self.status_badge.set_status(f"CRACKEADO {cracked_n}/{total_n}", T.GREEN)
            self.lbl_result_icon.configure(text="🔓")
            self.lbl_result_text.configure(
                text=f"Todos crackeados: {cracked_n}/{total_n}",
                text_color=T.GREEN,
            )
            self.console.append(
                f"🔓 TODOS CRACKEADOS: {cracked_n}/{total_n} hashes", "success"
            )
            self.console.append(
                f"   ({result.stages_run}/{result.total_stages} etapas ejecutadas)",
                "info",
            )
        elif cracked_n > 0:
            # Partial
            color = T.YELLOW if result.stopped else T.ORANGE
            self.status_badge.set_status(f"{cracked_n}/{total_n} CRACKEADOS", color)
            self.lbl_result_icon.configure(text="🔓")
            self.lbl_result_text.configure(
                text=f"{cracked_n}/{total_n} crackeados",
                text_color=color,
            )
            if result.stopped:
                self.console.append(
                    f"⏸ Detenido — {cracked_n}/{total_n} hashes crackeados.", "warning"
                )
            else:
                self.console.append(
                    f"🔓 Parcial: {cracked_n}/{total_n} hashes crackeados.", "warning"
                )
                self.console.append(
                    f"   {total_n - cracked_n} hashes sin crackear. Prueba con wordlist o más etapas.",
                    "info",
                )
            self.console.append(
                f"   ({result.stages_run}/{result.total_stages} etapas ejecutadas)",
                "info",
            )
        elif result.stopped:
            self.status_badge.set_status("DETENIDO", T.YELLOW)
            self.lbl_result_icon.configure(text="⏸")
            self.lbl_result_text.configure(text="Auto-ataque detenido", text_color=T.YELLOW)
            self.console.append("⏸ Auto-ataque detenido por el usuario.", "warning")
        else:
            self.status_badge.set_status("SIN RESULTADO", T.RED)
            self.lbl_result_icon.configure(text="🔒")
            self.lbl_result_text.configure(
                text="Todas las etapas agotadas — sin resultado",
                text_color=T.RED,
            )
            self.console.append(
                "🔒 Todas las etapas agotadas — contraseña no encontrada.", "error"
            )

        # ── Auto-save results to Result folder ───────────────
        if self._results.count() > 0:
            self._auto_save_results()

        self.console.append("")

    def _auto_save_results(self) -> None:
        """Auto-save results to Result/<datetime>/ folder."""
        from datetime import datetime

        base = Path(__file__).resolve().parent.parent / "Result"
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        folder = base / ts
        folder.mkdir(parents=True, exist_ok=True)

        results = self._results.all()
        has_emails = any(r.stage_name and "@" in r.stage_name for r in results)

        # Save email:password or hash:password
        txt_path = folder / "cracked.txt"
        with open(txt_path, "w", encoding="utf-8") as f:
            for r in results:
                if has_emails and r.stage_name and "@" in r.stage_name:
                    f.write(f"{r.stage_name}:{r.password}\n")
                else:
                    f.write(f"{r.hash_value}:{r.password}\n")

        # Also save CSV with full details
        csv_path = folder / "cracked_details.csv"
        import csv as csv_mod
        with open(csv_path, "w", encoding="utf-8", newline="") as f:
            writer = csv_mod.writer(f)
            if has_emails:
                writer.writerow(["email", "password", "hash", "algorithm", "date"])
                for r in results:
                    email = r.stage_name if r.stage_name and "@" in r.stage_name else ""
                    writer.writerow([email, r.password, r.hash_value, r.algorithm, r.cracked_at])
            else:
                writer.writerow(["hash", "password", "algorithm", "mode", "date"])
                for r in results:
                    writer.writerow([r.hash_value, r.password, r.algorithm, r.hash_mode, r.cracked_at])

        self.console.append(f"💾 Resultados guardados en: {folder}", "success")
        self.console.append(f"   📄 {txt_path.name} — {len(results)} registros", "info")
        self.console.append(f"   📊 {csv_path.name} — detalles completos", "info")

    def _on_finished(self, cracked: str | None) -> None:
        self._running = False
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")

        self.console.append("─" * 60, "accent")

        if cracked:
            self.status_badge.set_status("CRACKEADO", T.GREEN)
            self.lbl_result_icon.configure(text="🔓")
            self.lbl_result_text.configure(text=cracked, text_color=T.GREEN)
            self.console.append(f"🔓 RESULTADO: {cracked}", "success")
            # Save to history
            mode_str = self.entry_mode.get().strip()
            self._results.add_from_line(
                cracked,
                algorithm=self._detected_algo,
                hash_mode=int(mode_str) if mode_str.isdigit() else -1,
                attack_method=self.combo_attack.get(),
            )
            self.lbl_history_count.configure(text=f"🔓 {self._results.count()}")
        else:
            self.status_badge.set_status("SIN RESULTADO", T.RED)
            self.lbl_result_icon.configure(text="🔒")
            self.lbl_result_text.configure(
                text="No se encontró la contraseña", text_color=T.RED
            )
            self.console.append("🔒 No se encontró la contraseña con los parámetros dados.", "error")

        self.console.append("")

    def _stop(self) -> None:
        self.console.append("■ Deteniendo…", "warning")
        self._running = False
        self._stop_auto = True

        # Kill the running hashcat process immediately
        if self._proc_ref:
            try:
                self._proc_ref[0].kill()
            except Exception:
                pass

        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.status_badge.set_status("DETENIDO", T.YELLOW)

    def _clear_console(self) -> None:
        self.console.clear()
        self.status_badge.set_status("LISTO", T.CYAN_DIM)
        self.lbl_result_icon.configure(text="🔒")
        self.lbl_result_text.configure(text="Esperando ejecución…", text_color=T.TEXT_SECONDARY)
        self.lbl_command.configure(text="")

    # ── State persistence ────────────────────────────────────

    def _restore_state(self) -> None:
        if self.cfg.hashcat_path:
            self.entry_hc_path.set_text(self.cfg.hashcat_path)
            ver = hashcat_version(self.cfg.hashcat_path)
            if ver:
                self.lbl_hc_version.configure(text=f"✔ {ver}", text_color=T.GREEN)
        if self.cfg.last_wordlist:
            self.entry_wordlist.set_text(self.cfg.last_wordlist)
        if self.cfg.last_mask:
            self.entry_mask.set_text(self.cfg.last_mask)

    # ── History & export ────────────────────────────────────

    def _show_history(self) -> None:
        """Show a popup with all cracked results."""
        win = ctk.CTkToplevel(self)
        win.title("Historial de resultados")
        win.geometry("750x500")
        win.configure(fg_color=T.BG_DARKEST)
        win.attributes("-topmost", True)
        win.after(200, lambda: win.attributes("-topmost", False))

        ctk.CTkLabel(
            win, text=f"📋 Historial — {self._results.count()} resultados",
            font=(T.FONT_FAMILY, T.FONT_SIZE_LG, "bold"), text_color=T.CYAN,
        ).pack(pady=(T.PAD_LG, T.PAD_SM))

        results = self._results.all()
        if not results:
            ctk.CTkLabel(
                win, text="Sin resultados aún.", font=(T.FONT_FAMILY, T.FONT_SIZE_MD),
                text_color=T.TEXT_MUTED,
            ).pack(pady=T.PAD_XL)
        else:
            container = ctk.CTkFrame(win, fg_color=T.BG_DARK, corner_radius=T.CORNER_RADIUS)
            container.pack(fill="both", expand=True, padx=T.PAD_LG, pady=T.PAD_SM)

            # Header
            hdr = ctk.CTkFrame(container, fg_color=T.BG_MEDIUM, corner_radius=0)
            hdr.pack(fill="x", padx=2, pady=(2, 0))
            for col, w in [("Hash", 220), ("Password", 160), ("Algo", 100), ("Etapa", 130), ("Fecha", 120)]:
                ctk.CTkLabel(
                    hdr, text=col, font=(T.FONT_FAMILY, T.FONT_SIZE_SM, "bold"),
                    text_color=T.MAGENTA, width=w, anchor="w",
                ).pack(side="left", padx=T.PAD_XS, pady=T.PAD_XS)

            scroll = ctk.CTkScrollableFrame(container, fg_color=T.BG_DARK)
            scroll.pack(fill="both", expand=True, padx=2, pady=2)

            for i, r in enumerate(reversed(results)):
                bg = T.BG_DARK if i % 2 == 0 else T.BG_MEDIUM
                row = ctk.CTkFrame(scroll, fg_color=bg, corner_radius=0)
                row.pack(fill="x")
                # Show email if present (stored in stage_name for dump mode)
                has_email = r.stage_name and "@" in r.stage_name
                if has_email:
                    hv = r.stage_name  # email
                else:
                    hv = r.hash_value[:28] + "…" if len(r.hash_value) > 28 else r.hash_value
                ctk.CTkLabel(row, text=hv, font=(T.FONT_MONO, 10),
                             text_color=T.CYAN if has_email else T.TEXT_MUTED,
                             width=220, anchor="w").pack(side="left", padx=T.PAD_XS, pady=2)
                ctk.CTkLabel(row, text=r.password, font=(T.FONT_MONO, 10),
                             text_color=T.GREEN, width=160, anchor="w").pack(side="left", padx=T.PAD_XS, pady=2)
                ctk.CTkLabel(row, text=r.algorithm or f"m{r.hash_mode}", font=(T.FONT_FAMILY, 10),
                             text_color=T.CYAN, width=100, anchor="w").pack(side="left", padx=T.PAD_XS, pady=2)
                ctk.CTkLabel(row, text=r.attack_method[:18] if r.attack_method else "",
                             font=(T.FONT_FAMILY, 10),
                             text_color=T.TEXT_SECONDARY, width=130, anchor="w").pack(side="left", padx=T.PAD_XS, pady=2)
                date = r.cracked_at.split("T")[-1] if "T" in r.cracked_at else r.cracked_at[-8:]
                ctk.CTkLabel(row, text=date, font=(T.FONT_MONO, 10),
                             text_color=T.TEXT_MUTED, width=120, anchor="w").pack(side="left", padx=T.PAD_XS, pady=2)

        btn_row = ctk.CTkFrame(win, fg_color="transparent")
        btn_row.pack(pady=T.PAD_MD)
        AccentButton(btn_row, text="Cerrar", command=win.destroy, width=100).pack(side="left", padx=T.PAD_SM)
        MagentaButton(btn_row, text="🗑 Limpiar historial", width=140, command=lambda: self._clear_history(win)).pack(side="left", padx=T.PAD_SM)

    def _clear_history(self, win) -> None:
        self._results.clear()
        self.lbl_history_count.configure(text=f"🔓 0")
        self.console.append("🗑 Historial limpiado.", "warning")
        win.destroy()

    def _export_results(self) -> None:
        """Export results to file."""
        if self._results.count() == 0:
            self.console.append("⚠ No hay resultados para exportar.", "warning")
            return

        path = filedialog.asksaveasfilename(
            title="Exportar resultados",
            defaultextension=".csv",
            filetypes=[
                ("CSV", "*.csv"),
                ("Texto (email:pass o hash:pass)", "*.txt"),
                ("JSON", "*.json"),
            ],
        )
        if not path:
            return

        ext = Path(path).suffix.lower()

        # Smart export: if dump mode, write email:password
        results = self._results.all()
        has_emails = any(r.stage_name and "@" in r.stage_name for r in results)

        if ext == ".txt" and has_emails:
            with open(path, "w", encoding="utf-8") as f:
                for r in results:
                    if r.stage_name and "@" in r.stage_name:
                        f.write(f"{r.stage_name}:{r.password}\n")
                    else:
                        f.write(f"{r.hash_value}:{r.password}\n")
            count = len(results)
        elif ext == ".csv":
            import csv as csv_mod
            with open(path, "w", encoding="utf-8", newline="") as f:
                writer = csv_mod.writer(f)
                if has_emails:
                    writer.writerow(["email", "password", "hash", "algorithm", "date"])
                    for r in results:
                        email = r.stage_name if r.stage_name and "@" in r.stage_name else ""
                        writer.writerow([email, r.password, r.hash_value, r.algorithm, r.cracked_at])
                else:
                    writer.writerow(["hash", "password", "algorithm", "mode", "attack", "date"])
                    for r in results:
                        writer.writerow([r.hash_value, r.password, r.algorithm, r.hash_mode, r.attack_method, r.cracked_at])
            count = len(results)
        elif ext == ".json":
            count = self._results.export_json(path)
        else:
            count = self._results.export_txt(path)

        self.console.append(f"💾 {count} resultados exportados a: {path}", "success")

    def _on_close(self) -> None:
        self.cfg.hashcat_path = self.entry_hc_path.get().strip()
        self.cfg.last_wordlist = self.entry_wordlist.get().strip()
        self.cfg.last_mask = self.entry_mask.get().strip()
        try:
            geo = self.geometry()
            # Format: WxH+X+Y
            wh = geo.split("+")[0]
            w, h = wh.split("x")
            self.cfg.window_width = int(w)
            self.cfg.window_height = int(h)
        except Exception:
            pass
        self.cfg.save()
        self.destroy()


def main() -> None:
    app = HashCrackerApp()
    app.mainloop()
