"""
Auto-Attack engine — robust multi-stage cracking strategy.

Runs a chain of hashcat attacks in order of efficiency:
  Stage 1 → Wordlist (if available)
  Stage 2 → Wordlist + rules (best64, toggles)
  Stage 3 → Common PIN / numeric masks
  Stage 4 → Common password patterns (Ullllddd, etc.)
  Stage 5 → Lowercase brute-force incremental
  Stage 6 → Alphanumeric brute-force incremental
  Stage 7 → Full charset brute-force incremental

Each stage stops as soon as the hash is cracked.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Callable, Generator


# ── Stage definitions ────────────────────────────────────────

class StageStatus(Enum):
    PENDING = auto()
    RUNNING = auto()
    CRACKED = auto()
    EXHAUSTED = auto()
    SKIPPED = auto()
    STOPPED = auto()


@dataclass(slots=True)
class AttackStage:
    """A single step in the auto-attack chain."""

    name: str
    description: str
    attack_mode: int            # hashcat -a value
    mask: str = ""              # mask pattern (mode 3/6/7)
    wordlist: str = ""          # wordlist path (mode 0/6/7)
    rules: list[str] = field(default_factory=list)  # -r rule files
    increment: bool = False
    increment_min: int = 1
    increment_max: int = 8
    extra_args: list[str] = field(default_factory=list)
    status: StageStatus = StageStatus.PENDING
    estimated_time: str = ""    # human-readable estimate


def build_stages(
    wordlist: str = "",
    hashcat_dir: str = "",
) -> list[AttackStage]:
    """
    Build the full auto-attack chain.

    Args:
        wordlist: path to user-provided wordlist (empty = skip dictionary stages)
        hashcat_dir: hashcat installation dir (to find built-in rules)
    """
    stages: list[AttackStage] = []
    rules_dir = Path(hashcat_dir) / "rules" if hashcat_dir else Path()

    # ── Stage 1: Straight dictionary ─────────────────────────
    if wordlist and Path(wordlist).is_file():
        stages.append(AttackStage(
            name="Diccionario directo",
            description="Wordlist pura — sin reglas",
            attack_mode=0,
            wordlist=wordlist,
            estimated_time="Rápido",
        ))

        # ── Stage 2: Dictionary + best64 rules ───────────────
        best64 = rules_dir / "best64.rule"
        if best64.is_file():
            stages.append(AttackStage(
                name="Diccionario + best64",
                description="Wordlist + las 64 reglas más efectivas",
                attack_mode=0,
                wordlist=wordlist,
                rules=[str(best64)],
                estimated_time="Rápido-Medio",
            ))

        # ── Stage 2b: Dictionary + toggles ────────────────────
        toggles = rules_dir / "toggles1.rule"
        if toggles.is_file():
            stages.append(AttackStage(
                name="Diccionario + toggles",
                description="Wordlist + cambios de mayúsculas/minúsculas",
                attack_mode=0,
                wordlist=wordlist,
                rules=[str(toggles)],
                estimated_time="Medio",
            ))

        # ── Stage 2c: Dictionary + leetspeak ──────────────────
        leet = rules_dir / "leetspeak.rule"
        if leet.is_file():
            stages.append(AttackStage(
                name="Diccionario + leetspeak",
                description="Wordlist + sustituciones tipo l33t",
                attack_mode=0,
                wordlist=wordlist,
                rules=[str(leet)],
                estimated_time="Medio",
            ))

        # ── Stage 2d: Hybrid wordlist + digits ────────────────
        stages.append(AttackStage(
            name="Híbrido WL + dígitos",
            description="Wordlist + 1-4 dígitos al final (password123)",
            attack_mode=6,
            wordlist=wordlist,
            mask="?d?d?d?d",
            increment=True,
            increment_min=1,
            increment_max=4,
            estimated_time="Medio",
        ))

        # ── Stage 2e: Hybrid wordlist + years ─────────────────
        for year_mask in ["19?d?d", "20?d?d"]:
            stages.append(AttackStage(
                name=f"Híbrido WL + año ({year_mask[:2]}xx)",
                description=f"Wordlist + año {year_mask[:2]}xx al final",
                attack_mode=6,
                wordlist=wordlist,
                mask=year_mask,
                estimated_time="Rápido",
            ))

    # ── Stage 3: Numeric PINs ────────────────────────────────
    stages.append(AttackStage(
        name="PIN numérico (1-8 dígitos)",
        description="Prueba PINs: 0000, 123456, etc.",
        attack_mode=3,
        mask="?d?d?d?d?d?d?d?d",
        increment=True,
        increment_min=1,
        increment_max=8,
        estimated_time="Muy rápido",
    ))

    # ── Stage 4: Common password patterns ─────────────────────
    common_patterns = [
        ("Ullllldd",    "?u?l?l?l?l?l?d?d",     "Mayúscula + 5 min + 2 dígitos (Admin01)"),
        ("Ulllldddd",   "?u?l?l?l?l?d?d?d?d",   "Mayúscula + 4 min + 4 dígitos (Pass2024)"),
        ("Ulllldd",     "?u?l?l?l?l?d?d",        "Mayúscula + 4 min + 2 dígitos (Hello99)"),
        ("Ullllllldd",  "?u?l?l?l?l?l?l?l?d?d",  "Mayúscula + 7 min + 2 dígitos (Password01)"),
        ("lllllldd",    "?l?l?l?l?l?l?d?d",      "6 minúsculas + 2 dígitos (secret42)"),
        ("lllldddd",    "?l?l?l?l?d?d?d?d",      "4 minúsculas + 4 dígitos (pass1234)"),
        ("ddddllll",    "?d?d?d?d?l?l?l?l",      "4 dígitos + 4 minúsculas (2024pass)"),
        ("Ullllllsd",   "?u?l?l?l?l?l?l?s?d",    "Mayúsc + 6 min + especial + dígito (Welcome!1)"),
        ("Ulllllsdd",   "?u?l?l?l?l?l?s?d?d",    "Mayúsc + 5 min + especial + 2 dígitos (Passw0!23)"),
    ]

    for pname, mask, desc in common_patterns:
        stages.append(AttackStage(
            name=f"Patrón: {pname}",
            description=desc,
            attack_mode=3,
            mask=mask,
            estimated_time="Medio",
        ))

    # ── Stage 5: Lowercase incremental ───────────────────────
    stages.append(AttackStage(
        name="Minúsculas (1-8 chars)",
        description="Fuerza bruta solo minúsculas a-z incremental",
        attack_mode=3,
        mask="?l?l?l?l?l?l?l?l",
        increment=True,
        increment_min=1,
        increment_max=8,
        estimated_time="Medio-Largo",
    ))

    # ── Stage 6: Alphanumeric incremental ────────────────────
    stages.append(AttackStage(
        name="Alfanumérico (1-6 chars)",
        description="Minúsculas + dígitos incremental",
        attack_mode=3,
        mask="?h?h?h?h?h?h",  # Using custom charset below
        increment=True,
        increment_min=1,
        increment_max=6,
        extra_args=["-1", "?l?d", "--hex-charset"],
        estimated_time="Largo",
    ))

    # Fix: use custom charset properly
    stages[-1].mask = "?1?1?1?1?1?1"
    stages[-1].extra_args = ["-1", "?l?d"]

    # ── Stage 7: Full charset incremental ────────────────────
    stages.append(AttackStage(
        name="Charset completo (1-6 chars)",
        description="Todos los caracteres imprimibles — último recurso",
        attack_mode=3,
        mask="?a?a?a?a?a?a",
        increment=True,
        increment_min=1,
        increment_max=6,
        estimated_time="Muy largo",
    ))

    return stages


# ── Runner ───────────────────────────────────────────────────

@dataclass(slots=True)
class AutoAttackResult:
    """Outcome of the auto-attack run."""

    cracked: str | None = None
    cracked_count: int = 0
    total_hashes: int = 0
    stage_name: str = ""
    stages_run: int = 0
    total_stages: int = 0
    stopped: bool = False


def _count_hashes(hash_value: str) -> int:
    """Count how many hashes we're attacking."""
    p = Path(hash_value)
    if p.is_file():
        lines = p.read_text(encoding="utf-8", errors="replace").strip().splitlines()
        return len([l for l in lines if l.strip()])
    return 1


def run_auto_attack(
    hashcat_path: str,
    hash_value: str,
    hash_mode: int,
    stages: list[AttackStage],
    on_stage_start: Callable[[int, AttackStage], None] | None = None,
    on_line: Callable[[str], None] | None = None,
    on_stage_end: Callable[[int, AttackStage], None] | None = None,
    on_cracked: Callable[[str], None] | None = None,
    should_stop: Callable[[], bool] | None = None,
    proc_ref: list | None = None,
) -> AutoAttackResult:
    """
    Execute stages sequentially until ALL hashes cracked or all exhausted.

    For multi-hash files, the chain continues across stages, accumulating
    results. Hashcat's potfile tracks already-cracked hashes so they're
    skipped in later stages.
    """
    hashcat_dir = Path(hashcat_path).parent
    output_file = str(hashcat_dir / "cracked_auto.txt")
    potfile = str(hashcat_dir / "hashcracker_session.potfile")
    creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

    total_hashes = _count_hashes(hash_value)
    result = AutoAttackResult(total_stages=len(stages), total_hashes=total_hashes)

    # Clean output & potfile at start of chain (fresh run)
    for f in [output_file, potfile]:
        p = Path(f)
        if p.exists():
            p.unlink()

    # Track already-seen cracked lines to detect NEW cracks per stage
    seen_cracked: set[str] = set()

    for idx, stage in enumerate(stages):
        # ── Check stop signal ────────────────────────────────
        if should_stop and should_stop():
            stage.status = StageStatus.STOPPED
            result.stopped = True
            break

        # ── Check if all hashes already cracked ──────────────
        if result.cracked_count >= total_hashes:
            stage.status = StageStatus.SKIPPED
            if on_stage_end:
                on_stage_end(idx, stage)
            continue

        stage.status = StageStatus.RUNNING
        result.stages_run = idx + 1

        if on_stage_start:
            on_stage_start(idx, stage)

        # ── Build command ────────────────────────────────────
        cmd = [
            hashcat_path,
            "--force",
            "--status",
            "--status-timer=5",
            "-O",
            "-m", str(hash_mode),
            "-a", str(stage.attack_mode),
            "-o", output_file,
            "--potfile-path", potfile,
        ]

        if stage.increment:
            cmd += [
                "--increment",
                f"--increment-min={stage.increment_min}",
                f"--increment-max={stage.increment_max}",
            ]

        for rule in stage.rules:
            cmd += ["-r", rule]

        cmd += stage.extra_args
        cmd.append(hash_value)

        match stage.attack_mode:
            case 0:
                if stage.wordlist:
                    cmd.append(stage.wordlist)
            case 3:
                if stage.mask:
                    cmd.append(stage.mask)
            case 6:
                if stage.wordlist:
                    cmd.append(stage.wordlist)
                if stage.mask:
                    cmd.append(stage.mask)
            case 7:
                if stage.mask:
                    cmd.append(stage.mask)
                if stage.wordlist:
                    cmd.append(stage.wordlist)

        # ── Execute ──────────────────────────────────────────
        new_cracks_this_stage = 0

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                text=True,
                bufsize=1,
                cwd=str(hashcat_dir),
                creationflags=creation_flags,
            )

            assert proc.stdout is not None
            if proc_ref is not None:
                proc_ref.clear()
                proc_ref.append(proc)

            for line in proc.stdout:
                line = line.rstrip("\n")
                if not line:
                    continue

                if on_line:
                    on_line(line)

                # ── Detect live cracks in output ─────────────
                # Hashcat prints "hash:password" — hash part is hex
                stripped = line.strip()
                if ":" in stripped:
                    hash_part = stripped.split(":", 1)[0]
                    # Valid crack: hash part is hex-only and reasonable length
                    is_hex = all(c in "0123456789abcdefABCDEF" for c in hash_part)
                    if is_hex and 16 <= len(hash_part) <= 256 and stripped not in seen_cracked:
                        seen_cracked.add(stripped)
                        new_cracks_this_stage += 1
                        result.cracked_count = len(seen_cracked)
                        if on_cracked:
                            on_cracked(stripped)

                # Check stop signal mid-stage
                if should_stop and should_stop():
                    proc.kill()
                    try:
                        proc.stdout.close()
                    except Exception:
                        pass
                    stage.status = StageStatus.STOPPED
                    result.stopped = True
                    break

            proc.wait(timeout=5)

        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        except Exception as exc:
            if on_line:
                on_line(f"[ERROR] {exc}")
            stage.status = StageStatus.EXHAUSTED
            if on_stage_end:
                on_stage_end(idx, stage)
            continue

        # ── Read output file for any results we missed ───────
        out_path = Path(output_file)
        if out_path.is_file():
            for file_line in out_path.read_text(encoding="utf-8", errors="replace").strip().splitlines():
                file_line = file_line.strip()
                if not file_line or file_line in seen_cracked:
                    continue
                if ":" in file_line:
                    hash_part = file_line.split(":", 1)[0]
                    is_hex = all(c in "0123456789abcdefABCDEF" for c in hash_part)
                    if is_hex and 16 <= len(hash_part) <= 256:
                        seen_cracked.add(file_line)
                        new_cracks_this_stage += 1
                        result.cracked_count = len(seen_cracked)
                        if on_cracked:
                            on_cracked(file_line)

        # ── Update result ────────────────────────────────────
        if seen_cracked:
            result.cracked = "\n".join(seen_cracked)

        if new_cracks_this_stage > 0:
            stage.status = StageStatus.CRACKED
            result.stage_name = stage.name
        elif result.stopped:
            pass  # already set
        else:
            stage.status = StageStatus.EXHAUSTED

        if on_stage_end:
            on_stage_end(idx, stage)

        # ── Stop if ALL hashes cracked ───────────────────────
        if result.cracked_count >= total_hashes:
            break

        if result.stopped:
            break

    return result
