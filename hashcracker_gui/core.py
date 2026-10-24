"""
Hashcat process manager — builds commands, launches, and streams output.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Generator


class AttackMode(IntEnum):
    STRAIGHT = 0
    COMBINATION = 1
    BRUTE_FORCE = 3
    HYBRID_WL_MASK = 6
    HYBRID_MASK_WL = 7
    ASSOCIATION = 9

    @property
    def label(self) -> str:
        labels = {
            0: "Diccionario",
            1: "Combinación",
            3: "Fuerza bruta / Mask",
            6: "Híbrido WL + Mask",
            7: "Híbrido Mask + WL",
            9: "Asociación",
        }
        return labels.get(self.value, f"Modo {self.value}")


@dataclass(slots=True)
class CrackJob:
    hashcat_path: str
    hash_value: str
    hash_mode: int
    attack_mode: AttackMode = AttackMode.STRAIGHT
    wordlist: str = ""
    mask: str = ""
    increment: bool = False
    increment_min: int = 1
    increment_max: int = 8
    extra_args: list[str] = field(default_factory=list)
    output_file: str = ""

    def build_command(self) -> list[str]:
        cmd = [
            self.hashcat_path,
            "--force",
            "--status",
            "--status-timer=3",
            "-m", str(self.hash_mode),
            "-a", str(int(self.attack_mode)),
        ]

        if self.output_file:
            cmd += ["-o", self.output_file]

        if self.increment:
            cmd += ["--increment",
                     f"--increment-min={self.increment_min}",
                     f"--increment-max={self.increment_max}"]

        cmd += self.extra_args
        cmd.append(self.hash_value)

        match self.attack_mode:
            case AttackMode.STRAIGHT:
                if self.wordlist:
                    cmd.append(self.wordlist)
            case AttackMode.BRUTE_FORCE:
                if self.mask:
                    cmd.append(self.mask)
            case AttackMode.HYBRID_WL_MASK:
                if self.wordlist:
                    cmd.append(self.wordlist)
                if self.mask:
                    cmd.append(self.mask)
            case AttackMode.HYBRID_MASK_WL:
                if self.mask:
                    cmd.append(self.mask)
                if self.wordlist:
                    cmd.append(self.wordlist)

        return cmd


def run_hashcat(job: CrackJob, proc_ref: list | None = None) -> Generator[str, None, int]:
    cmd = job.build_command()
    creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        text=True,
        bufsize=1,
        cwd=str(Path(job.hashcat_path).parent),
        creationflags=creation_flags,
    )

    assert proc.stdout is not None
    if proc_ref is not None:
        proc_ref.clear()
        proc_ref.append(proc)
    for line in proc.stdout:
        yield line.rstrip("\n")

    proc.wait()
    return proc.returncode


def hashcat_version(hashcat_path: str) -> str | None:
    try:
        result = subprocess.run(
            [hashcat_path, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        return result.stdout.strip() or result.stderr.strip()
    except Exception:
        return None
