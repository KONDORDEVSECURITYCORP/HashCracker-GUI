"""
Smart Attack engine — probability-ordered cracking strategy.

Attacks in the order real humans create passwords:

  Phase 1 — Pure words (lowercase, most common base)
  Phase 2 — Word + digit suffix (password1)
  Phase 3 — Capitalised word (Password)
  Phase 4 — Capitalised + digits (Password1, Password123)
  Phase 5 — Word + year (password2024)
  Phase 6 — Common keyboard patterns & numeric sequences
  Phase 7 — Mixed alpha + digits (p4ssw0rd)
  Phase 8 — Word + special + digit (password!1)
  Phase 9 — Full alphanumeric incremental
  Phase 10 — Full charset incremental (last resort)

Each phase builds hashcat mask commands that exhaust the most
probable keyspace first, so simple passwords crack in seconds.
"""

from __future__ import annotations

from .auto_attack import AttackStage


def build_smart_stages(
    wordlist: str = "",
    hashcat_dir: str = "",
) -> list[AttackStage]:
    """
    Build a probability-ordered attack chain.

    The order mirrors how real users pick passwords:
    lowercase words → add a number → capitalise → add year → symbols.
    """
    from pathlib import Path

    stages: list[AttackStage] = []
    rules_dir = Path(hashcat_dir) / "rules" if hashcat_dir else Path()

    # ─────────────────────────────────────────────────────────
    # PHASE 0: Wordlist first (if provided) — fastest possible
    # ─────────────────────────────────────────────────────────
    if wordlist and Path(wordlist).is_file():
        stages.append(AttackStage(
            name="📖 Diccionario directo",
            description="Wordlist pura — prueba cada palabra tal cual",
            attack_mode=0,
            wordlist=wordlist,
            estimated_time="Muy rápido",
        ))

        best64 = rules_dir / "best64.rule"
        if best64.is_file():
            stages.append(AttackStage(
                name="📖 Diccionario + best64",
                description="Wordlist + las 64 mutaciones más comunes",
                attack_mode=0,
                wordlist=wordlist,
                rules=[str(best64)],
                estimated_time="Rápido",
            ))

        # Wordlist + 1-4 dígitos al final
        stages.append(AttackStage(
            name="📖 Diccionario + dígitos",
            description="Wordlist + 1-4 dígitos al final (password123)",
            attack_mode=6,
            wordlist=wordlist,
            mask="?d?d?d?d",
            increment=True,
            increment_min=1,
            increment_max=4,
            estimated_time="Rápido",
        ))

        # Wordlist + años
        for year_mask, label in [("19?d?d", "19xx"), ("20?d?d", "20xx")]:
            stages.append(AttackStage(
                name=f"📖 Diccionario + año {label}",
                description=f"Wordlist + año {label} al final",
                attack_mode=6,
                wordlist=wordlist,
                mask=year_mask,
                estimated_time="Rápido",
            ))

    # ─────────────────────────────────────────────────────────
    # PHASE 1: Pure lowercase words (a-z) — the most common base
    # "password", "dragon", "master", "monkey", etc.
    # ─────────────────────────────────────────────────────────
    stages.append(AttackStage(
        name="🔤 Minúsculas puras (1→8)",
        description="Solo letras a-z — la base de la mayoría de passwords",
        attack_mode=3,
        mask="?l?l?l?l?l?l?l?l",
        increment=True,
        increment_min=1,
        increment_max=8,
        estimated_time="Rápido",
    ))

    # ─────────────────────────────────────────────────────────
    # PHASE 2: Word + single digit (password1, dragon7)
    # ─────────────────────────────────────────────────────────
    for word_len in range(3, 8):
        mask = "?l" * word_len + "?d"
        stages.append(AttackStage(
            name=f"🔤 {word_len} letras + 1 dígito",
            description=f"Palabra de {word_len} letras + un número al final",
            attack_mode=3,
            mask=mask,
            estimated_time="Rápido",
        ))

    # ─────────────────────────────────────────────────────────
    # PHASE 3: Capitalised word (Password, Dragon, Master)
    # ─────────────────────────────────────────────────────────
    stages.append(AttackStage(
        name="🔠 Mayúscula inicial (3→8)",
        description="Primera letra mayúscula + minúsculas (Password)",
        attack_mode=3,
        mask="?u?l?l?l?l?l?l?l",
        increment=True,
        increment_min=3,
        increment_max=8,
        estimated_time="Rápido",
    ))

    # ─────────────────────────────────────────────────────────
    # PHASE 4: Capitalised + digits (Password1, Admin123)
    # ─────────────────────────────────────────────────────────
    cap_patterns = [
        ("Ullld",      "?u?l?l?l?d",           "Mayúsc + 3 min + 1 dígito (Pass1)"),
        ("Ulllld",     "?u?l?l?l?l?d",         "Mayúsc + 4 min + 1 dígito (Admin1)"),
        ("Ullllld",    "?u?l?l?l?l?l?d",       "Mayúsc + 5 min + 1 dígito (Master1)"),
        ("Ullldd",     "?u?l?l?l?d?d",         "Mayúsc + 3 min + 2 dígitos (Pass12)"),
        ("Ulllldd",    "?u?l?l?l?l?d?d",       "Mayúsc + 4 min + 2 dígitos (Admin12)"),
        ("Ullllldd",   "?u?l?l?l?l?l?d?d",     "Mayúsc + 5 min + 2 dígitos (Master12)"),
        ("Ulllddd",    "?u?l?l?l?d?d?d",       "Mayúsc + 3 min + 3 dígitos (Pass123)"),
        ("Ullllddd",   "?u?l?l?l?l?d?d?d",     "Mayúsc + 4 min + 3 dígitos (Admin123)"),
        ("Ulllllddd",  "?u?l?l?l?l?l?d?d?d",   "Mayúsc + 5 min + 3 dígitos (Master123)"),
        ("Ulllldddd",  "?u?l?l?l?l?d?d?d?d",   "Mayúsc + 4 min + 4 dígitos (Admin1234)"),
        ("Ullllldddd", "?u?l?l?l?l?l?d?d?d?d", "Mayúsc + 5 min + 4 dígitos (Passw1234)"),
    ]
    for pname, mask, desc in cap_patterns:
        stages.append(AttackStage(
            name=f"🔠 Patrón {pname}",
            description=desc,
            attack_mode=3,
            mask=mask,
            estimated_time="Medio",
        ))

    # ─────────────────────────────────────────────────────────
    # PHASE 5: Word + 2-4 digits (password12, dragon1234)
    # ─────────────────────────────────────────────────────────
    word_digit_patterns = [
        ("lllldd",     "?l?l?l?l?d?d",         "4 min + 2 dígitos (pass12)"),
        ("llllldd",    "?l?l?l?l?l?d?d",       "5 min + 2 dígitos (admin12)"),
        ("lllllldd",   "?l?l?l?l?l?l?d?d",     "6 min + 2 dígitos (dragon12)"),
        ("llllddd",    "?l?l?l?l?d?d?d",       "4 min + 3 dígitos (pass123)"),
        ("lllllddd",   "?l?l?l?l?l?d?d?d",     "5 min + 3 dígitos (admin123)"),
        ("llllllddd",  "?l?l?l?l?l?l?d?d?d",   "6 min + 3 dígitos (dragon123)"),
        ("lllldddd",   "?l?l?l?l?d?d?d?d",     "4 min + 4 dígitos (pass1234)"),
        ("llllldddd",  "?l?l?l?l?l?d?d?d?d",   "5 min + 4 dígitos (admin1234)"),
    ]
    for pname, mask, desc in word_digit_patterns:
        stages.append(AttackStage(
            name=f"🔢 Patrón {pname}",
            description=desc,
            attack_mode=3,
            mask=mask,
            estimated_time="Medio",
        ))

    # ─────────────────────────────────────────────────────────
    # PHASE 6: Word + year (password2024, admin1990)
    # ─────────────────────────────────────────────────────────
    for prefix_len in range(4, 8):
        for century in ["19", "20"]:
            mask = "?l" * prefix_len + century + "?d?d"
            stages.append(AttackStage(
                name=f"📅 {prefix_len} letras + año {century}xx",
                description=f"Palabra de {prefix_len} letras + año ({century}00-{century}99)",
                attack_mode=3,
                mask=mask,
                estimated_time="Medio",
            ))

    # Capitalised + year
    for prefix_len in range(3, 7):
        for century in ["19", "20"]:
            mask = "?u" + "?l" * prefix_len + century + "?d?d"
            stages.append(AttackStage(
                name=f"📅 Mayúsc + {prefix_len} min + año {century}xx",
                description=f"Capitalizada + año (Admin{century}24)",
                attack_mode=3,
                mask=mask,
                estimated_time="Medio",
            ))

    # ─────────────────────────────────────────────────────────
    # PHASE 7: PINs numéricos (1-10 dígitos)
    # ─────────────────────────────────────────────────────────
    stages.append(AttackStage(
        name="🔢 PIN numérico (1→10)",
        description="Solo dígitos — PINs, códigos, teléfonos",
        attack_mode=3,
        mask="?d?d?d?d?d?d?d?d?d?d",
        increment=True,
        increment_min=1,
        increment_max=10,
        estimated_time="Rápido",
    ))

    # ─────────────────────────────────────────────────────────
    # PHASE 8: Word + special char + digit (password!1, admin@123)
    # ─────────────────────────────────────────────────────────
    special_patterns = [
        ("llllsd",      "?l?l?l?l?s?d",         "4 min + especial + 1 dígito (pass!1)"),
        ("lllllsd",     "?l?l?l?l?l?s?d",       "5 min + especial + 1 dígito (admin!1)"),
        ("llllsdd",     "?l?l?l?l?s?d?d",       "4 min + especial + 2 dígitos (pass!12)"),
        ("lllllsdd",    "?l?l?l?l?l?s?d?d",     "5 min + especial + 2 dígitos (admin!12)"),
        ("Ullllsd",     "?u?l?l?l?l?s?d",       "Mayúsc + 4 min + especial + dígito (Pass!1)"),
        ("Ulllllsd",    "?u?l?l?l?l?l?s?d",     "Mayúsc + 5 min + especial + dígito (Admin!1)"),
        ("Ullllsdd",    "?u?l?l?l?l?s?d?d",     "Mayúsc + 4 min + especial + 2 dígitos (Pass!12)"),
        ("Ulllllsdd",   "?u?l?l?l?l?l?s?d?d",   "Mayúsc + 5 min + especial + 2 dígitos (Admin!12)"),
    ]
    for pname, mask, desc in special_patterns:
        stages.append(AttackStage(
            name=f"⚡ Patrón {pname}",
            description=desc,
            attack_mode=3,
            mask=mask,
            estimated_time="Largo",
        ))

    # ─────────────────────────────────────────────────────────
    # PHASE 9: Mixed alpha+digit incremental (custom charset)
    # ─────────────────────────────────────────────────────────
    stages.append(AttackStage(
        name="🔀 Alfanumérico mixto (1→7)",
        description="Minúsculas + dígitos mezclados (p4ssw0rd)",
        attack_mode=3,
        mask="?1?1?1?1?1?1?1",
        increment=True,
        increment_min=1,
        increment_max=7,
        extra_args=["-1", "?l?d"],
        estimated_time="Largo",
    ))

    # ─────────────────────────────────────────────────────────
    # PHASE 10: Minúsculas extendidas 9-10
    # ─────────────────────────────────────────────────────────
    stages.append(AttackStage(
        name="🔤 Minúsculas largas (9→10)",
        description="Palabras largas solo minúsculas (a-z)",
        attack_mode=3,
        mask="?l?l?l?l?l?l?l?l?l?l",
        increment=True,
        increment_min=9,
        increment_max=10,
        estimated_time="Muy largo",
    ))

    # ─────────────────────────────────────────────────────────
    # PHASE 11: Full charset incremental (último recurso)
    # ─────────────────────────────────────────────────────────
    stages.append(AttackStage(
        name="💀 Charset completo (1→6)",
        description="Todos los caracteres imprimibles — último recurso",
        attack_mode=3,
        mask="?a?a?a?a?a?a",
        increment=True,
        increment_min=1,
        increment_max=6,
        estimated_time="Extremadamente largo",
    ))

    return stages
