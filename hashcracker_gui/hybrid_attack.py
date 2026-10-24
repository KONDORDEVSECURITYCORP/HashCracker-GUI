"""
Hybrid Smart Attack — dictionary + intelligent masks.

Combines wordlist power with mask mutations to crack passwords
that are built from real words + modifications:

  Phase 1  → Dictionary straight (exact matches)
  Phase 2  → Dictionary + best rules (best64, toggles, leetspeak)
  Phase 3  → Dictionary + digits suffix (password1, admin123)
  Phase 4  → Dictionary + special suffix (password!, admin@)
  Phase 5  → Dictionary + year suffix (password2024)
  Phase 6  → Dictionary + complex suffix (password!123, admin@2024)
  Phase 7  → Prefix digits + dictionary (123password)
  Phase 8  → Prefix special + dictionary (!password)
  Phase 9  → Dictionary + combined rules (d3Ad, OneRuleToRuleThemAll)
  Phase 10 → Smart mask fallback (no dictionary, pure brute patterns)

This cracks passwords like:
  Simple:    password, admin, dragon
  With nums: password123, admin1, test2024
  With spec: password!, admin@123, Pass!2024
  Reversed:  123admin, !password
  Complex:   P@ssw0rd, Dr4g0n!, 4dm1n2024
"""

from __future__ import annotations

from pathlib import Path

from .auto_attack import AttackStage
from .smart_attack import build_smart_stages


def build_hybrid_stages(
    wordlist: str,
    hashcat_dir: str = "",
) -> list[AttackStage]:
    """
    Build hybrid dictionary+mask attack chain.

    Requires a wordlist. Falls back to smart_attack stages at the end.
    """
    stages: list[AttackStage] = []
    rules_dir = Path(hashcat_dir) / "rules" if hashcat_dir else Path()
    wl = wordlist

    if not wl or not Path(wl).is_file():
        # No wordlist → fall back to pure smart attack
        return build_smart_stages(wordlist="", hashcat_dir=hashcat_dir)

    # ═════════════════════════════════════════════════════════
    #  PHASE 1: Dictionary straight — exact word matches
    #  Cracks: password, admin, dragon, monkey, etc.
    # ═════════════════════════════════════════════════════════
    stages.append(AttackStage(
        name="📖 Diccionario directo",
        description="Cada palabra del diccionario tal cual",
        attack_mode=0,
        wordlist=wl,
        estimated_time="Muy rápido",
    ))

    # ═════════════════════════════════════════════════════════
    #  PHASE 2: Dictionary + rules — mutations
    #  Cracks: Password, PASSWORD, p@ssword, passw0rd
    # ═════════════════════════════════════════════════════════
    rule_files = [
        ("best64.rule",    "📖 Dict + best64",      "Las 64 mutaciones más efectivas (Password, password1, etc.)"),
        ("toggles1.rule",  "📖 Dict + toggles",     "Cambios mayúscula/minúscula (pASSWORD, Password, etc.)"),
        ("leetspeak.rule", "📖 Dict + leetspeak",   "Sustituciones l33t (p@ssw0rd, 4dm1n, dr4g0n)"),
        ("best66.rule",    "📖 Dict + best66",      "Reglas extendidas de mutación"),
        ("rockyou-30000.rule", "📖 Dict + rockyou rules", "30k reglas extraídas de rockyou patterns"),
    ]
    for rule_name, stage_name, desc in rule_files:
        rule_path = rules_dir / rule_name
        if rule_path.is_file():
            stages.append(AttackStage(
                name=stage_name,
                description=desc,
                attack_mode=0,
                wordlist=wl,
                rules=[str(rule_path)],
                estimated_time="Rápido",
            ))

    # Combinar best64 + toggles si ambos existen
    best64 = rules_dir / "best64.rule"
    toggles = rules_dir / "toggles1.rule"
    if best64.is_file() and toggles.is_file():
        stages.append(AttackStage(
            name="📖 Dict + best64 + toggles",
            description="Doble regla: mutaciones + cambio de case combinados",
            attack_mode=0,
            wordlist=wl,
            rules=[str(best64), str(toggles)],
            estimated_time="Medio",
        ))

    # ═════════════════════════════════════════════════════════
    #  PHASE 3: Hybrid wordlist + digit suffixes
    #  Cracks: password1, admin12, dragon123, test1234
    # ═════════════════════════════════════════════════════════
    stages.append(AttackStage(
        name="🔢 Dict + 1-4 dígitos al final",
        description="Palabra + dígitos incrementales (password1 → password1234)",
        attack_mode=6,
        wordlist=wl,
        mask="?d?d?d?d",
        increment=True,
        increment_min=1,
        increment_max=4,
        estimated_time="Rápido",
    ))

    stages.append(AttackStage(
        name="🔢 Dict + 5-6 dígitos al final",
        description="Palabra + dígitos largos (password12345, admin123456)",
        attack_mode=6,
        wordlist=wl,
        mask="?d?d?d?d?d?d",
        increment=True,
        increment_min=5,
        increment_max=6,
        estimated_time="Medio",
    ))

    # ═════════════════════════════════════════════════════════
    #  PHASE 4: Hybrid wordlist + special char suffix
    #  Cracks: password!, admin@, dragon#, test$
    # ═════════════════════════════════════════════════════════
    stages.append(AttackStage(
        name="⚡ Dict + 1 especial al final",
        description="Palabra + símbolo (password!, admin@, dragon#)",
        attack_mode=6,
        wordlist=wl,
        mask="?s",
        estimated_time="Muy rápido",
    ))

    stages.append(AttackStage(
        name="⚡ Dict + especial + 1-2 dígitos",
        description="Palabra + símbolo + dígitos (password!1, admin@12)",
        attack_mode=6,
        wordlist=wl,
        mask="?s?d?d",
        increment=True,
        increment_min=2,
        increment_max=3,
        estimated_time="Rápido",
    ))

    stages.append(AttackStage(
        name="⚡ Dict + especial + 3-4 dígitos",
        description="Palabra + símbolo + dígitos (password!123, admin@1234)",
        attack_mode=6,
        wordlist=wl,
        mask="?s?d?d?d?d",
        increment=True,
        increment_min=4,
        increment_max=5,
        estimated_time="Medio",
    ))

    # ═════════════════════════════════════════════════════════
    #  PHASE 5: Hybrid wordlist + year suffix
    #  Cracks: password2024, admin1990, dragon2023
    # ═════════════════════════════════════════════════════════
    for century, label in [("20", "20xx"), ("19", "19xx")]:
        stages.append(AttackStage(
            name=f"📅 Dict + año {label}",
            description=f"Palabra + año {century}00-{century}99",
            attack_mode=6,
            wordlist=wl,
            mask=f"{century}?d?d",
            estimated_time="Rápido",
        ))

    # Year + special: password2024!, admin1990@
    stages.append(AttackStage(
        name="📅 Dict + año + especial",
        description="Palabra + año 20xx + símbolo (password2024!, admin2023@)",
        attack_mode=6,
        wordlist=wl,
        mask="20?d?d?s",
        estimated_time="Rápido",
    ))

    # ═════════════════════════════════════════════════════════
    #  PHASE 6: Complex suffix combos
    #  Cracks: password!123, admin@2024, dragon#99
    # ═════════════════════════════════════════════════════════
    complex_suffixes = [
        ("?d?d?s",       "Dict + 2 dígitos + especial",       "password12!, admin99@"),
        ("?d?d?d?s",     "Dict + 3 dígitos + especial",       "password123!, admin456@"),
        ("?s?d?d?d?d",   "Dict + especial + 4 dígitos",       "password!1234, admin@5678"),
        ("?u?d?d",       "Dict + mayúscula + 2 dígitos",      "passwordA12, adminZ99"),
        ("?d?s?d",       "Dict + dígito + especial + dígito",  "password1!2, admin3@4"),
    ]
    for mask, name, examples in complex_suffixes:
        stages.append(AttackStage(
            name=f"🔀 {name}",
            description=f"Palabra + sufijo complejo ({examples})",
            attack_mode=6,
            wordlist=wl,
            mask=mask,
            estimated_time="Medio",
        ))

    # ═════════════════════════════════════════════════════════
    #  PHASE 7: Prefix + dictionary (reverse hybrid)
    #  Cracks: 123password, !admin, 2024dragon
    # ═════════════════════════════════════════════════════════
    stages.append(AttackStage(
        name="🔄 1-3 dígitos + Dict",
        description="Dígitos al inicio + palabra (123password, 1admin)",
        attack_mode=7,
        wordlist=wl,
        mask="?d?d?d",
        increment=True,
        increment_min=1,
        increment_max=3,
        estimated_time="Rápido",
    ))

    stages.append(AttackStage(
        name="🔄 4 dígitos + Dict",
        description="4 dígitos al inicio (1234password, 2024admin)",
        attack_mode=7,
        wordlist=wl,
        mask="?d?d?d?d",
        estimated_time="Medio",
    ))

    stages.append(AttackStage(
        name="🔄 Especial + Dict",
        description="Símbolo al inicio (!password, @admin, #dragon)",
        attack_mode=7,
        wordlist=wl,
        mask="?s",
        estimated_time="Muy rápido",
    ))

    stages.append(AttackStage(
        name="🔄 Especial + dígitos + Dict",
        description="Símbolo + dígitos al inicio (!1password, @12admin)",
        attack_mode=7,
        wordlist=wl,
        mask="?s?d?d",
        increment=True,
        increment_min=2,
        increment_max=3,
        estimated_time="Rápido",
    ))

    # Prefix year
    for century, label in [("20", "20xx"), ("19", "19xx")]:
        stages.append(AttackStage(
            name=f"🔄 Año {label} + Dict",
            description=f"Año {century}xx al inicio + palabra ({century}24password)",
            attack_mode=7,
            wordlist=wl,
            mask=f"{century}?d?d",
            estimated_time="Rápido",
        ))

    # ═════════════════════════════════════════════════════════
    #  PHASE 8: Dictionary + advanced rules (if available)
    #  Cracks: P@$$w0rD, 4DM1N, dR@g0N (heavy mutations)
    # ═════════════════════════════════════════════════════════
    advanced_rules = [
        ("d3ad0ne.rule",                 "📖 Dict + d3ad0ne",           "Reglas agresivas de mutación"),
        ("dive.rule",                    "📖 Dict + dive",              "Reglas dive — profundidad máxima"),
        ("T0XlC.rule",                   "📖 Dict + T0XlC",            "Mutaciones tipo toxic/l33t extremo"),
        ("unix-ninja-leetspeak.rule",    "📖 Dict + ninja leetspeak",  "Leetspeak avanzado ninja-style"),
        ("OneRuleToRuleThemAll.rule",    "📖 Dict + OneRule",          "La mega-regla: todo en una"),
    ]
    for rule_name, stage_name, desc in advanced_rules:
        rule_path = rules_dir / rule_name
        if rule_path.is_file():
            stages.append(AttackStage(
                name=stage_name,
                description=desc,
                attack_mode=0,
                wordlist=wl,
                rules=[str(rule_path)],
                estimated_time="Largo",
            ))

    # ═════════════════════════════════════════════════════════
    #  PHASE 9: Dictionary + rules + hybrid combined
    #  Dict with best64 mutations + digit suffix
    # ═════════════════════════════════════════════════════════
    if best64.is_file():
        stages.append(AttackStage(
            name="🔥 Dict + best64 + 1-2 dígitos",
            description="Diccionario mutado + dígitos (P@ssword1, Adm1n23)",
            attack_mode=6,
            wordlist=wl,
            mask="?d?d",
            increment=True,
            increment_min=1,
            increment_max=2,
            rules=[str(best64)],
            estimated_time="Medio",
        ))

        stages.append(AttackStage(
            name="🔥 Dict + best64 + especial",
            description="Diccionario mutado + símbolo (P@ssword!, Adm1n@)",
            attack_mode=6,
            wordlist=wl,
            mask="?s",
            rules=[str(best64)],
            estimated_time="Medio",
        ))

        stages.append(AttackStage(
            name="🔥 Dict + best64 + especial + dígitos",
            description="Diccionario mutado + símbolo + dígitos (P@ssword!1, Adm1n@23)",
            attack_mode=6,
            wordlist=wl,
            mask="?s?d?d",
            increment=True,
            increment_min=2,
            increment_max=3,
            rules=[str(best64)],
            estimated_time="Largo",
        ))

    # ═════════════════════════════════════════════════════════
    #  PHASE 10: Smart mask fallback (no dictionary needed)
    #  For passwords not in any wordlist
    # ═════════════════════════════════════════════════════════
    smart_stages = build_smart_stages(wordlist="", hashcat_dir=hashcat_dir)
    for s in smart_stages:
        s.name = f"💀 {s.name}"
        s.description = f"[Fallback] {s.description}"
    stages.extend(smart_stages)

    return stages
