# 🏗️ Arquitectura — HashCracker GUI v1.2.0

## Stack tecnológico

| Capa | Tecnología | Detalle |
|------|-----------|---------|
| GUI Framework | CustomTkinter 6.x | Sobre Tkinter, aspecto nativo moderno |
| Tema | Custom dark palette | 30+ constantes en theme.py |
| Hash detection | Regex engine | 179 firmas compiladas |
| Attack engines | auto_attack + smart_attack | Cadenas multi-etapa |
| Dump parser | dump_parser.py | email:hash, CSV, SQL INSERT |
| Results | results.py | JSON persistente + export CSV/TXT/JSON |
| Auto-save | Result/<timestamp>/ | TXT + CSV por ejecución |
| Hashcat | subprocess + threading | Streaming stdout en hilo separado |
| Python | 3.10+ | match/case, slots, type hints |

---

## Diagrama de componentes

```
┌────────────────────────────────────────────────────────────┐
│                        main.py                             │
└───────────────────────────┬────────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────────┐
│                 app.py (HashCrackerApp)                     │
│                                                            │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────┐   │
│  │   Sidebar    │  │   Console    │  │  Result Bar    │   │
│  │  310px fixed │  │  flex grow   │  │  bottom dock   │   │
│  └───┬──────────┘  └──────┬───────┘  └────────────────┘   │
│      │                    │                                │
│  ┌───▼──┐ ┌──────┐  ┌────▼───┐  ┌─────────┐ ┌────────┐  │
│  │detect│ │dump  │  │auto_   │  │smart_   │ │results │  │
│  │or.py │ │parser│  │attack  │  │attack   │ │.py     │  │
│  │      │ │.py   │  │.py     │  │.py      │ │        │  │
│  │179   │ │email │  │19 stg  │  │54 stg   │ │JSON    │  │
│  │sigs  │ │:hash │  │        │  │         │ │+export │  │
│  └──────┘ └──────┘  └────┬───┘  └────┬────┘ └────┬───┘  │
│                          │           │            │       │
└──────────────────────────┼───────────┼────────────┼───────┘
                           │           │            │
                      subprocess    subprocess   Result/
                      (hashcat)    (hashcat)    <timestamp>/
```

---

## Módulos

### `app.py` — Orquestador principal (900+ líneas)

Ventana única con layout sidebar + consola. Gestiona:
- Ciclo de vida de la UI (build, restore, close)
- Validación de inputs
- Dispatch a auto/smart/manual attack
- Callbacks de crack en vivo
- Auto-save de resultados
- Historial y export

### `detector.py` — Motor de detección (179 firmas)

Regex compilado en import-time organizado por familias:
- bcrypt/scrypt/Argon2, Unix crypt, PBKDF2
- Windows/AD, Kerberos
- Raw hashes (MD/SHA/Keccak/Whirlpool/BLAKE2)
- HMAC, Salted variants
- Databases, Web/CMS, WiFi, Office, Archives
- Password managers, Crypto wallets, Disk encryption
- SSH/PKI/JWT, LDAP, Messaging
- Cisco/FortiGate/Juniper, QNX

Sistema de prioridades para disambiguación (ej: MD5 > NTLM > MD4 para 32 hex chars).

### `auto_attack.py` — Motor Auto Attack

- `build_stages()`: 19 etapas con diccionario + rules + híbrido + fuerza bruta
- `run_auto_attack()`: ejecutor multi-etapa con:
  - Potfile dedicado por sesión (hashcat recuerda cracks entre etapas)
  - Detección de cracks en vivo via validación hex del output
  - Callback `on_cracked` para UI en tiempo real
  - `proc.kill()` + `stdout.close()` para stop inmediato
  - Conteo de hashes crackeados vs total para multi-hash
  - Continúa entre etapas hasta completar TODOS los hashes

### `smart_attack.py` — Motor Smart Attack

- `build_smart_stages()`: 54 etapas ordenadas por probabilidad humana
- Progresión: lowercase → word+digit → capitalized → patterns → years → PINs → specials → mixed → full

### `dump_parser.py` — Parser de SQL dumps

- Auto-detecta formatos: `email:hash`, CSV con headers, SQL INSERT
- Extrae hashes puros a archivo para hashcat
- Mantiene mapa `hash → [emails]` para reconstrucción de resultados
- Valida emails con regex y hashes por longitud hex

### `results.py` — Historial persistente

- `ResultsStore`: append-only JSON store
- `CrackResult`: dataclass con hash, password, algoritmo, método, email, fecha
- Export a CSV, TXT, JSON
- Limpieza de historial

### `core.py` — Wrapper de hashcat

- `CrackJob` dataclass con `build_command()` usando match/case
- `run_hashcat()` generator con streaming stdout
- `hashcat_version()` verificación de instalación
- `stdin=DEVNULL` para evitar hang en prompts interactivos

### `config.py` — Configuración

- `AppConfig` dataclass con serialización JSON
- Guarda: ruta hashcat, wordlist, máscara, modo, tamaño de ventana
- Auto-carga/save

### `theme.py` — Paleta oscura

30+ constantes centralizadas: backgrounds, acentos, texto, bordes, fonts, dimensiones.

### `widgets.py` — 9 widgets custom

| Widget | Función |
|--------|---------|
| `GlowLabel` | Labels con color accent |
| `SectionTitle` | Headers de sección cyan |
| `DarkEntry` | Input con fondo oscuro y placeholder |
| `AccentButton` | Botón primario cyan |
| `SecondaryButton` | Botón ghost con borde |
| `MagentaButton` | Botón secundario magenta |
| `DarkCard` | Frame contenedor con borde |
| `StatusBadge` | Badge de estado coloreado |
| `OutputConsole` | Textbox read-only con colour tags |

---

## Decisiones de diseño

1. **CustomTkinter**: una dependencia pip, aspecto nativo moderno, sin runtime Qt
2. **Thread + after()**: thread-safe sin conflictos de event loop
3. **Potfile por sesión**: hashcat recuerda cracks entre etapas sin contaminar runs anteriores
4. **stdin=DEVNULL**: evita que hashcat cuelgue esperando input interactivo
5. **proc.kill() + stdout.close()**: stop inmediato sin deadlocks de pipe
6. **Hex validation para cracks**: evita falsos positivos de URLs y líneas de status
7. **Auto-save en Result/timestamp/**: cada ejecución preservada, sin overwrite
8. **Dump parser multi-formato**: auto-detecta email:hash vs CSV vs SQL INSERT
9. **Prioridades en detector**: MD5 > NTLM > MD4 para 32 hex chars (por frecuencia real)
10. **-O flag**: kernels optimizados por defecto para máxima velocidad
