# 🔓 HashCracker GUI v1.2.0

**Interfaz gráfica moderna para Hashcat** — detección automática de 179 algoritmos, motor de ataque inteligente multi-etapa, soporte de SQL dumps con mapeo email→password, y resultados en tiempo real.

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![Hashcat 7.x](https://img.shields.io/badge/hashcat-7.x-orange)
![CustomTkinter](https://img.shields.io/badge/UI-CustomTkinter-purple)
![Signatures](https://img.shields.io/badge/firmas-179-green)

---

## ✨ Características principales

| Feature | Descripción |
|---------|-------------|
| 🎨 **Dark Theme** | Interfaz oscura completa (#0d0f12) con acentos cyan, magenta y verde |
| 🔍 **179 firmas** | Auto-detección de MD5, SHA, bcrypt, NTLM, Kerberos, WPA2, Office, wallets y más |
| 🧠 **Smart Attack** | 54 etapas ordenadas por probabilidad real de passwords humanos |
| ⚡ **Auto Attack** | 19 etapas con diccionario, reglas, híbrido y fuerza bruta |
| 📧 **SQL Dump** | Parsea email:hash, CSV, SQL INSERT — mapea resultados a email:password |
| 📊 **Multi-hash** | Crackea archivos con cientos de hashes, continúa entre etapas hasta completar todos |
| 🔓 **Cracks en vivo** | Muestra cada password crackeado al instante en la consola |
| 💾 **Auto-guardado** | Resultados en `Result/<fecha_hora>/` con TXT y CSV automáticos |
| 📋 **Historial** | Base persistente de todos los cracks con export a CSV, JSON, TXT |
| ⏹ **Stop inmediato** | Mata el proceso hashcat al instante con `proc.kill()` |

---

## 📦 Requisitos

| Componente | Versión |
|-----------|---------|
| Python | ≥ 3.10 |
| Hashcat | ≥ 6.0 (probado con 7.1.2) |
| GPU | NVIDIA (CUDA) o AMD (OpenCL) |
| CustomTkinter | ≥ 5.2.0 (se instala con pip) |

---

## 🚀 Instalación

```bash
cd HashCrackerGUI
pip install -r requirements.txt
python main.py
```

---

## 🎮 Flujo de uso

### Modo básico (hash directo)

```
1. 🔧 Selecciona hashcat.exe con el botón 📂
2. 🔑 Pega un hash o carga un archivo con 📄
3. 🔍 Clic en Detectar → identifica el algoritmo
4. ⚔️ Elige modo de ataque (Smart recomendado)
5. ▶  INICIAR → ve la salida en vivo
6. 📋 Resultados guardados automáticamente
```

### Modo SQL Dump (email:hash)

```
1. 📄 Desde archivo → selecciona el dump
2. ✅ Se auto-detecta formato email:hash
3. 🔍 Detectar → identifica algoritmo de la primera línea
4. 🧠 Smart → INICIAR
5. 📧 Consola muestra: email → password crackeado
6. 💾 Auto-guarda en Result/ como email:password
```

---

## ⚔️ Modos de ataque

### 🧠 Smart (Inteligente) — 54 etapas

Ataca en el orden en que los humanos realmente crean passwords:

| Fase | Etapas | Qué prueba | Ejemplos |
|------|--------|------------|----------|
| 📖 Diccionario | 1-6 | Wordlist + reglas + dígitos + años | *(si se provee wordlist)* |
| 🔤 Minúsculas | 7 | Palabras a-z, 1→8 chars | `password`, `dragon` |
| 🔤 Palabra+dígito | 8-12 | Letras + 1 dígito al final | `admin1`, `hello7` |
| 🔠 Capitalizada | 13 | Mayúscula inicial | `Password`, `Dragon` |
| 🔠 Capital+dígitos | 14-24 | Mayúscula + letras + 1-4 dígitos | `Admin123`, `Pass12` |
| 🔢 Palabra+dígitos | 25-32 | Minúsculas + 2-4 dígitos | `pass1234`, `test99` |
| 📅 Palabra+año | 33-48 | Letras + 19xx/20xx | `admin2024` |
| 🔢 PIN numérico | 49 | Solo dígitos 1→10 | `123456`, `0000` |
| ⚡ Especiales | 50-57 | Letras + símbolo + dígitos | `admin!12`, `Pass!1` |
| 🔀 Alfanumérico | 58 | Mezclado a-z + 0-9 | `p4ssw0rd` |
| 🔤 Largas | 59 | Minúsculas 9-10 chars | `qwertyzxcv` |
| 💀 Full charset | 60 | Todos imprimibles 1→6 | `P@$$!` |

### ⚡ Auto — 19 etapas

Versión más compacta con diccionario, reglas, patrones comunes y fuerza bruta.

### Modos manuales

| Modo | Nombre | Uso |
|------|--------|-----|
| 0 | Diccionario | Wordlist → hash |
| 3 | Fuerza bruta / Mask | Genera candidatos con máscara |
| 6 | Híbrido WL+Mask | Wordlist + máscara al final |
| 7 | Híbrido Mask+WL | Máscara + wordlist al final |

---

## 🔍 Algoritmos soportados (179 firmas)

| Categoría | Tipos detectados |
|-----------|-----------------|
| **Raw** | MD4, MD5, SHA-1, SHA-224/256/384/512, SHA3-256/512, Keccak, RIPEMD-160, Whirlpool, BLAKE2b |
| **Unix crypt** | md5crypt, sha256crypt, sha512crypt, bcrypt, scrypt, descrypt, BSDi |
| **PBKDF2** | HMAC-SHA1, SHA256, SHA512, MD5 |
| **Windows** | NTLM, LM, NetNTLMv1/v2, DCC, DCC2, DPAPI v1/v2 |
| **Kerberos** | TGS-REP RC4/AES128/AES256, AS-REP RC4/AES, Pre-Auth |
| **HMAC** | MD5, SHA1, SHA256, SHA512 |
| **Salted** | md5/sha1/sha256/sha512 ($pass.$salt, $salt.$pass) |
| **Databases** | MySQL 323/4.1+, MSSQL 2000-2012, PostgreSQL, Oracle H/S/T, MongoDB, CouchDB |
| **Web/CMS** | WordPress, phpBB3, Django, Joomla, Drupal 7, vBulletin, PrestaShop, Magento |
| **WiFi** | WPA2 PMKID+EAPOL, TACACS+, SNMPv3, RADIUS |
| **Office** | MS Office 2003-2013+, PDF 1.1-1.7, ODF 1.1/1.2 |
| **Archives** | 7-Zip, RAR3/5, PKZIP, WinZip, SecureZIP |
| **Pwd managers** | KeePass, 1Password, LastPass, Bitwarden, Dashlane |
| **Crypto** | Bitcoin, Ethereum (PBKDF2/Scrypt), Electrum v1/v2, Monero, MultiBit |
| **OS/Network** | macOS, AIX, Cisco PIX/ASA/Type 5/8/9, FortiGate, Juniper |
| **LDAP** | SHA/SSHA 1/256/512, CRAM-MD5 |
| **Messaging** | Telegram Desktop/Mobile, Signal |
| **Disk encryption** | LUKS, VeraCrypt, TrueCrypt, FileVault 2, BitLocker, APFS, eCryptfs |
| **SSH/PKI** | RSA, DSA, ECDSA, Ed25519, PEM, PKCS#12, JWT |
| **Misc** | SIP, TOTP, Minecraft, Atlassian, SAP, Lotus Notes, DNSSEC, QNX |

---

## 📧 Modo SQL Dump

Soporta archivos de base de datos con formato email:hash.

### Formatos reconocidos

```
# Formato 1: email:hash (más común)
carlos.lopez@gmail.com:5f4dcc3b5aa765d61d8327deb882cf99

# Formato 2: CSV con headers
email,password_hash,username
user@mail.com,5f4dcc3b5aa765d61d8327deb882cf99,user1

# Formato 3: SQL INSERT
INSERT INTO users (email, pass_hash) VALUES ('user@mail.com', '5f4dcc...');
```

### Flujo de procesamiento

```
Archivo dump (email:hash)
    │
    ▼  dump_parser.py
Extrae hashes puros → dump_hashes.txt (para hashcat)
Guarda mapa: hash → [emails]
    │
    ▼  hashcat ejecuta sobre dump_hashes.txt
Crackea: hash:password
    │
    ▼  _save_crack_result()
Mapea hash→email via dump_data
    │
    ▼  Resultado final
📧 carlos.lopez@gmail.com:abc123
📧 maria.garcia@hotmail.com:love
```

### Auto-guardado

Al terminar la ejecución, los resultados se guardan automáticamente:

```
HashCrackerGUI/
└── Result/
    └── 2026-10-23_22-05-54/
        ├── cracked.txt           ← email:password (una por línea)
        └── cracked_details.csv   ← email, password, hash, algoritmo, fecha
```

---

## 💾 Sistema de resultados

### Historial persistente

Todos los cracks se almacenan en `results.json` con:
- Hash original
- Password crackeado
- Algoritmo y modo
- Método de ataque y etapa
- Email asociado (si es modo dump)
- Fecha y hora

### Export manual

Botón **💾 Exportar** en la barra superior:

| Formato | Contenido |
|---------|-----------|
| `.txt` | `email:password` (dump) o `hash:password` (normal) |
| `.csv` | Tabla completa con email, password, hash, algoritmo, fecha |
| `.json` | Todos los campos en formato estructurado |

---

## 🎨 Paleta de colores

| Elemento | Color | Hex |
|----------|-------|-----|
| Fondo principal | Negro profundo | `#0d0f12` |
| Paneles | Gris oscuro | `#141720` |
| Inputs | Gris medio | `#1a1e2e` |
| Acento primario | Cyan | `#00e5ff` |
| Acento secundario | Magenta | `#d946ef` |
| Éxito / Cracked | Verde | `#22c55e` |
| Error | Rojo | `#ef4444` |
| Advertencia | Amarillo | `#eab308` |
| SQL Dump | Naranja | `#f97316` |
| Texto primario | Slate claro | `#e2e8f0` |

---

## 📁 Estructura del proyecto

```
HashCrackerGUI/
├── main.py                          ← Punto de entrada
├── pyproject.toml                   ← Metadatos del proyecto
├── requirements.txt                 ← customtkinter
├── README.md                        ← Este archivo
├── config.json                      ← Configuración persistente (auto)
├── results.json                     ← Historial de cracks (auto)
├── .gitignore
├── Result/                          ← Auto-guardado por ejecución
│   └── 2026-10-23_22-05-54/
│       ├── cracked.txt
│       └── cracked_details.csv
├── docs/
│   ├── USAGE_EXAMPLES.md
│   └── ARCHITECTURE.md
└── hashcracker_gui/
    ├── __init__.py                  ← Versión y metadata
    ├── app.py                       ← Ventana principal (sidebar + consola)
    ├── core.py                      ← Wrapper hashcat (subprocess + streaming)
    ├── detector.py                  ← Auto-detección de 179 algoritmos
    ├── auto_attack.py               ← Motor Auto Attack (19 etapas)
    ├── smart_attack.py              ← Motor Smart Attack (54 etapas)
    ├── dump_parser.py               ← Parser de SQL dumps (email:hash)
    ├── results.py                   ← Historial persistente + export
    ├── config.py                    ← Configuración persistente JSON
    ├── theme.py                     ← Paleta oscura centralizada
    └── widgets.py                   ← 9 widgets custom dark
```

---

## 🏗️ Arquitectura

```
┌──────────────────────────────────────────────────────────┐
│                     main.py                              │
└──────────────────────┬───────────────────────────────────┘
                       │
┌──────────────────────▼───────────────────────────────────┐
│                  app.py (HashCrackerApp)                  │
│                                                          │
│  ┌─────────────┐  ┌────────────┐  ┌──────────────────┐  │
│  │  Sidebar    │  │  Console   │  │  Result Bar      │  │
│  │  (inputs)   │  │  (output)  │  │  (status/crack)  │  │
│  └──────┬──────┘  └──────┬─────┘  └──────────────────┘  │
└─────────┼────────────────┼───────────────────────────────┘
          │                │
  ┌───────▼──────┐   ┌────▼─────────┐
  │  detector    │   │  auto_attack │──▶ threading.Thread
  │  (179 sigs)  │   │  smart_attack│      │
  └──────────────┘   └──────────────┘      ▼
                                      subprocess.Popen
  ┌──────────────┐   ┌──────────────┐  (hashcat.exe)
  │ dump_parser  │   │  results     │
  │ (email:hash) │   │  (history)   │──▶ Result/<ts>/
  └──────────────┘   └──────────────┘
```

### Threading model

```
Main Thread (Tkinter)              Worker Thread
─────────────────────              ─────────────
  _start_auto()
    ├─ validate inputs
    ├─ build stages (54 or 19)
    ├─ spawn thread ──────────────▶ _run_auto_worker()
    │                                 │
    │                                 ├─ for stage in stages:
    │                                 │    ├─ Popen(hashcat)
    │  ◀── on_cracked(line) ◀────────│    ├─ for line in stdout:
    │      save + display             │    │    detect cracks
    │                                 │    └─ read output file
    │                                 │
    │  ◀── _on_auto_finished() ◀─────┘
    │       ├─ show final status
    │       ├─ _auto_save_results()
    │       └─ re-enable buttons
```

### Flujo multi-hash

```
Stage 1: lowercase 1-8   → cracks 150/200   ──▶ saves 150
Stage 2: word+digit      → cracks 20/200    ──▶ saves 20
Stage 3: capitalized     → cracks 15/200    ──▶ saves 15
Stage 4: patterns        → cracks 10/200    ──▶ saves 10
Stage 5: ...             → cracks 5/200     ──▶ saves 5
                           ─────────────
                           200/200 TOTAL ✔  ──▶ auto-save Result/
```

Hashcat usa un potfile dedicado por sesión para recordar qué hashes ya crackeó entre etapas.

---

## ⚙️ Configuración persistente

Al cerrar la app, guarda en `config.json`:

```json
{
  "hashcat_path": "C:\\ruta\\a\\hashcat.exe",
  "last_wordlist": "C:\\wordlists\\rockyou.txt",
  "last_mask": "?a?a?a?a?a?a?a?a",
  "last_mode": -1,
  "window_width": 1100,
  "window_height": 750
}
```

Se restaura automáticamente en la próxima ejecución.

---

## 🛡️ Notas de seguridad

- Esta herramienta es para uso **educativo y autorizado** exclusivamente.
- Solo utilícela con hashes de su propiedad o con autorización explícita.
- No almacena ni transmite datos a servicios externos.
- Todo el procesamiento es local a través de hashcat.
- Los archivos de resultados se guardan localmente en la carpeta del proyecto.

---

## 📄 Licencia

MIT — Libre para uso personal y educativo.
