"""
Hash algorithm auto-detection engine — expanded edition.

Maps hash patterns (regex + length) to hashcat mode numbers.
120+ signatures covering all major hash families.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class HashSignature:
    """Describes a known hash format."""

    name: str
    mode: int
    pattern: re.Pattern[str]
    priority: int = 0


# fmt: off
_SIGNATURES: list[HashSignature] = [

    # ═══════════════════════════════════════════════════════════
    #  BCRYPT / SCRYPT / ARGON2
    # ═══════════════════════════════════════════════════════════
    HashSignature("bcrypt $2*$",                3200,  re.compile(r"^\$2[aby]?\$\d{2}\$.{53}$")),
    HashSignature("scrypt",                     8900,  re.compile(r"^SCRYPT:\d+:\d+:\d+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$")),
    HashSignature("Argon2id",                   34000, re.compile(r"^\$argon2id\$")),
    HashSignature("Argon2d",                    34000, re.compile(r"^\$argon2d\$")),
    HashSignature("Argon2i",                    34000, re.compile(r"^\$argon2i\$")),

    # ═══════════════════════════════════════════════════════════
    #  UNIX CRYPT FAMILY
    # ═══════════════════════════════════════════════════════════
    HashSignature("sha512crypt $6$",            1800,  re.compile(r"^\$6\$[^$]+\$[A-Za-z0-9./]{86}$")),
    HashSignature("sha256crypt $5$",            7400,  re.compile(r"^\$5\$[^$]+\$[A-Za-z0-9./]{43}$")),
    HashSignature("md5crypt $1$",               500,   re.compile(r"^\$1\$[^$]+\$[A-Za-z0-9./]{22}$")),
    HashSignature("apr1 (Apache)",              1600,  re.compile(r"^\$apr1\$[^$]+\$[A-Za-z0-9./]{22}$")),
    HashSignature("descrypt",                   1500,  re.compile(r"^[A-Za-z0-9./]{13}$")),
    HashSignature("BSDi crypt",                 12400, re.compile(r"^_[A-Za-z0-9./]{19}$")),

    # ═══════════════════════════════════════════════════════════
    #  PBKDF2 FAMILY
    # ═══════════════════════════════════════════════════════════
    HashSignature("PBKDF2-HMAC-SHA256",         10900, re.compile(r"^sha256:\d+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$")),
    HashSignature("PBKDF2-HMAC-SHA512",         12100, re.compile(r"^sha512:\d+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$")),
    HashSignature("PBKDF2-HMAC-SHA1",           12001, re.compile(r"^sha1:\d+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$")),
    HashSignature("PBKDF2-HMAC-MD5",            11900, re.compile(r"^md5:\d+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$")),

    # ═══════════════════════════════════════════════════════════
    #  WINDOWS / ACTIVE DIRECTORY
    # ═══════════════════════════════════════════════════════════
    HashSignature("NTLM",                       1000,  re.compile(r"^[a-fA-F0-9]{32}$"), priority=0),
    HashSignature("LM",                         3000,  re.compile(r"^[a-fA-F0-9]{32}$"), priority=-2),
    HashSignature("NetNTLMv2",                  5600,  re.compile(r"^[^:]+::\S+:[a-fA-F0-9]{16}:[a-fA-F0-9]{32}:[a-fA-F0-9]+$")),
    HashSignature("NetNTLMv1",                  5500,  re.compile(r"^[^:]+::\S+:[a-fA-F0-9]{48}:[a-fA-F0-9]{48}:[a-fA-F0-9]{16}$")),
    HashSignature("DCC (Domain Cached Cred)",   1100,  re.compile(r"^[a-fA-F0-9]{32}:[^:]+$"), priority=-1),
    HashSignature("DCC2 (mscash2)",             2100,  re.compile(r"^\$DCC2\$\d+#[^#]+#[a-fA-F0-9]{32}$")),
    HashSignature("DPAPI masterkey v1",         15300, re.compile(r"^\$DPAPImk\$1\$")),
    HashSignature("DPAPI masterkey v2",         15900, re.compile(r"^\$DPAPImk\$2\$")),

    # ═══════════════════════════════════════════════════════════
    #  KERBEROS
    # ═══════════════════════════════════════════════════════════
    HashSignature("Kerberoast TGS-REP RC4",     13100, re.compile(r"^\$krb5tgs\$23\$")),
    HashSignature("AS-REP Roast RC4",           18200, re.compile(r"^\$krb5asrep\$23\$")),
    HashSignature("Kerberos TGS-REP AES128",    19600, re.compile(r"^\$krb5tgs\$17\$")),
    HashSignature("Kerberos TGS-REP AES256",    19700, re.compile(r"^\$krb5tgs\$18\$")),
    HashSignature("Kerberos AS-REP AES128",     19800, re.compile(r"^\$krb5asrep\$17\$")),
    HashSignature("Kerberos AS-REP AES256",     19900, re.compile(r"^\$krb5asrep\$18\$")),
    HashSignature("Kerberos 5 Pre-Auth etype23",7500,  re.compile(r"^\$krb5pa\$23\$")),

    # ═══════════════════════════════════════════════════════════
    #  RAW HASHES (SHA / MD families)
    # ═══════════════════════════════════════════════════════════
    HashSignature("SHA-512",                    1700,  re.compile(r"^[a-fA-F0-9]{128}$")),
    HashSignature("SHA-384",                    10800, re.compile(r"^[a-fA-F0-9]{96}$")),
    HashSignature("SHA-256",                    1400,  re.compile(r"^[a-fA-F0-9]{64}$")),
    HashSignature("SHA-224",                    1300,  re.compile(r"^[a-fA-F0-9]{56}$")),
    HashSignature("SHA-1",                      100,   re.compile(r"^[a-fA-F0-9]{40}$")),
    HashSignature("MD5",                        0,     re.compile(r"^[a-fA-F0-9]{32}$"), priority=1),
    HashSignature("MD4",                        900,   re.compile(r"^[a-fA-F0-9]{32}$"), priority=-1),
    HashSignature("RIPEMD-160",                 6000,  re.compile(r"^[a-fA-F0-9]{40}$"), priority=-1),
    HashSignature("Whirlpool",                  6100,  re.compile(r"^[a-fA-F0-9]{128}$"), priority=-1),
    HashSignature("SHA3-256",                   17400, re.compile(r"^[a-fA-F0-9]{64}$"), priority=-1),
    HashSignature("SHA3-512",                   17600, re.compile(r"^[a-fA-F0-9]{128}$"), priority=-1),
    HashSignature("Keccak-256",                 17800, re.compile(r"^[a-fA-F0-9]{64}$"), priority=-2),
    HashSignature("Keccak-512",                 18000, re.compile(r"^[a-fA-F0-9]{128}$"), priority=-2),
    HashSignature("BLAKE2b-512",                600,   re.compile(r"^\$BLAKE2\$[a-fA-F0-9]{128}$")),

    # ═══════════════════════════════════════════════════════════
    #  HMAC VARIANTS
    # ═══════════════════════════════════════════════════════════
    HashSignature("HMAC-MD5",                   50,    re.compile(r"^[a-fA-F0-9]{32}:[^\s]+$"), priority=-2),
    HashSignature("HMAC-SHA1",                  150,   re.compile(r"^[a-fA-F0-9]{40}:[^\s]+$"), priority=-2),
    HashSignature("HMAC-SHA256",                1450,  re.compile(r"^[a-fA-F0-9]{64}:[^\s]+$"), priority=-2),
    HashSignature("HMAC-SHA512",                1750,  re.compile(r"^[a-fA-F0-9]{128}:[^\s]+$"), priority=-2),

    # ═══════════════════════════════════════════════════════════
    #  SALTED HASHES
    # ═══════════════════════════════════════════════════════════
    HashSignature("md5($pass.$salt)",           10,    re.compile(r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]+$"), priority=-3),
    HashSignature("md5($salt.$pass)",           20,    re.compile(r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]+$"), priority=-4),
    HashSignature("sha1($pass.$salt)",          110,   re.compile(r"^[a-fA-F0-9]{40}:[a-zA-Z0-9]+$"), priority=-3),
    HashSignature("sha1($salt.$pass)",          120,   re.compile(r"^[a-fA-F0-9]{40}:[a-zA-Z0-9]+$"), priority=-4),
    HashSignature("sha256($pass.$salt)",        1410,  re.compile(r"^[a-fA-F0-9]{64}:[a-zA-Z0-9]+$"), priority=-3),
    HashSignature("sha512($pass.$salt)",        1710,  re.compile(r"^[a-fA-F0-9]{128}:[a-zA-Z0-9]+$"), priority=-3),

    # ═══════════════════════════════════════════════════════════
    #  DATABASES
    # ═══════════════════════════════════════════════════════════
    HashSignature("MySQL 4.1+ (SHA1)",          300,   re.compile(r"^\*[A-Fa-f0-9]{40}$")),
    HashSignature("MySQL 323",                  200,   re.compile(r"^[a-fA-F0-9]{16}$")),
    HashSignature("MSSQL (2012+)",              1731,  re.compile(r"^0x0200[a-fA-F0-9]{136}$")),
    HashSignature("MSSQL (2005)",               132,   re.compile(r"^0x0100[a-fA-F0-9]{88}$")),
    HashSignature("MSSQL (2000)",               131,   re.compile(r"^0x0100[a-fA-F0-9]{88}$"), priority=-1),
    HashSignature("PostgreSQL MD5",             12,    re.compile(r"^md5[a-fA-F0-9]{32}$")),
    HashSignature("Oracle H (DES)",             3100,  re.compile(r"^[a-fA-F0-9]{16}$"), priority=-1),
    HashSignature("Oracle S (SHA1)",            112,   re.compile(r"^[a-fA-F0-9]{40}:[a-fA-F0-9]{20}$")),
    HashSignature("Oracle T (SHA512)",          12300, re.compile(r"^[a-fA-F0-9]{160}$")),
    HashSignature("MongoDB (SCRAM-SHA1)",       24100, re.compile(r"^\$mongodb-scram\$")),
    HashSignature("CouchDB (PBKDF2-SHA1)",      24200, re.compile(r"^\$couchdb\$")),

    # ═══════════════════════════════════════════════════════════
    #  WEB FRAMEWORKS / CMS
    # ═══════════════════════════════════════════════════════════
    HashSignature("Django (PBKDF2-SHA256)",     10000, re.compile(r"^pbkdf2_sha256\$\d+\$")),
    HashSignature("Django (SHA1)",              800,   re.compile(r"^sha1\$[^$]+\$[a-fA-F0-9]{40}$")),
    HashSignature("Django (MD5)",               12001, re.compile(r"^md5\$[^$]+\$[a-fA-F0-9]{32}$")),
    HashSignature("phpBB3 (MD5)",               400,   re.compile(r"^\$H\$[A-Za-z0-9./]{31}$")),
    HashSignature("WordPress (MD5)",            400,   re.compile(r"^\$P\$[A-Za-z0-9./]{31}$"), priority=1),
    HashSignature("Joomla (MD5)",               11,    re.compile(r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]{32}$")),
    HashSignature("Drupal 7+",                  7900,  re.compile(r"^\$S\$[A-Za-z0-9./]{52}$")),
    HashSignature("vBulletin",                  2611,  re.compile(r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]{3,}$"), priority=-2),
    HashSignature("osCommerce / xt:Commerce",   21,    re.compile(r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]{2}$")),
    HashSignature("PrestaShop",                 11000, re.compile(r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{56}$")),
    HashSignature("Magento",                    20,    re.compile(r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]{2}$"), priority=-2),

    # ═══════════════════════════════════════════════════════════
    #  WIFI / NETWORK
    # ═══════════════════════════════════════════════════════════
    HashSignature("WPA-PBKDF2-PMKID+EAPOL",    22000, re.compile(r"^WPA\*")),
    HashSignature("WPA-PMKID-PBKDF2",          22000, re.compile(r"^[a-fA-F0-9]{32}\*[a-fA-F0-9]{12}\*[a-fA-F0-9]{12}\*")),
    HashSignature("TACACS+",                    16100, re.compile(r"^\$tacacs-plus\$")),
    HashSignature("SNMPv3 HMAC-MD5/SHA1",       25100, re.compile(r"^\$SNMPv3\$0\$")),
    HashSignature("SNMPv3 HMAC-SHA256",         25200, re.compile(r"^\$SNMPv3\$1\$")),
    HashSignature("RADIUS (MD5)",               25300, re.compile(r"^\$radius\$")),

    # ═══════════════════════════════════════════════════════════
    #  OFFICE / DOCUMENTS
    # ═══════════════════════════════════════════════════════════
    HashSignature("MS Office 2013+",            9600,  re.compile(r"^\$office\$2013\$")),
    HashSignature("MS Office 2010",             9500,  re.compile(r"^\$office\$2010\$")),
    HashSignature("MS Office 2007",             9400,  re.compile(r"^\$office\$2007\$")),
    HashSignature("MS Office ≤2003 (MD5+RC4)",  9700,  re.compile(r"^\$oldoffice\$[01]\$")),
    HashSignature("MS Office ≤2003 (SHA1+RC4)", 9800,  re.compile(r"^\$oldoffice\$[34]\$")),
    HashSignature("PDF 1.1-1.3 (MD5+RC4)",      10400, re.compile(r"^\$pdf\$1\*2\$")),
    HashSignature("PDF 1.4-1.6 (MD5+RC4)",      10500, re.compile(r"^\$pdf\$2\*3\$")),
    HashSignature("PDF 1.7 Level 3 (SHA256)",   10600, re.compile(r"^\$pdf\$5\*5\$")),
    HashSignature("PDF 1.7 Level 8 (AES256)",   10700, re.compile(r"^\$pdf\$5\*8\$")),
    HashSignature("Open Document (ODF 1.2)",    18400, re.compile(r"^\$odf\$\*1\*1\*")),
    HashSignature("Open Document (ODF 1.1)",    18300, re.compile(r"^\$odf\$\*0\*0\*")),

    # ═══════════════════════════════════════════════════════════
    #  ARCHIVES
    # ═══════════════════════════════════════════════════════════
    HashSignature("7-Zip",                      11600, re.compile(r"^\$7z\$")),
    HashSignature("RAR5",                       13000, re.compile(r"^\$rar5\$")),
    HashSignature("RAR3-hp",                    12500, re.compile(r"^\$RAR3\$")),
    HashSignature("PKZIP (Mixed Multi-File)",   17220, re.compile(r"^\$pkzip2\$")),
    HashSignature("PKZIP (Compressed)",         17210, re.compile(r"^\$pkzip\$")),
    HashSignature("PKZIP Master Key",           20510, re.compile(r"^\$pkzip-mk\$")),
    HashSignature("SecureZIP AES-256",          23003, re.compile(r"^\$zip3\$")),
    HashSignature("WinZip (PBKDF2-HMAC-SHA1)",  13600, re.compile(r"^\$zip2\$")),

    # ═══════════════════════════════════════════════════════════
    #  PASSWORD MANAGERS
    # ═══════════════════════════════════════════════════════════
    HashSignature("KeePass (AES/TwoFish)",      13400, re.compile(r"^\$keepass\$")),
    HashSignature("1Password (cloudkeychain)",  8200,  re.compile(r"^\$cloudkeychain\$")),
    HashSignature("1Password (agilekeychain)",  6600,  re.compile(r"^\$agilekeychain\$")),
    HashSignature("LastPass",                   6800,  re.compile(r"^[a-fA-F0-9]{64}:[a-fA-F0-9]+:\d+:[^\s]+$")),
    HashSignature("Bitwarden",                  31700, re.compile(r"^\$bitwarden\$")),
    HashSignature("Dashlane",                   26200, re.compile(r"^\$dashlane\$")),

    # ═══════════════════════════════════════════════════════════
    #  CRYPTOCURRENCY
    # ═══════════════════════════════════════════════════════════
    HashSignature("Bitcoin wallet.dat",         11300, re.compile(r"^\$bitcoin\$")),
    HashSignature("Ethereum wallet (PBKDF2)",   15600, re.compile(r"^\$ethereum\$p")),
    HashSignature("Ethereum wallet (Scrypt)",   15700, re.compile(r"^\$ethereum\$s")),
    HashSignature("Electrum wallet (v1)",       16600, re.compile(r"^\$electrum\$1\$")),
    HashSignature("Electrum wallet (v2)",       21700, re.compile(r"^\$electrum\$4\$")),
    HashSignature("Monero wallet",              18300, re.compile(r"^\$monero\$")),
    HashSignature("MultiBit Classic .key",      22500, re.compile(r"^\$multibit\$1\$")),
    HashSignature("MultiBit HD .aes",           22700, re.compile(r"^\$multibit\$2\$")),

    # ═══════════════════════════════════════════════════════════
    #  LINUX / MACOS / CISCO
    # ═══════════════════════════════════════════════════════════
    HashSignature("macOS v10.8+ (PBKDF2-SHA512)", 7100, re.compile(r"^\$ml\$\d+\$")),
    HashSignature("macOS v10.4/v10.5/v10.6",    1722,  re.compile(r"^[a-fA-F0-9]{48}$")),
    HashSignature("AIX {ssha256}",              6400,  re.compile(r"^\{ssha256\}")),
    HashSignature("AIX {ssha512}",              6500,  re.compile(r"^\{ssha512\}")),
    HashSignature("AIX {ssha1}",                6700,  re.compile(r"^\{ssha1\}")),
    HashSignature("Cisco-PIX MD5",              2400,  re.compile(r"^[A-Za-z0-9./]{16}$")),
    HashSignature("Cisco-ASA MD5",              2410,  re.compile(r"^[A-Za-z0-9./]{16}:[A-Za-z0-9./]+$")),
    HashSignature("Cisco Type 5 (MD5)",         500,   re.compile(r"^\$1\$[A-Za-z0-9./]{8}\$[A-Za-z0-9./]{22}$"), priority=-1),
    HashSignature("Cisco Type 8 (PBKDF2-SHA256)", 9200, re.compile(r"^\$8\$[A-Za-z0-9./]{14}\$[A-Za-z0-9./]{43}$")),
    HashSignature("Cisco Type 9 (scrypt)",      9300,  re.compile(r"^\$9\$[A-Za-z0-9./]{14}\$[A-Za-z0-9./]{43}$")),
    HashSignature("Cisco-IOS $4$ (SHA256)",     5700,  re.compile(r"^\$4\$[^\$]+\$[A-Za-z0-9./]+$")),
    HashSignature("FortiGate (SHA256)",         7000,  re.compile(r"^AK1[A-Za-z0-9/+=]{44}$")),
    HashSignature("Juniper NetScreen (MD5)",    22,    re.compile(r"^[a-fA-F0-9]{30}:[a-zA-Z0-9]{4,}$")),

    # ═══════════════════════════════════════════════════════════
    #  LDAP / DIRECTORY
    # ═══════════════════════════════════════════════════════════
    HashSignature("SSHA-1 (LDAP)",              111,   re.compile(r"^\{SSHA\}[A-Za-z0-9+/=]+$")),
    HashSignature("SSHA-256 (LDAP)",            1411,  re.compile(r"^\{SSHA256\}[A-Za-z0-9+/=]+$")),
    HashSignature("SSHA-512 (LDAP)",            1711,  re.compile(r"^\{SSHA512\}[A-Za-z0-9+/=]+$")),
    HashSignature("SHA-1 (LDAP base64)",        101,   re.compile(r"^\{SHA\}[A-Za-z0-9+/=]+$")),
    HashSignature("SHA-256 (LDAP base64)",      1401,  re.compile(r"^\{SHA256\}[A-Za-z0-9+/=]+$")),
    HashSignature("SHA-512 (LDAP base64)",      1701,  re.compile(r"^\{SHA512\}[A-Za-z0-9+/=]+$")),
    HashSignature("CRAM-MD5 (LDAP)",            16400, re.compile(r"^\$cram_md5\$")),

    # ═══════════════════════════════════════════════════════════
    #  EMAIL / MESSAGING
    # ═══════════════════════════════════════════════════════════
    HashSignature("Telegram Desktop (PBKDF2)",  22301, re.compile(r"^\$telegram\$1\$")),
    HashSignature("Telegram Mobile (SHA256)",   22302, re.compile(r"^\$telegram\$2\$")),
    HashSignature("Signal (Argon2id)",          28400, re.compile(r"^\$signal\$")),

    # ═══════════════════════════════════════════════════════════
    #  DISK / VOLUME ENCRYPTION
    # ═══════════════════════════════════════════════════════════
    HashSignature("LUKS (Linux)",               14600, re.compile(r"^\$luks\$")),
    HashSignature("VeraCrypt PBKDF2-SHA512+AES",13721, re.compile(r"^\$veracrypt\$")),
    HashSignature("FileVault 2 (Apple)",        16700, re.compile(r"^\$fvde\$")),
    HashSignature("BitLocker",                  22100, re.compile(r"^\$bitlocker\$")),
    HashSignature("TrueCrypt PBKDF2-SHA512+AES",6221,  re.compile(r"^\$truecrypt\$")),
    HashSignature("APFS (Apple File System)",   18300, re.compile(r"^\$apfs\$")),
    HashSignature("Android FDE ≤4.3",           12900, re.compile(r"^\$fde\$")),
    HashSignature("eCryptfs",                   12200, re.compile(r"^\$ecryptfs\$0\$")),

    # ═══════════════════════════════════════════════════════════
    #  SSH / PKI / JWT
    # ═══════════════════════════════════════════════════════════
    HashSignature("SSH RSA/DSA (private key)",  22911, re.compile(r"^\$sshng\$0\$")),
    HashSignature("SSH ECDSA (private key)",    22921, re.compile(r"^\$sshng\$6\$")),
    HashSignature("SSH Ed25519 (private key)",  22931, re.compile(r"^\$sshng\$4\$")),
    HashSignature("PKCS#12 (PFX, .p12)",        23001, re.compile(r"^\$pfxng\$")),
    HashSignature("JWT (JSON Web Token)",       16500, re.compile(r"^eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+$")),
    HashSignature("PEM (RSA/DSA/EC/OPENSSH)",   22941, re.compile(r"^\$PEM\$")),

    # ═══════════════════════════════════════════════════════════
    #  CLOUD / SaaS
    # ═══════════════════════════════════════════════════════════
    HashSignature("AWS4-HMAC-SHA256",           28100, re.compile(r"^\$aws4\$")),
    HashSignature("Apple iWork",                23300, re.compile(r"^\$iwork\$")),

    # ═══════════════════════════════════════════════════════════
    #  GAMING / APPS
    # ═══════════════════════════════════════════════════════════
    HashSignature("Minecraft (xAuth/AuthMe)",   20711, re.compile(r"^\$SHA\$[a-zA-Z0-9]+\$[a-fA-F0-9]{64}$")),
    HashSignature("Minecraft (BAuth/Spigot)",   20720, re.compile(r"^\$2y\$\d{2}\$.{53}$"), priority=-1),
    HashSignature("RuneScape",                  23,    re.compile(r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]+$"), priority=-5),
    HashSignature("WBB3 (Woltlab BB)",          8400,  re.compile(r"^[a-fA-F0-9]{40}:[a-fA-F0-9]{40}$")),

    # ═══════════════════════════════════════════════════════════
    #  HASH WITH PREFIX ($sha1$, $6$, etc. — extra formats)
    # ═══════════════════════════════════════════════════════════
    HashSignature("Atlassian (PBKDF2-HMAC-SHA1)", 12001, re.compile(r"^\{PKCS5S2\}[A-Za-z0-9+/=]+$")),
    HashSignature("SAP CODVN B (MD5)",          7700,  re.compile(r"^[A-Z0-9]{40}$")),
    HashSignature("SAP CODVN F/G (SHA1)",       7800,  re.compile(r"^[A-Z0-9]{40}:[A-Z0-9]{40}$")),
    HashSignature("Lotus Notes/Domino 5",       8600,  re.compile(r"^\([A-Za-z0-9+/]{20}\)$")),
    HashSignature("Lotus Notes/Domino 6",       8700,  re.compile(r"^\([A-Za-z0-9+/]{48}\)$")),
    HashSignature("PeopleSoft (SHA1)",          133,   re.compile(r"^[a-fA-F0-9]{40}$"), priority=-3),

    # ═══════════════════════════════════════════════════════════
    #  RADIUS / VPN / AUTHENTICATION
    # ═══════════════════════════════════════════════════════════
    HashSignature("IKE-PSK MD5",                5300,  re.compile(r"^[a-fA-F0-9]+:[a-fA-F0-9]+:[a-fA-F0-9]+:[a-fA-F0-9]+:[a-fA-F0-9]+$")),
    HashSignature("IKE-PSK SHA1",               5400,  re.compile(r"^[a-fA-F0-9]+:[a-fA-F0-9]+:[a-fA-F0-9]+:[a-fA-F0-9]+:[a-fA-F0-9]+$"), priority=-1),
    HashSignature("IPMI2 RAKP HMAC-SHA1",       7300,  re.compile(r"^[a-fA-F0-9]{40}:[a-fA-F0-9]+$"), priority=-3),
    HashSignature("iSCSI CHAP (MD5)",           4800,  re.compile(r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{2}:[a-fA-F0-9]{32}$")),

    # ═══════════════════════════════════════════════════════════
    #  MISC / SPECIAL
    # ═══════════════════════════════════════════════════════════
    HashSignature("CRC32",                      11500, re.compile(r"^[a-fA-F0-9]{8}:[\d]+:$")),
    HashSignature("SIP digest (MD5)",           11400, re.compile(r"^\$sip\$\*")),
    HashSignature("TOTP (HMAC-based OTP)",      18100, re.compile(r"^[a-fA-F0-9]{40}:[0-9]+$"), priority=-4),
    HashSignature("Web2py (PBKDF2-SHA512)",     29200, re.compile(r"^pbkdf2\(1000,20,sha512\)\$")),
    HashSignature("ArubaOS",                    125,   re.compile(r"^[a-fA-F0-9]{40}:[a-fA-F0-9]{20}$"), priority=-1),
    HashSignature("hMailServer",                111,   re.compile(r"^[a-fA-F0-9]{6}[a-fA-F0-9]{40}$")),
    HashSignature("MediaWiki B type",           3711,  re.compile(r"^\$B\$[a-fA-F0-9]{8}\$[a-fA-F0-9]{32}$")),
    HashSignature("DNSSEC (NSEC3)",             8300,  re.compile(r"^[a-fA-F0-9]{40}:[A-Za-z0-9.]+:\d+$")),
    HashSignature("QNX /etc/shadow (MD5)",      19000, re.compile(r"^@m[A-Za-z0-9./]{22}\$[A-Za-z0-9./]+$")),
    HashSignature("QNX /etc/shadow (SHA256)",   19100, re.compile(r"^@s[A-Za-z0-9./]{22}\$[A-Za-z0-9./]+$")),
    HashSignature("QNX /etc/shadow (SHA512)",   19200, re.compile(r"^@S[A-Za-z0-9./]{22}\$[A-Za-z0-9./]+$")),
]
# fmt: on


def detect_hash(hash_value: str) -> list[HashSignature]:
    """Return matching signatures sorted by priority (highest first)."""
    hash_value = hash_value.strip()
    matches = [sig for sig in _SIGNATURES if sig.pattern.search(hash_value)]
    matches.sort(key=lambda s: s.priority, reverse=True)
    return matches


def get_all_signatures() -> list[HashSignature]:
    """Return every known signature (for reference display)."""
    return list(_SIGNATURES)
