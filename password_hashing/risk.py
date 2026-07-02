"""
password_hashing/risk.py
---------------------------
Classification table for password hashing schemes, across every surface
Cryptiq scans: Linux /etc/shadow (crypt(3) IDs), Windows (NTLM/LM),
network device configs (Cisco IOS / Juniper secret types), and common
application-level schemes (for when a customer pastes a DB column sample).

Same weighted-risk philosophy as ssh_scanner/ssh_risk.py: every entry
gets a risk tier and a concrete recommendation, not just a pass/fail.
"""

from __future__ import annotations

from password_hashing.types import HashAlgorithmInfo, HashRisk

# crypt(3) format-id prefix -> info (Linux/BSD /etc/shadow, also some macOS legacy)
CRYPT_PREFIXES: dict[str, HashAlgorithmInfo] = {
    "": HashAlgorithmInfo(  # classic DES crypt, 13-char hash, no $ prefix at all
        "des-crypt", HashRisk.CRITICAL,
        "Original Unix DES crypt — 56-bit effective strength, 8-char password limit, no real salt space.",
        "Force a password reset under SHA-512/yescrypt; DES crypt is crackable in seconds offline.",
    ),
    "$1$": HashAlgorithmInfo(
        "md5crypt", HashRisk.HIGH,
        "MD5-based crypt — fast hash, GPU-crackable at billions of guesses/sec.",
        "Migrate to yescrypt ($y$) or SHA-512 ($6$) via PAM/login.defs; reset affected accounts.",
    ),
    "$2a$": HashAlgorithmInfo("bcrypt", HashRisk.LOW,
        "bcrypt, older variant tag — adaptive, salted.", "Acceptable; prefer $2b$ for new hashes."),
    "$2b$": HashAlgorithmInfo("bcrypt", HashRisk.LOW,
        "bcrypt — adaptive cost factor, salted.", "Acceptable. Verify cost factor >= 12."),
    "$2y$": HashAlgorithmInfo("bcrypt", HashRisk.LOW,
        "bcrypt (PHP variant tag) — adaptive, salted.", "Acceptable. Verify cost factor >= 12."),
    "$5$": HashAlgorithmInfo(
        "sha256crypt", HashRisk.MEDIUM,
        "SHA-256 crypt — salted but not memory-hard; GPU rigs do meaningful damage at scale.",
        "Migrate to yescrypt ($y$) where supported (glibc 2.35+/most modern distros).",
    ),
    "$6$": HashAlgorithmInfo(
        "sha512crypt", HashRisk.MEDIUM,
        "SHA-512 crypt — current Linux default on many distros; salted, configurable rounds, but not memory-hard.",
        "Acceptable baseline. Prefer yescrypt if your distro's libxcrypt supports it (set ENCRYPT_METHOD in /etc/login.defs).",
    ),
    "$y$": HashAlgorithmInfo(
        "yescrypt", HashRisk.BEST,
        "yescrypt — memory-hard KDF, default on Fedora/Debian 11+/Ubuntu 22.04+.",
        "Already strong. No action needed.",
    ),
    "$7$": HashAlgorithmInfo(
        "scrypt", HashRisk.BEST,
        "scrypt — memory-hard KDF.", "Already strong. No action needed.",
    ),
    "$argon2id$": HashAlgorithmInfo(
        "argon2id", HashRisk.BEST,
        "Argon2id — winner of the Password Hashing Competition, memory-hard + side-channel resistant.",
        "Already strong (this is the current best-practice recommendation for new application code).",
    ),
    "$argon2i$": HashAlgorithmInfo(
        "argon2i", HashRisk.BEST,
        "Argon2i — memory-hard, optimized against side-channel attacks.",
        "Strong. Argon2id is marginally preferred for most threat models but this is fine.",
    ),
}

# Windows
WINDOWS_HASH_INFO: dict[str, HashAlgorithmInfo] = {
    "lm": HashAlgorithmInfo(
        "LM hash", HashRisk.CRITICAL,
        "LAN Manager hash — splits password into two 7-char halves, no salt, case-insensitive. "
        "Crackable essentially instantly with rainbow tables.",
        "Disable LM hash storage entirely (NoLMHash policy / GPO); it should not exist on any "
        "system after Windows XP/2003.",
    ),
    "ntlm": HashAlgorithmInfo(
        "NTLM hash", HashRisk.HIGH,
        "Unsalted MD4 of the UTF-16 password. Fast to compute -> fast to brute-force/crack offline "
        "once the SAM/NTDS.dit is exfiltrated, and vulnerable to pass-the-hash.",
        "Move authentication to Kerberos where possible; enforce long passphrases + MFA; "
        "restrict NTLM via GPO (Network security: Restrict NTLM); rotate krbtgt periodically.",
    ),
}

# Cisco IOS "secret"/"password" types
CISCO_TYPE_INFO: dict[str, HashAlgorithmInfo] = {
    "0": HashAlgorithmInfo(
        "cisco-type-0", HashRisk.CRITICAL,
        "Type 0 — stored in PLAINTEXT in the running-config.",
        "Replace with `secret <type9|type8>` (scrypt/PBKDF2). Anyone with config read access has the password today.",
    ),
    "7": HashAlgorithmInfo(
        "cisco-type-7", HashRisk.CRITICAL,
        "Type 7 — reversible Vigenere-style obfuscation, not real encryption. Decoded by public "
        "tools/scripts in milliseconds.",
        "Replace `password 7 ...` lines with `secret 9 ...` (or 8); type 7 should never protect anything sensitive.",
    ),
    "5": HashAlgorithmInfo(
        "cisco-type-5", HashRisk.MEDIUM,
        "Type 5 — salted MD5 crypt. Better than 0/7 but MD5-based and fast to brute-force on modern GPUs.",
        "Migrate to `secret 9` (scrypt, IOS 15.3(3)M+/IOS-XE) or `secret 8` (PBKDF2-SHA256).",
    ),
    "8": HashAlgorithmInfo(
        "cisco-type-8", HashRisk.LOW,
        "Type 8 — PBKDF2-SHA256, 20000 iterations. Solid, adaptive.",
        "Acceptable.",
    ),
    "9": HashAlgorithmInfo(
        "cisco-type-9", HashRisk.BEST,
        "Type 9 — scrypt. Memory-hard, current Cisco best practice.",
        "Already strong. No action needed.",
    ),
}

GENERIC_PATTERNS: dict[str, HashAlgorithmInfo] = {
    "md5_hex32": HashAlgorithmInfo(
        "raw-md5", HashRisk.HIGH,
        "Bare 32-hex-char MD5 digest, no visible salt — classic legacy web-app password column.",
        "Migrate the application to bcrypt/scrypt/Argon2id; force resets to re-hash under the new scheme.",
    ),
    "sha1_hex40": HashAlgorithmInfo(
        "raw-sha1", HashRisk.HIGH,
        "Bare 40-hex-char SHA-1 digest, no visible salt.",
        "Migrate the application to bcrypt/scrypt/Argon2id; force resets.",
    ),
}


def classify_crypt_prefix(hash_value: str) -> HashAlgorithmInfo:
    for prefix in ("$argon2id$", "$argon2i$", "$y$", "$7$", "$6$", "$5$", "$2b$", "$2y$", "$2a$", "$1$"):
        if hash_value.startswith(prefix):
            return CRYPT_PREFIXES[prefix]
    # 13-char classic DES crypt has no $ marker at all
    if len(hash_value) == 13 and "$" not in hash_value:
        return CRYPT_PREFIXES[""]
    return HashAlgorithmInfo("unknown", HashRisk.MEDIUM,
                              "Could not positively identify the hashing scheme.",
                              "Manually confirm the scheme in use; treat as unverified until known.")