"""
Cofre de segredos local — criptografia AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC)
e derivação de chave via PBKDF2-HMAC-SHA256.

Restrição de supply chain: ZERO dependências externas. A stdlib do Python não
fornece AES, então o bloco AES-256 é implementado em Python puro aqui (verificado
contra o vetor de teste oficial FIPS-197). HMAC, PBKDF2 e os bytes aleatórios vêm
de `hmac`, `hashlib` e `secrets` (todos stdlib).

Formato do arquivo de cofre (JSON):
{
  "version": 1,
  "kdf": "pbkdf2_sha256",
  "iterations": 200000,
  "salt": "<hex>",
  "check": "<hex>",         # HMAC(mac_key, CHECK_CONST) — detecta senha errada
  "secrets": { "<nome>": {"iv": "<hex>", "ct": "<hex>", "mac": "<hex>"} },
}
Cada segredo usa IV aleatório de 16 bytes; o ciphertext é autenticado com
HMAC-SHA256 sobre (iv || ct) usando mac_key (encrypt-then-MAC).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets as _secrets
from dataclasses import dataclass
from pathlib import Path

# ════════════════════════════════════════════════════════════════════════════
#  AES-256 — núcleo em Python puro (FIPS-197)
# ════════════════════════════════════════════════════════════════════════════

_SBOX = (
    0x63,
    0x7C,
    0x77,
    0x7B,
    0xF2,
    0x6B,
    0x6F,
    0xC5,
    0x30,
    0x01,
    0x67,
    0x2B,
    0xFE,
    0xD7,
    0xAB,
    0x76,
    0xCA,
    0x82,
    0xC9,
    0x7D,
    0xFA,
    0x59,
    0x47,
    0xF0,
    0xAD,
    0xD4,
    0xA2,
    0xAF,
    0x9C,
    0xA4,
    0x72,
    0xC0,
    0xB7,
    0xFD,
    0x93,
    0x26,
    0x36,
    0x3F,
    0xF7,
    0xCC,
    0x34,
    0xA5,
    0xE5,
    0xF1,
    0x71,
    0xD8,
    0x31,
    0x15,
    0x04,
    0xC7,
    0x23,
    0xC3,
    0x18,
    0x96,
    0x05,
    0x9A,
    0x07,
    0x12,
    0x80,
    0xE2,
    0xEB,
    0x27,
    0xB2,
    0x75,
    0x09,
    0x83,
    0x2C,
    0x1A,
    0x1B,
    0x6E,
    0x5A,
    0xA0,
    0x52,
    0x3B,
    0xD6,
    0xB3,
    0x29,
    0xE3,
    0x2F,
    0x84,
    0x53,
    0xD1,
    0x00,
    0xED,
    0x20,
    0xFC,
    0xB1,
    0x5B,
    0x6A,
    0xCB,
    0xBE,
    0x39,
    0x4A,
    0x4C,
    0x58,
    0xCF,
    0xD0,
    0xEF,
    0xAA,
    0xFB,
    0x43,
    0x4D,
    0x33,
    0x85,
    0x45,
    0xF9,
    0x02,
    0x7F,
    0x50,
    0x3C,
    0x9F,
    0xA8,
    0x51,
    0xA3,
    0x40,
    0x8F,
    0x92,
    0x9D,
    0x38,
    0xF5,
    0xBC,
    0xB6,
    0xDA,
    0x21,
    0x10,
    0xFF,
    0xF3,
    0xD2,
    0xCD,
    0x0C,
    0x13,
    0xEC,
    0x5F,
    0x97,
    0x44,
    0x17,
    0xC4,
    0xA7,
    0x7E,
    0x3D,
    0x64,
    0x5D,
    0x19,
    0x73,
    0x60,
    0x81,
    0x4F,
    0xDC,
    0x22,
    0x2A,
    0x90,
    0x88,
    0x46,
    0xEE,
    0xB8,
    0x14,
    0xDE,
    0x5E,
    0x0B,
    0xDB,
    0xE0,
    0x32,
    0x3A,
    0x0A,
    0x49,
    0x06,
    0x24,
    0x5C,
    0xC2,
    0xD3,
    0xAC,
    0x62,
    0x91,
    0x95,
    0xE4,
    0x79,
    0xE7,
    0xC8,
    0x37,
    0x6D,
    0x8D,
    0xD5,
    0x4E,
    0xA9,
    0x6C,
    0x56,
    0xF4,
    0xEA,
    0x65,
    0x7A,
    0xAE,
    0x08,
    0xBA,
    0x78,
    0x25,
    0x2E,
    0x1C,
    0xA6,
    0xB4,
    0xC6,
    0xE8,
    0xDD,
    0x74,
    0x1F,
    0x4B,
    0xBD,
    0x8B,
    0x8A,
    0x70,
    0x3E,
    0xB5,
    0x66,
    0x48,
    0x03,
    0xF6,
    0x0E,
    0x61,
    0x35,
    0x57,
    0xB9,
    0x86,
    0xC1,
    0x1D,
    0x9E,
    0xE1,
    0xF8,
    0x98,
    0x11,
    0x69,
    0xD9,
    0x8E,
    0x94,
    0x9B,
    0x1E,
    0x87,
    0xE9,
    0xCE,
    0x55,
    0x28,
    0xDF,
    0x8C,
    0xA1,
    0x89,
    0x0D,
    0xBF,
    0xE6,
    0x42,
    0x68,
    0x41,
    0x99,
    0x2D,
    0x0F,
    0xB0,
    0x54,
    0xBB,
    0x16,
)
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i

_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8)


def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _gmul(a: int, b: int) -> int:
    """Multiplicação no campo de Galois GF(2^8)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        b >>= 1
        a = _xtime(a)
    return p & 0xFF


class AES:
    """AES com bloco de 128 bits. Suporta chaves de 128/192/256 bits."""

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("Chave AES deve ter 16, 24 ou 32 bytes")
        self.nk = len(key) // 4
        self.nr = {4: 10, 6: 12, 8: 14}[self.nk]
        self._round_keys = self._expand_key(key)

    # ── Expansão de chave ─────────────────────────────────────────────────────
    def _expand_key(self, key: bytes) -> list[list[int]]:
        nk, nr = self.nk, self.nr
        words: list[list[int]] = [list(key[4 * i : 4 * i + 4]) for i in range(nk)]
        for i in range(nk, 4 * (nr + 1)):
            temp = list(words[i - 1])
            if i % nk == 0:
                temp = temp[1:] + temp[:1]  # RotWord
                temp = [_SBOX[b] for b in temp]  # SubWord
                temp[0] ^= _RCON[i // nk - 1]
            elif nk > 6 and i % nk == 4:
                temp = [_SBOX[b] for b in temp]  # SubWord
            words.append([words[i - nk][j] ^ temp[j] for j in range(4)])
        # Agrupa em blocos de 16 bytes por round (coluna-major)
        round_keys: list[list[int]] = []
        for r in range(nr + 1):
            rk: list[int] = []
            for c in range(4):
                rk.extend(words[4 * r + c])
            round_keys.append(rk)
        return round_keys

    # ── Operações de estado (estado = 16 bytes, índice = linha + 4*coluna) ─────
    @staticmethod
    def _add_round_key(state: list[int], rk: list[int]) -> None:
        for i in range(16):
            state[i] ^= rk[i]

    @staticmethod
    def _sub_bytes(state: list[int], box) -> None:
        for i in range(16):
            state[i] = box[state[i]]

    @staticmethod
    def _shift_rows(state: list[int]) -> None:
        new = state[:]
        for r in range(1, 4):
            for c in range(4):
                new[r + 4 * c] = state[r + 4 * ((c + r) % 4)]
        state[:] = new

    @staticmethod
    def _inv_shift_rows(state: list[int]) -> None:
        new = state[:]
        for r in range(1, 4):
            for c in range(4):
                new[r + 4 * c] = state[r + 4 * ((c - r) % 4)]
        state[:] = new

    @staticmethod
    def _mix_columns(state: list[int]) -> None:
        for c in range(4):
            i = 4 * c
            a0, a1, a2, a3 = state[i], state[i + 1], state[i + 2], state[i + 3]
            state[i] = _xtime(a0) ^ (_xtime(a1) ^ a1) ^ a2 ^ a3
            state[i + 1] = a0 ^ _xtime(a1) ^ (_xtime(a2) ^ a2) ^ a3
            state[i + 2] = a0 ^ a1 ^ _xtime(a2) ^ (_xtime(a3) ^ a3)
            state[i + 3] = (_xtime(a0) ^ a0) ^ a1 ^ a2 ^ _xtime(a3)

    @staticmethod
    def _inv_mix_columns(state: list[int]) -> None:
        for c in range(4):
            i = 4 * c
            a0, a1, a2, a3 = state[i], state[i + 1], state[i + 2], state[i + 3]
            state[i] = _gmul(a0, 14) ^ _gmul(a1, 11) ^ _gmul(a2, 13) ^ _gmul(a3, 9)
            state[i + 1] = _gmul(a0, 9) ^ _gmul(a1, 14) ^ _gmul(a2, 11) ^ _gmul(a3, 13)
            state[i + 2] = _gmul(a0, 13) ^ _gmul(a1, 9) ^ _gmul(a2, 14) ^ _gmul(a3, 11)
            state[i + 3] = _gmul(a0, 11) ^ _gmul(a1, 13) ^ _gmul(a2, 9) ^ _gmul(a3, 14)

    # ── Bloco ──────────────────────────────────────────────────────────────────
    def encrypt_block(self, block: bytes) -> bytes:
        state = list(block)
        self._add_round_key(state, self._round_keys[0])
        for r in range(1, self.nr):
            self._sub_bytes(state, _SBOX)
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, self._round_keys[r])
        self._sub_bytes(state, _SBOX)
        self._shift_rows(state)
        self._add_round_key(state, self._round_keys[self.nr])
        return bytes(state)

    def decrypt_block(self, block: bytes) -> bytes:
        state = list(block)
        self._add_round_key(state, self._round_keys[self.nr])
        for r in range(self.nr - 1, 0, -1):
            self._inv_shift_rows(state)
            self._sub_bytes(state, _INV_SBOX)
            self._add_round_key(state, self._round_keys[r])
            self._inv_mix_columns(state)
        self._inv_shift_rows(state)
        self._sub_bytes(state, _INV_SBOX)
        self._add_round_key(state, self._round_keys[0])
        return bytes(state)


# ── PKCS#7 + CBC ────────────────────────────────────────────────────────────


def _pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    n = block - (len(data) % block)
    return data + bytes([n]) * n


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % 16 != 0:
        raise ValueError("Padding inválido")
    n = data[-1]
    if n < 1 or n > 16 or data[-n:] != bytes([n]) * n:
        raise ValueError("Padding inválido")
    return data[:-n]


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES(key)
    data = _pkcs7_pad(plaintext)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[i : i + 16], prev, strict=True))
        enc = aes.encrypt_block(block)
        out.extend(enc)
        prev = enc
    return bytes(out)


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext não é múltiplo de 16")
    aes = AES(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i : i + 16]
        dec = aes.decrypt_block(block)
        out.extend(a ^ b for a, b in zip(dec, prev, strict=True))
        prev = block
    return _pkcs7_unpad(bytes(out))


# ════════════════════════════════════════════════════════════════════════════
#  SecretVault
# ════════════════════════════════════════════════════════════════════════════

_CHECK_CONST = b"vulnvault-check-v1"
_DEFAULT_ITERS = 200_000


class VaultError(Exception):
    pass


@dataclass
class _Keys:
    enc: bytes  # 32 bytes para AES-256
    mac: bytes  # 32 bytes para HMAC-SHA256


def _derive_keys(password: str, salt: bytes, iterations: int) -> _Keys:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=64)
    return _Keys(enc=dk[:32], mac=dk[32:])


class SecretVault:
    """Gerenciador de segredos criptografado em arquivo único."""

    def __init__(self, path: str, keys: _Keys, salt: bytes, iterations: int, secrets: dict[str, dict]):
        self.path = Path(path)
        self._keys = keys
        self._salt = salt
        self._iterations = iterations
        self._secrets = secrets  # nome -> {iv, ct, mac} (hex)

    # ── Criação / abertura ─────────────────────────────────────────────────────
    @classmethod
    def create(cls, path: str, password: str, iterations: int = _DEFAULT_ITERS) -> SecretVault:
        p = Path(path)
        if p.exists():
            raise VaultError(f"Cofre já existe: {path}")
        if not password:
            raise VaultError("Senha mestre não pode ser vazia")
        salt = _secrets.token_bytes(16)
        keys = _derive_keys(password, salt, iterations)
        vault = cls(path, keys, salt, iterations, {})
        vault.save()
        return vault

    @classmethod
    def open(cls, path: str, password: str) -> SecretVault:
        p = Path(path)
        if not p.exists():
            raise VaultError(f"Cofre não encontrado: {path}")
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:
            raise VaultError(f"Arquivo de cofre inválido: {e}") from e

        salt = bytes.fromhex(data["salt"])
        iterations = int(data.get("iterations", _DEFAULT_ITERS))
        keys = _derive_keys(password, salt, iterations)

        # Verifica senha via HMAC de constante conhecida (comparação constante)
        expected = hmac.new(keys.mac, _CHECK_CONST, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, data.get("check", "")):
            raise VaultError("Senha mestre incorreta ou cofre corrompido")

        return cls(path, keys, salt, iterations, data.get("secrets", {}))

    # ── Operações ──────────────────────────────────────────────────────────────
    def set_secret(self, name: str, value: str) -> None:
        if not name:
            raise VaultError("Nome do segredo não pode ser vazio")
        iv = _secrets.token_bytes(16)
        ct = aes_cbc_encrypt(self._keys.enc, iv, value.encode("utf-8"))
        mac = hmac.new(self._keys.mac, iv + ct, hashlib.sha256).hexdigest()
        self._secrets[name] = {"iv": iv.hex(), "ct": ct.hex(), "mac": mac}

    def get_secret(self, name: str) -> str:
        entry = self._secrets.get(name)
        if entry is None:
            raise VaultError(f"Segredo não encontrado: {name}")
        iv = bytes.fromhex(entry["iv"])
        ct = bytes.fromhex(entry["ct"])
        # Verifica integridade (encrypt-then-MAC) antes de decifrar
        expected = hmac.new(self._keys.mac, iv + ct, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, entry.get("mac", "")):
            raise VaultError(f"Segredo '{name}' falhou na verificação de integridade (adulterado?)")
        return aes_cbc_decrypt(self._keys.enc, iv, ct).decode("utf-8")

    def delete_secret(self, name: str) -> None:
        if name not in self._secrets:
            raise VaultError(f"Segredo não encontrado: {name}")
        del self._secrets[name]

    def list_secrets(self) -> list[str]:
        return sorted(self._secrets.keys())

    def change_password(self, new_password: str) -> None:
        """Re-criptografa todos os segredos sob uma nova senha mestre."""
        if not new_password:
            raise VaultError("Nova senha não pode ser vazia")
        plain = {name: self.get_secret(name) for name in self._secrets}
        self._salt = _secrets.token_bytes(16)
        self._keys = _derive_keys(new_password, self._salt, self._iterations)
        self._secrets = {}
        for name, value in plain.items():
            self.set_secret(name, value)

    # ── Persistência ───────────────────────────────────────────────────────────
    def save(self) -> None:
        check = hmac.new(self._keys.mac, _CHECK_CONST, hashlib.sha256).hexdigest()
        doc = {
            "version": 1,
            "kdf": "pbkdf2_sha256",
            "iterations": self._iterations,
            "salt": self._salt.hex(),
            "check": check,
            "secrets": self._secrets,
        }
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        tmp.replace(self.path)  # escrita atômica
