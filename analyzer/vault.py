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
import json
import hmac
import hashlib
import secrets as _secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


# ════════════════════════════════════════════════════════════════════════════
#  AES-256 — núcleo em Python puro (FIPS-197)
# ════════════════════════════════════════════════════════════════════════════

_SBOX = (
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
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
    def _expand_key(self, key: bytes) -> List[List[int]]:
        nk, nr = self.nk, self.nr
        words: List[List[int]] = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
        for i in range(nk, 4 * (nr + 1)):
            temp = list(words[i - 1])
            if i % nk == 0:
                temp = temp[1:] + temp[:1]                      # RotWord
                temp = [_SBOX[b] for b in temp]                 # SubWord
                temp[0] ^= _RCON[i // nk - 1]
            elif nk > 6 and i % nk == 4:
                temp = [_SBOX[b] for b in temp]                 # SubWord
            words.append([words[i - nk][j] ^ temp[j] for j in range(4)])
        # Agrupa em blocos de 16 bytes por round (coluna-major)
        round_keys: List[List[int]] = []
        for r in range(nr + 1):
            rk: List[int] = []
            for c in range(4):
                rk.extend(words[4 * r + c])
            round_keys.append(rk)
        return round_keys

    # ── Operações de estado (estado = 16 bytes, índice = linha + 4*coluna) ─────
    @staticmethod
    def _add_round_key(state: List[int], rk: List[int]) -> None:
        for i in range(16):
            state[i] ^= rk[i]

    @staticmethod
    def _sub_bytes(state: List[int], box) -> None:
        for i in range(16):
            state[i] = box[state[i]]

    @staticmethod
    def _shift_rows(state: List[int]) -> None:
        new = state[:]
        for r in range(1, 4):
            for c in range(4):
                new[r + 4 * c] = state[r + 4 * ((c + r) % 4)]
        state[:] = new

    @staticmethod
    def _inv_shift_rows(state: List[int]) -> None:
        new = state[:]
        for r in range(1, 4):
            for c in range(4):
                new[r + 4 * c] = state[r + 4 * ((c - r) % 4)]
        state[:] = new

    @staticmethod
    def _mix_columns(state: List[int]) -> None:
        for c in range(4):
            i = 4 * c
            a0, a1, a2, a3 = state[i], state[i + 1], state[i + 2], state[i + 3]
            state[i]     = _xtime(a0) ^ (_xtime(a1) ^ a1) ^ a2 ^ a3
            state[i + 1] = a0 ^ _xtime(a1) ^ (_xtime(a2) ^ a2) ^ a3
            state[i + 2] = a0 ^ a1 ^ _xtime(a2) ^ (_xtime(a3) ^ a3)
            state[i + 3] = (_xtime(a0) ^ a0) ^ a1 ^ a2 ^ _xtime(a3)

    @staticmethod
    def _inv_mix_columns(state: List[int]) -> None:
        for c in range(4):
            i = 4 * c
            a0, a1, a2, a3 = state[i], state[i + 1], state[i + 2], state[i + 3]
            state[i]     = _gmul(a0, 14) ^ _gmul(a1, 11) ^ _gmul(a2, 13) ^ _gmul(a3, 9)
            state[i + 1] = _gmul(a0, 9)  ^ _gmul(a1, 14) ^ _gmul(a2, 11) ^ _gmul(a3, 13)
            state[i + 2] = _gmul(a0, 13) ^ _gmul(a1, 9)  ^ _gmul(a2, 14) ^ _gmul(a3, 11)
            state[i + 3] = _gmul(a0, 11) ^ _gmul(a1, 13) ^ _gmul(a2, 9)  ^ _gmul(a3, 14)

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
        block = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
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
        block = ciphertext[i:i + 16]
        dec = aes.decrypt_block(block)
        out.extend(a ^ b for a, b in zip(dec, prev))
        prev = block
    return _pkcs7_unpad(bytes(out))


# ════════════════════════════════════════════════════════════════════════════
#  SecretVault
# ════════════════════════════════════════════════════════════════════════════

_CHECK_CONST   = b"vulnvault-check-v1"
_DEFAULT_ITERS = 200_000


class VaultError(Exception):
    pass


@dataclass
class _Keys:
    enc: bytes   # 32 bytes para AES-256
    mac: bytes   # 32 bytes para HMAC-SHA256


def _derive_keys(password: str, salt: bytes, iterations: int) -> _Keys:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=64)
    return _Keys(enc=dk[:32], mac=dk[32:])


class SecretVault:
    """Gerenciador de segredos criptografado em arquivo único."""

    def __init__(self, path: str, keys: _Keys, salt: bytes,
                 iterations: int, secrets: Dict[str, dict]):
        self.path       = Path(path)
        self._keys      = keys
        self._salt      = salt
        self._iterations = iterations
        self._secrets   = secrets   # nome -> {iv, ct, mac} (hex)

    # ── Criação / abertura ─────────────────────────────────────────────────────
    @classmethod
    def create(cls, path: str, password: str, iterations: int = _DEFAULT_ITERS) -> "SecretVault":
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
    def open(cls, path: str, password: str) -> "SecretVault":
        p = Path(path)
        if not p.exists():
            raise VaultError(f"Cofre não encontrado: {path}")
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:
            raise VaultError(f"Arquivo de cofre inválido: {e}")

        salt       = bytes.fromhex(data["salt"])
        iterations = int(data.get("iterations", _DEFAULT_ITERS))
        keys       = _derive_keys(password, salt, iterations)

        # Verifica senha via HMAC de constante conhecida (comparação constante)
        expected = hmac.new(keys.mac, _CHECK_CONST, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, data.get("check", "")):
            raise VaultError("Senha mestre incorreta ou cofre corrompido")

        return cls(path, keys, salt, iterations, data.get("secrets", {}))

    # ── Operações ──────────────────────────────────────────────────────────────
    def set_secret(self, name: str, value: str) -> None:
        if not name:
            raise VaultError("Nome do segredo não pode ser vazio")
        iv  = _secrets.token_bytes(16)
        ct  = aes_cbc_encrypt(self._keys.enc, iv, value.encode("utf-8"))
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

    def list_secrets(self) -> List[str]:
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
            "version":    1,
            "kdf":        "pbkdf2_sha256",
            "iterations": self._iterations,
            "salt":       self._salt.hex(),
            "check":      check,
            "secrets":    self._secrets,
        }
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        tmp.replace(self.path)   # escrita atômica
