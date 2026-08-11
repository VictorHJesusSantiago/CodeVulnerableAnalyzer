"""
Round-trip das cifras em tamanhos que cruzam a fronteira de bloco.

Guarda os parâmetros `strict=` recém-adicionados aos `zip()`:
  - AES-CBC (bloco de 16, dados sempre alinhados por pkcs7) → strict=True
  - ChaCha20 (stream, último bloco parcial quando len % 64 != 0) → strict=False

Um `strict=True` errado no ChaCha20 quebraria qualquer payload não múltiplo de 64.
"""

from __future__ import annotations

import pytest

from analyzer.vault import aes_cbc_decrypt, aes_cbc_encrypt
from analyzer.vault_advanced import (
    chacha20poly1305_decrypt,
    chacha20poly1305_encrypt,
)

# Tamanhos que exercitam bloco vazio, parcial, exato e múltiplos+resto
_LENGTHS = [0, 1, 15, 16, 17, 31, 63, 64, 65, 100, 128, 130, 255]


@pytest.mark.parametrize("n", _LENGTHS)
def test_aes_cbc_roundtrip(n):
    key = bytes(range(16))
    iv = bytes(range(16, 32))
    msg = bytes((i * 7) % 256 for i in range(n))
    assert aes_cbc_decrypt(key, iv, aes_cbc_encrypt(key, iv, msg)) == msg


@pytest.mark.parametrize("n", _LENGTHS)
def test_chacha20poly1305_roundtrip_partial_blocks(n):
    key = bytes(range(32))
    nonce = bytes(range(12))
    msg = bytes((i * 13) % 256 for i in range(n))
    cipher, tag = chacha20poly1305_encrypt(key, nonce, msg, b"aad")
    # O ciphertext do stream cipher tem exatamente o tamanho do plaintext
    assert len(cipher) == n
    assert chacha20poly1305_decrypt(key, nonce, cipher, tag, b"aad") == msg


def test_chacha20poly1305_tampered_tag_rejected():
    key = bytes(range(32))
    nonce = bytes(range(12))
    cipher, tag = chacha20poly1305_encrypt(key, nonce, b"mensagem secreta", b"aad")
    bad_tag = bytes([tag[0] ^ 0x01]) + tag[1:]
    with pytest.raises(Exception):
        chacha20poly1305_decrypt(key, nonce, cipher, bad_tag, b"aad")
