"""Primitivas do PKCS #1 v2.2 (RFC 8017) compartilhadas por OAEP e PSS."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from librsa import PrivateKey, PublicKey

HASH_LEN = 32  # SHA3-256


def sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def i2osp(x: int, x_len: int) -> bytes:
    """Integer-to-Octet-String (RFC 8017, seção 4.1)."""
    if x < 0 or x >= 256**x_len:
        raise ValueError("inteiro grande demais")
    return x.to_bytes(x_len, "big")


def os2ip(x: bytes) -> int:
    """Octet-String-to-Integer (RFC 8017, seção 4.2)."""
    return int.from_bytes(x, "big")


def mgf1(seed: bytes, mask_len: int) -> bytes:
    """MGF1 com SHA3-256 (RFC 8017, apêndice B.2.1)."""
    if mask_len > (2**32) * HASH_LEN:
        raise ValueError("máscara longa demais")
    t = bytearray()
    counter = 0
    while len(t) < mask_len:
        t += sha3_256(seed + i2osp(counter, 4))
        counter += 1
    return bytes(t[:mask_len])


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


def key_byte_len(n: int) -> int:
    return (n.bit_length() + 7) // 8


def rsaep(pub: PublicKey, m: int) -> int:
    """Primitiva de cifragem RSA (RFC 8017, seção 5.1.1)."""
    if not 0 <= m < pub.N:
        raise ValueError("representante da mensagem fora do intervalo")
    return pow(m, pub.e, pub.N)


def rsadp(priv: PrivateKey, c: int) -> int:
    """Primitiva de decifragem RSA usando CRT (RFC 8017, seção 5.1.2)."""
    if not 0 <= c < priv.N:
        raise ValueError("representante do ciphertext fora do intervalo")
    m1 = pow(c, priv.crt_dP, priv.p)
    m2 = pow(c, priv.crt_dQ, priv.q)
    h = (priv.crt_qInv * (m1 - m2)) % priv.p
    return m2 + priv.q * h
