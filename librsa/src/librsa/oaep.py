"""RSA-OAEP com SHA3-256 e MGF1 (RFC 8017, seção 7.1)."""

from __future__ import annotations

import hmac
import secrets
from typing import TYPE_CHECKING

from librsa.primitives import (
    HASH_LEN,
    i2osp,
    key_byte_len,
    mgf1,
    os2ip,
    rsadp,
    rsaep,
    sha3_256,
    xor_bytes,
)

if TYPE_CHECKING:
    from librsa import PrivateKey, PublicKey


class DecryptionError(Exception):
    """Falha de decifragem OAEP.

    A mensagem é sempre a mesma, independente da causa (tamanho, padding,
    label ou ciphertext adulterado), para não servir de oráculo a ataques
    como o de Manger.
    """

    def __init__(self) -> None:
        super().__init__("erro de decifragem")


def max_message_len(pub: PublicKey) -> int:
    return key_byte_len(pub.N) - 2 * HASH_LEN - 2


def oaep_encode(message: bytes, k: int, label: bytes = b"") -> bytes:
    """EME-OAEP encoding: EM = 0x00 || maskedSeed || maskedDB."""
    if len(message) > k - 2 * HASH_LEN - 2:
        raise ValueError("mensagem longa demais para a chave")

    l_hash = sha3_256(label)
    ps = b"\x00" * (k - len(message) - 2 * HASH_LEN - 2)
    db = l_hash + ps + b"\x01" + message

    seed = secrets.token_bytes(HASH_LEN)
    masked_db = xor_bytes(db, mgf1(seed, k - HASH_LEN - 1))
    masked_seed = xor_bytes(seed, mgf1(masked_db, HASH_LEN))
    return b"\x00" + masked_seed + masked_db


def oaep_decode(em: bytes, k: int, label: bytes = b"") -> bytes:
    """EME-OAEP decoding. Lança DecryptionError em qualquer inconsistência."""
    if len(em) != k or k < 2 * HASH_LEN + 2:
        raise DecryptionError()

    y = em[0]
    masked_seed = em[1 : HASH_LEN + 1]
    masked_db = em[HASH_LEN + 1 :]

    seed = xor_bytes(masked_seed, mgf1(masked_db, HASH_LEN))
    db = xor_bytes(masked_db, mgf1(seed, k - HASH_LEN - 1))

    # DB = lHash || PS (zeros) || 0x01 || M
    l_hash_ok = hmac.compare_digest(db[:HASH_LEN], sha3_256(label))
    sep = db.find(b"\x01", HASH_LEN)
    ps_ok = sep != -1 and db[HASH_LEN:sep] == b"\x00" * (sep - HASH_LEN)

    # Mesmo erro para qualquer falha: não revelar qual verificação falhou.
    if y != 0 or not l_hash_ok or not ps_ok:
        raise DecryptionError()

    return db[sep + 1 :]


def oaep_encrypt(pub: PublicKey, message: bytes, label: bytes = b"") -> bytes:
    """RSAES-OAEP-ENCRYPT. Retorna o ciphertext com k bytes."""
    k = key_byte_len(pub.N)
    em = oaep_encode(message, k, label)
    c = rsaep(pub, os2ip(em))
    return i2osp(c, k)


def oaep_decrypt(priv: PrivateKey, ciphertext: bytes, label: bytes = b"") -> bytes:
    """RSAES-OAEP-DECRYPT. Lança DecryptionError se o ciphertext for inválido."""
    k = key_byte_len(priv.N)
    if len(ciphertext) != k:
        raise DecryptionError()

    c = os2ip(ciphertext)
    if c >= priv.N:
        raise DecryptionError()

    em = i2osp(rsadp(priv, c), k)
    return oaep_decode(em, k, label)
