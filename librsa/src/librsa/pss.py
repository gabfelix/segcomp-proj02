"""Assinatura RSASSA-PSS com SHA3-256 (RFC 8017, seções 8.1 e 9.1.1)."""

from __future__ import annotations

import base64
import hashlib
import secrets
from pathlib import Path
from typing import TYPE_CHECKING

from librsa.primitives import (
    HASH_LEN,
    i2osp,
    key_byte_len,
    mgf1,
    os2ip,
    sha3_256,
    xor_bytes,
)

if TYPE_CHECKING:
    from librsa import PrivateKey


def sha3_256_file(path: str | Path) -> bytes:
    """Calcula SHA3-256 em blocos para não carregar o arquivo inteiro na memória."""
    digest = hashlib.sha3_256()
    with open(path, "rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.digest()


def pss_encode_digest(
    digest: bytes, em_bits: int, *, salt_length: int = HASH_LEN
) -> bytes:
    """Codifica um digest SHA3-256 com EMSA-PSS; retorna EM, não a assinatura.

    ``em_bits`` deve ser ``private_key.N.bit_length() - 1``. O salt é gerado
    com ``secrets`` em cada chamada. O verificador deve usar o mesmo tamanho
    de salt (32 bytes por padrão).
    """
    if not isinstance(digest, bytes) or len(digest) != HASH_LEN:
        raise ValueError("digest SHA3-256 deve conter exatamente 32 bytes")
    if not isinstance(em_bits, int) or em_bits <= 0:
        raise ValueError("em_bits deve ser um inteiro positivo")
    if not isinstance(salt_length, int) or salt_length < 0:
        raise ValueError("salt_length deve ser um inteiro não negativo")

    em_len = (em_bits + 7) // 8
    if em_len < HASH_LEN + salt_length + 2:
        raise ValueError("chave pequena demais para SHA3-256 e este salt")

    salt = secrets.token_bytes(salt_length)
    h = sha3_256(b"\x00" * 8 + digest + salt)
    ps = b"\x00" * (em_len - HASH_LEN - salt_length - 2)
    db = ps + b"\x01" + salt
    masked_db = bytearray(xor_bytes(db, mgf1(h, em_len - HASH_LEN - 1)))

    unused_bits = 8 * em_len - em_bits
    masked_db[0] &= 0xFF >> unused_bits
    return bytes(masked_db) + h + b"\xbc"


def pss_sign_digest(
    private_key: PrivateKey, digest: bytes, *, salt_length: int = HASH_LEN
) -> bytes:
    """Assina um digest SHA3-256 e retorna uma assinatura de k bytes.

    A operação privada é RSASP1 sobre o representante PSS codificado, e não
    uma operação RSA diretamente sobre o digest.
    """
    n = private_key.N
    if (
        not isinstance(n, int)
        or n <= 1
        or not isinstance(private_key.d, int)
        or private_key.d <= 0
        or private_key.d >= n
        or not isinstance(private_key.e, int)
        or not 1 < private_key.e < n
    ):
        raise ValueError("chave privada RSA inválida")

    em = pss_encode_digest(digest, n.bit_length() - 1, salt_length=salt_length)
    representative = os2ip(em)
    if representative >= n:
        raise ValueError("representante PSS fora do intervalo da chave")

    signature = pow(representative, private_key.d, n)
    if pow(signature, private_key.e, n) != representative:
        raise ValueError("chave privada RSA inconsistente")
    return i2osp(signature, key_byte_len(n))


def pss_sign_file(
    private_key: PrivateKey, path: str | Path, *, salt_length: int = HASH_LEN
) -> str:
    """Assina o conteúdo de um arquivo e devolve a assinatura em Base64."""
    signature = pss_sign_digest(
        private_key, sha3_256_file(path), salt_length=salt_length
    )
    return base64.b64encode(signature).decode("ascii")
