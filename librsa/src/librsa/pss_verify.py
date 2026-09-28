"""Parte IV: verificação RSASSA-PSS com SHA3-256 (RFC 8017, 8.1.2 e 9.1.2).

Contraparte de ``pss.py``. As funções devolvem True/False e nunca lançam
exceção por causa de uma assinatura adulterada.
"""

from __future__ import annotations

import base64
import binascii
import hmac
from pathlib import Path
from typing import TYPE_CHECKING

# MGF1 e conversões da Parte II; hash do arquivo da Parte III.
from librsa.primitives import (
    HASH_LEN,
    i2osp,
    key_byte_len,
    mgf1,
    os2ip,
    sha3_256,
    xor_bytes,
)
from librsa.pss import sha3_256_file

if TYPE_CHECKING:
    from librsa import PublicKey


def check_public_key(public_key: PublicKey) -> None:
    """Lança ValueError se (N, e) não formarem uma chave pública plausível.

    N a partir de 1023 bits porque rsa_gen_keys(1024) pode gerar N com um bit
    a menos; o teto de 16384 bits evita chaves que travariam o programa.
    """
    n, e = public_key.N, public_key.e
    if type(n) is not int or type(e) is not int or n % 2 == 0 or e % 2 == 0:
        raise ValueError("chave pública RSA inválida")
    if not 1023 <= n.bit_length() <= 16384 or not 1 < e < n:
        raise ValueError("chave pública RSA inválida")


def pss_verify_digest(
    public_key: PublicKey, digest: bytes, signature: bytes, salt_length: int = HASH_LEN
) -> bool:
    """RSASSA-PSS-VERIFY: True se ``signature`` assina ``digest``."""
    check_public_key(public_key)
    n = public_key.N
    em_bits = n.bit_length() - 1
    em_len = (em_bits + 7) // 8

    # RSAVP1: assinatura com k bytes, s < N; EM = s^e mod N.
    if len(signature) != key_byte_len(n) or os2ip(signature) >= n:
        return False
    m = pow(os2ip(signature), public_key.e, n)
    if m.bit_length() > 8 * em_len:
        return False
    em = i2osp(m, em_len)

    # EMSA-PSS-VERIFY: EM = maskedDB || H || 0xbc.
    if em_len < HASH_LEN + salt_length + 2 or em[-1] != 0xBC:
        return False
    masked_db, h = em[: em_len - HASH_LEN - 1], em[em_len - HASH_LEN - 1 : -1]
    unused_bits = 8 * em_len - em_bits
    if masked_db[0] >> (8 - unused_bits):  # bits excedentes devem ser zero
        return False

    # DB = maskedDB XOR MGF1(H) deve ser: zeros || 0x01 || salt.
    db = bytearray(xor_bytes(masked_db, mgf1(h, len(masked_db))))
    db[0] &= 0xFF >> unused_bits
    ps_len = em_len - HASH_LEN - salt_length - 2
    if any(db[:ps_len]) or db[ps_len] != 0x01:
        return False

    # Recalcula H com o salt recuperado e compara em tempo constante.
    salt = bytes(db[ps_len + 1 :])
    return hmac.compare_digest(h, sha3_256(b"\x00" * 8 + digest + salt))


def pss_verify_file(
    public_key: PublicKey, path: str | Path, signature_b64: str
) -> bool:
    """Verifica a assinatura Base64 gerada por ``pss_sign_file``."""
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError, TypeError):
        return False
    return pss_verify_digest(public_key, sha3_256_file(path), signature)
