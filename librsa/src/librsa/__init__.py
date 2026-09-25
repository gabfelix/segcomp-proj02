from __future__ import annotations

import json
import math
import random
import secrets
from dataclasses import dataclass
from typing import TextIO, cast, override


def _format_bigint(val: int) -> str:
    """Formata inteiros grandes truncando a representação hexadecimal."""
    hex_str = f"{val:x}"
    if len(hex_str) <= 16:
        return f"0x{hex_str}"
    return f"0x{hex_str[:8]}...{hex_str[-8:]} ({val.bit_length()} bits)"


@dataclass
class PublicKey:
    N: int
    e: int

    def to_json(self) -> str:
        hex_dict = {"N": f"{self.N:x}", "e": f"{self.e:x}"}
        return json.dumps(hex_dict, indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> PublicKey:
        parsed: dict[str, object] = cast(dict[str, object], json.loads(json_str))

        def _get_hex(key: str) -> int:
            val = parsed.get(key)
            if not isinstance(val, str):
                raise TypeError(f"Campo '{key}' ausente ou inválido.")
            return int(val, 16)

        return cls(N=_get_hex("N"), e=_get_hex("e"))

    def save(self, file_obj: TextIO) -> None:
        _ = file_obj.write(self.to_json())

    @classmethod
    def load(cls, file_obj: TextIO) -> PublicKey:
        return cls.from_json(file_obj.read())

    @override
    def __str__(self) -> str:
        return (
            f"=== RSA Public Key ({self.N.bit_length()} bits) ===\n"
            f"N (Modulus) : {_format_bigint(self.N)}\n"
            f"e (Exponent): {self.e} (0x{self.e:x})"
        )

    @override
    def __repr__(self) -> str:
        return self.__str__()


@dataclass
class PrivateKey:
    N: int
    e: int
    d: int
    p: int
    q: int
    crt_dP: int
    crt_dQ: int
    crt_qInv: int

    def to_json(self) -> str:
        hex_dict = {
            "N": f"{self.N:x}",
            "e": f"{self.e:x}",
            "d": f"{self.d:x}",
            "p": f"{self.p:x}",
            "q": f"{self.q:x}",
            "crt_dP": f"{self.crt_dP:x}",
            "crt_dQ": f"{self.crt_dQ:x}",
            "crt_qInv": f"{self.crt_qInv:x}",
        }
        return json.dumps(hex_dict, indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> PrivateKey:
        parsed: dict[str, object] = cast(dict[str, object], json.loads(json_str))

        def _get_hex(key: str) -> int:
            val = parsed.get(key)
            if not isinstance(val, str):
                raise TypeError(f"Campo '{key}' ausente ou inválido.")
            return int(val, 16)

        return cls(
            N=_get_hex("N"),
            e=_get_hex("e"),
            d=_get_hex("d"),
            p=_get_hex("p"),
            q=_get_hex("q"),
            crt_dP=_get_hex("crt_dP"),
            crt_dQ=_get_hex("crt_dQ"),
            crt_qInv=_get_hex("crt_qInv"),
        )

    def save(self, file_obj: TextIO) -> None:
        _ = file_obj.write(self.to_json())

    @classmethod
    def load(cls, file_obj: TextIO) -> PrivateKey:
        return cls.from_json(file_obj.read())

    @override
    def __str__(self) -> str:
        return (
            f"=== RSA Private Key ({self.N.bit_length()} bits) ===\n"
            f"N (Modulus) : {_format_bigint(self.N)}\n"
            f"e (Exponent): {self.e} (0x{self.e:x})\n"
            f"d (Private) : {_format_bigint(self.d)}\n"
            f"p (Prime 1) : {_format_bigint(self.p)}\n"
            f"q (Prime 2) : {_format_bigint(self.q)}\n"
            f"CRT dP      : {_format_bigint(self.crt_dP)}\n"
            f"CRT dQ      : {_format_bigint(self.crt_dQ)}\n"
            f"CRT qInv    : {_format_bigint(self.crt_qInv)}"
        )

    @override
    def __repr__(self) -> str:
        return self.__str__()


SMALL_PRIMES = [
    2,
    3,
    5,
    7,
    11,
    13,
    17,
]


def rsa_gen_keys(
    key_length: int = 1024, prime_test_iterations: int = 40
) -> tuple[PrivateKey, PublicKey]:
    prime_length = key_length // 2

    p = _get_prime(prime_length, prime_test_iterations)
    q = _get_prime(prime_length, prime_test_iterations)

    while p == q:
        q = _get_prime(prime_length, prime_test_iterations)

    if q > p:
        p, q = q, p

    n = p * q
    totient = (p - 1) * (q - 1)

    visited: list[int] = []
    while True:
        enc_exponent = random.randrange(2, totient)
        if enc_exponent in visited:
            continue
        if math.gcd(enc_exponent, totient) == 1:
            break
        visited.append(enc_exponent)

    dec_exponent = pow(enc_exponent, -1, totient)

    crt_dP = dec_exponent % (p - 1)
    crt_dQ = dec_exponent % (q - 1)
    crt_qInv = pow(q, -1, p)

    public_key = PublicKey(N=n, e=enc_exponent)
    private_key = PrivateKey(
        N=n,
        e=enc_exponent,
        d=dec_exponent,
        p=p,
        q=q,
        crt_dP=crt_dP,
        crt_dQ=crt_dQ,
        crt_qInv=crt_qInv,
    )

    print(f"Chave RSA gerada com sucesso! Tamanho de N: {n.bit_length()} bits")
    return private_key, public_key


def test_primality_miller_rabbin(n: int, k: int) -> bool:
    if n <= 2:
        return n == 2
    if n % 2 == 0:
        return False

    for p in SMALL_PRIMES:
        if n % p == 0:
            return n == p

    n_minus_1 = n - 1
    s = (n_minus_1 & -n_minus_1).bit_length() - 1
    d = n_minus_1 >> s
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n_minus_1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n_minus_1:
                break
        else:
            return False
    return True


def _get_odd_candidate(bits: int) -> int:
    num_bytes = (bits + 7) // 8
    candidato_bytes = secrets.token_bytes(num_bytes)
    candidato = int.from_bytes(candidato_bytes, "big")

    candidato |= 1 << (bits - 1)
    candidato |= 1

    return candidato


def _get_prime(bits: int, k: int) -> int:
    while True:
        candidate = _get_odd_candidate(bits)
        if test_primality_miller_rabbin(candidate, k):
            return candidate


from librsa.oaep import DecryptionError, max_message_len, oaep_decrypt, oaep_encrypt  # noqa: E402
from librsa.primitives import mgf1  # noqa: E402

__all__ = [
    "DecryptionError",
    "PrivateKey",
    "PublicKey",
    "max_message_len",
    "mgf1",
    "oaep_decrypt",
    "oaep_encrypt",
    "rsa_gen_keys",
    "test_primality_miller_rabbin",
]
