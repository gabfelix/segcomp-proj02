"""Testes da Parte III; cryptography é usada apenas para interoperabilidade."""

import base64
import contextlib
import hashlib
import io
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from librsa import (
    pss_encode_digest,
    pss_sign_digest,
    pss_sign_file,
    rsa_gen_keys,
    sha3_256_file,
)

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
except ImportError:
    InvalidSignature = None


class PssTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            cls.private_key, cls.public_key = rsa_gen_keys(
                key_length=1024, prime_test_iterations=16
            )

    def test_digest_de_arquivo_e_assinatura_base64(self) -> None:
        contents = b"arquivo de teste\x00com bytes arbitrarios"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dados.bin"
            path.write_bytes(contents)
            self.assertEqual(sha3_256_file(path), hashlib.sha3_256(contents).digest())

            signature_b64 = pss_sign_file(self.private_key, path)
            signature = base64.b64decode(signature_b64, validate=True)
            self.assertEqual(len(signature), (self.private_key.N.bit_length() + 7) // 8)

    def test_assinaturas_probabilisticas(self) -> None:
        digest = hashlib.sha3_256(b"mesmo arquivo").digest()
        first = pss_sign_digest(self.private_key, digest)
        second = pss_sign_digest(self.private_key, digest)
        self.assertNotEqual(first, second)

    def test_codificacao_e_entradas_invalidas(self) -> None:
        digest = hashlib.sha3_256(b"arquivo").digest()
        em_bits = self.private_key.N.bit_length() - 1
        encoded = pss_encode_digest(digest, em_bits)
        self.assertEqual(encoded[-1], 0xBC)
        self.assertLess(
            int.from_bytes(encoded, "big").bit_length(),
            self.private_key.N.bit_length(),
        )
        with self.assertRaises(ValueError):
            pss_encode_digest(b"curto", em_bits)
        with self.assertRaises(ValueError):
            pss_encode_digest(digest, 511)
        with self.assertRaises(ValueError):
            pss_encode_digest(digest, em_bits, salt_length=-1)
        with self.assertRaises(ValueError):
            pss_sign_digest(replace(self.private_key, d=1), digest)

    @unittest.skipIf(InvalidSignature is None, "cryptography não instalada")
    def test_interoperabilidade_e_adulteracoes(self) -> None:
        public_key = rsa.RSAPublicNumbers(
            self.public_key.e, self.public_key.N
        ).public_key()
        original = b"conteudo assinado"
        digest = hashlib.sha3_256(original).digest()
        signature = pss_sign_digest(self.private_key, digest)
        pss_padding = padding.PSS(
            mgf=padding.MGF1(hashes.SHA3_256()), salt_length=32
        )

        public_key.verify(
            signature, digest, pss_padding, utils.Prehashed(hashes.SHA3_256())
        )
        with self.assertRaises(InvalidSignature):
            public_key.verify(
                signature,
                hashlib.sha3_256(b"Conteudo assinado").digest(),
                pss_padding,
                utils.Prehashed(hashes.SHA3_256()),
            )
        corrupted = bytearray(signature)
        corrupted[-1] ^= 1
        with self.assertRaises(InvalidSignature):
            public_key.verify(
                bytes(corrupted),
                digest,
                pss_padding,
                utils.Prehashed(hashes.SHA3_256()),
            )


if __name__ == "__main__":
    unittest.main()
