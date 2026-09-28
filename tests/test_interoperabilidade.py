"""Parte IV: interoperabilidade com a biblioteca consolidada ``cryptography``.

A ``cryptography`` é usada só nestes testes, como juiz independente. Rodar com:
    uv run --with cryptography python -m unittest discover -s tests -v
Sem ela instalada, os testes aparecem como "skipped".
"""

import base64
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from librsa import PublicKey, rsa_gen_keys
from proj02.__main__ import verify_signature

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
except ImportError:
    InvalidSignature = None


@unittest.skipIf(InvalidSignature is None, "cryptography não instalada")
class InteroperabilidadeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            cls.group_private, cls.group_public = rsa_gen_keys(2048, 16)
        cls.lib_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = cls.lib_private.public_key().public_numbers()
        cls.lib_public = PublicKey(numbers.n, numbers.e)
        cls.pss = padding.PSS(mgf=padding.MGF1(hashes.SHA3_256()), salt_length=32)

    def setUp(self) -> None:
        temp_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temp_directory.cleanup)
        self.dir = Path(temp_directory.name)
        self.data = b"Relatorio final\n" * 100
        self.file = self.dir / "relatorio.pdf"
        self.file.write_bytes(self.data)

    def group_verifies(self, signature: bytes, key: PublicKey, data=None) -> bool:
        """Grava assinatura e chave no formato do grupo e usa o verify do grupo."""
        file = self.file
        if data is not None:
            file = self.dir / "outro.pdf"
            file.write_bytes(data)
        sig = self.dir / "externa.sig.json"
        sig.write_text(json.dumps({
            "version": 1, "algorithm": "RSASSA-PSS", "hash": "SHA3-256",
            "mgf": "MGF1-SHA3-256", "salt_length": 32,
            "signature": base64.b64encode(signature).decode(),
        }))
        key_path = self.dir / "externa_public_key.json"
        key_path.write_text(key.to_json())
        return verify_signature(file, sig, key_path)

    def library_verifies(self, signature: bytes, key: PublicKey, data=None) -> bool:
        public = rsa.RSAPublicNumbers(key.e, key.N).public_key()
        try:
            public.verify(signature, self.data if data is None else data,
                          self.pss, hashes.SHA3_256())
        except InvalidSignature:
            return False
        return True

    def group_sign(self) -> bytes:
        (self.dir / "private_key.json").write_text(self.group_private.to_json())
        subprocess.run([sys.executable, "-m", "proj02", "sign", "relatorio.pdf"],
                       cwd=self.dir, capture_output=True, check=True)
        signed = json.loads((self.dir / "relatorio.pdf.sig.json").read_text())
        return base64.b64decode(signed["signature"])

    def test_cryptography_aceita_assinatura_do_grupo(self) -> None:
        self.assertTrue(self.library_verifies(self.group_sign(), self.group_public))

    def test_grupo_aceita_assinatura_da_cryptography(self) -> None:
        for key_size in (2048, 2049, 3072):  # 2049: caso de borda emLen = k - 1
            with self.subTest(key_size=key_size):
                private = rsa.generate_private_key(65537, key_size)
                numbers = private.public_key().public_numbers()
                signature = private.sign(self.data, self.pss, hashes.SHA3_256())
                key = PublicKey(numbers.n, numbers.e)
                self.assertTrue(self.group_verifies(signature, key))

    def test_grupo_recusa_outros_parametros(self) -> None:
        mgf_sha3 = padding.MGF1(hashes.SHA3_256())
        pss_sha256 = padding.PSS(padding.MGF1(hashes.SHA256()), 32)
        cases = {
            "hash SHA-256": (pss_sha256, hashes.SHA256()),
            "MGF1 com SHA-256": (pss_sha256, hashes.SHA3_256()),
            "salt de 0 bytes": (padding.PSS(mgf_sha3, 0), hashes.SHA3_256()),
            "PKCS#1 v1.5": (padding.PKCS1v15(), hashes.SHA3_256()),
        }
        for label, (pad, hash_algorithm) in cases.items():
            with self.subTest(label):
                signature = self.lib_private.sign(self.data, pad, hash_algorithm)
                self.assertFalse(self.group_verifies(signature, self.lib_public))

    def test_as_duas_recusam_as_adulteracoes(self) -> None:
        signature = self.group_sign()
        data = bytearray(self.data)
        data[10] ^= 1
        bad_signature = bytearray(signature)
        bad_signature[100] ^= 1
        cases = {
            "byte do arquivo": (signature, self.group_public, bytes(data)),
            "byte da assinatura": (bytes(bad_signature), self.group_public, None),
            "chave de outro par": (signature, self.lib_public, None),
        }
        for label, (sig, key, content) in cases.items():
            with self.subTest(label):
                self.assertFalse(self.library_verifies(sig, key, content))
                self.assertFalse(self.group_verifies(sig, key, content))


if __name__ == "__main__":
    unittest.main()
