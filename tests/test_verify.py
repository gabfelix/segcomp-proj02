"""Parte IV: parsing do .sig.json e comando ``python -m proj02 verify``."""

import base64
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from librsa import rsa_gen_keys
from proj02.__main__ import parse_signature

VALID = {
    "version": 1,
    "algorithm": "RSASSA-PSS",
    "hash": "SHA3-256",
    "mgf": "MGF1-SHA3-256",
    "salt_length": 32,
    "signature": base64.b64encode(b"\x01" * 128).decode(),
}
EVEN_N_KEY = '{"N": "' + "f" * 255 + 'e", "e": "3"}'  # N par não é chave RSA


def run(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=dict(os.environ, PYTHONIOENCODING="utf-8"),
        check=False,
    )


class ParseSignatureTests(unittest.TestCase):
    def test_recupera_a_assinatura(self) -> None:
        self.assertEqual(parse_signature(dict(VALID)), VALID["signature"])

    def test_campos_errados_sao_recusados(self) -> None:
        cases = {
            "campo ausente": {k: v for k, v in VALID.items() if k != "hash"},
            "campo desconhecido": {**VALID, "extra": 1},
            "versão diferente": {**VALID, "version": 2},
            "true no lugar de 1": {**VALID, "version": True},
            "1.0 no lugar de 1": {**VALID, "version": 1.0},
            "algoritmo trocado": {**VALID, "algorithm": "RSASSA-PKCS1-v1_5"},
            "hash trocado": {**VALID, "hash": "SHA-256"},
            "mgf trocado": {**VALID, "mgf": "MGF1-SHA-256"},
            "salt diferente": {**VALID, "salt_length": 20},
            "salt como texto": {**VALID, "salt_length": "32"},
            "assinatura vazia": {**VALID, "signature": ""},
            "assinatura não é texto": {**VALID, "signature": 123},
            "Base64 inválido": {**VALID, "signature": "!!!!"},
            "Base64 com espaço": {**VALID, "signature": "AAAA AAAA"},
        }
        for label, data in cases.items():
            with self.subTest(label):
                with self.assertRaises(ValueError):
                    parse_signature(data)


class VerifyCommandTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            cls.private_key, cls.public_key = rsa_gen_keys(1024, 16)

    def setUp(self) -> None:
        temp_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temp_directory.cleanup)
        self.dir = Path(temp_directory.name)
        (self.dir / "contrato.pdf").write_bytes(b"Contrato: R$ 1.000\n")
        (self.dir / "private_key.json").write_text(self.private_key.to_json())
        (self.dir / "public_key.json").write_text(self.public_key.to_json())
        result = run(["proj02", "sign", "contrato.pdf"], self.dir)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.sig = self.dir / "contrato.pdf.sig.json"

    def verify(self) -> subprocess.CompletedProcess[str]:
        return run(["proj02", "verify", "contrato.pdf"], self.dir)

    def test_valida_retorna_0(self) -> None:
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("VÁLIDA", result.stdout)

    def test_invalida_retorna_1(self) -> None:
        (self.dir / "contrato.pdf").write_bytes(b"Contrato: R$ 9.000\n")
        result = self.verify()
        self.assertEqual(result.returncode, 1)
        self.assertIn("INVÁLIDA", result.stderr)

    def test_entradas_invalidas_retornam_2_sem_travar(self) -> None:
        cases = {
            "sig.json não é JSON": (self.sig, "{ isto nao e json"),
            "sig.json com campo repetido": (self.sig, '{"version": 1, "version": 1}'),
            "sig.json gigante": (self.sig, " " * (64 * 1024 + 1)),
            "chave não é objeto": (self.dir / "public_key.json", "[1, 2]"),
            "chave sem N": (self.dir / "public_key.json", '{"e": "3"}'),
            "chave com N par": (self.dir / "public_key.json", EVEN_N_KEY),
            "arquivo ausente": (self.dir / "contrato.pdf", None),
        }
        for label, (path, content) in cases.items():
            with self.subTest(label):
                backup = path.read_bytes()
                path.unlink() if content is None else path.write_text(content)
                try:
                    result = self.verify()
                    self.assertEqual(result.returncode, 2, result.stdout)
                    self.assertNotIn("Traceback", result.stderr)
                finally:
                    path.write_bytes(backup)


if __name__ == "__main__":
    unittest.main()
