"""Teste do fluxo de assinatura pela aplicação principal."""

import base64
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from librsa import rsa_gen_keys

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
except ImportError:
    hashes = None


class SignCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            cls.private_key, cls.public_key = rsa_gen_keys(1024, 16)

    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_directory.cleanup)
        self.directory = Path(self.temp_directory.name)
        self.file_path = self.directory / "contrato.pdf"
        self.file_path.write_bytes(b"Contrato: R$ 1.000\n")
        self.key_path = self.directory / "private_key.json"
        self.key_path.write_text(self.private_key.to_json(), encoding="utf-8")
        self.output_path = self.directory / "contrato.pdf.sig.json"

    def _run_sign(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "proj02",
                "sign",
                str(self.file_path),
                "--private-key",
                str(self.key_path),
            ],
            cwd=self.directory,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_assinatura_por_linha_de_comando(self) -> None:
        result = self._run_sign()
        self.assertEqual(result.returncode, 0, result.stderr)
        signed_data = json.loads(self.output_path.read_text(encoding="utf-8"))
        self.assertEqual(signed_data["algorithm"], "RSASSA-PSS")
        self.assertEqual(signed_data["hash"], "SHA3-256")
        self.assertEqual(signed_data["mgf"], "MGF1-SHA3-256")
        self.assertEqual(signed_data["salt_length"], 32)
        signature = base64.b64decode(signed_data["signature"], validate=True)
        self.assertEqual(len(signature), (self.public_key.N.bit_length() + 7) // 8)

        if hashes is not None:
            verifier = rsa.RSAPublicNumbers(
                self.public_key.e, self.public_key.N
            ).public_key()
            verifier.verify(
                signature,
                self.file_path.read_bytes(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA3_256()), salt_length=32
                ),
                hashes.SHA3_256(),
            )

    def test_nao_sobrescreve_assinatura_existente(self) -> None:
        self.output_path.write_text("preservar", encoding="utf-8")
        result = self._run_sign()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.output_path.read_text(encoding="utf-8"), "preservar")

    def test_arquivo_inexistente_falha(self) -> None:
        self.file_path.unlink()
        result = self._run_sign()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.output_path.exists())


if __name__ == "__main__":
    unittest.main()
