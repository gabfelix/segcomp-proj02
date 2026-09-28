"""Parte IV: testes de adulteração exigidos pelo trabalho.

Partindo de um arquivo assinado por ``python -m proj02 sign`` (chave de 2048
bits), a verificação precisa FALHAR quando se altera um byte do arquivo, um
byte da assinatura ou a chave pública. Cada teste confere também que o
original continua válido, provando que a falha vem da adulteração.
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


class AdulteracaoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            cls.private_key, cls.public_key = rsa_gen_keys(2048, 16)
            _, cls.other_public_key = rsa_gen_keys(2048, 16)

    def setUp(self) -> None:
        temp_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temp_directory.cleanup)
        self.dir = Path(temp_directory.name)
        self.original = b"CONTRATO\nValor: R$ 1.000,00\n" + bytes(range(256))
        self.file = self.dir / "contrato.pdf"
        self.file.write_bytes(self.original)
        (self.dir / "private_key.json").write_text(self.private_key.to_json())
        self.key = self.dir / "public_key.json"
        self.key.write_text(self.public_key.to_json())
        subprocess.run(
            [sys.executable, "-m", "proj02", "sign", "contrato.pdf"],
            cwd=self.dir, capture_output=True, check=True,
        )
        self.sig = self.dir / "contrato.pdf.sig.json"
        self.signed = json.loads(self.sig.read_text())
        self.signature = base64.b64decode(self.signed["signature"])

    def tearDown(self) -> None:
        # O original precisa continuar válido depois de cada teste.
        self.assertTrue(verify_signature(self.file, self.sig, self.key))

    def verify_with(self, *, data=None, signature=None, key=None) -> bool:
        """Verifica trocando só o arquivo, só a assinatura ou só a chave."""
        file, sig, key_path = self.file, self.sig, self.key
        if data is not None:
            file = self.dir / "adulterado.pdf"
            file.write_bytes(data)
        if signature is not None:
            sig = self.dir / "adulterada.sig.json"
            encoded = base64.b64encode(signature).decode()
            sig.write_text(json.dumps({**self.signed, "signature": encoded}))
        if key is not None:
            key_path = self.dir / "chave_adulterada.json"
            key_path.write_text(key if isinstance(key, str) else key.to_json())
        try:
            return verify_signature(file, sig, key_path)
        except (ValueError, TypeError):
            return False  # chave malformada também é recusada

    def test_1_alterar_um_byte_do_arquivo(self) -> None:
        size = len(self.original)
        for position in (0, size // 2, size - 1):
            for mask in (0x01, 0x80, 0xFF):
                with self.subTest(posicao=position, mascara=mask):
                    data = bytearray(self.original)
                    data[position] ^= mask
                    self.assertFalse(self.verify_with(data=bytes(data)))
        changed = self.original.replace(b"R$ 1.000", b"R$ 9.000")
        self.assertFalse(self.verify_with(data=changed))

    def test_2_alterar_um_byte_da_assinatura_em_todas_as_posicoes(self) -> None:
        for position in range(len(self.signature)):  # 256 bytes
            with self.subTest(posicao=position):
                signature = bytearray(self.signature)
                signature[position] ^= 0x01
                self.assertFalse(self.verify_with(signature=bytes(signature)))

    def test_3_alterar_a_chave_publica(self) -> None:
        n, e = self.public_key.N, self.public_key.e
        keys = {
            "chave de outro par": self.other_public_key,
            "bit de N trocado": PublicKey(n ^ (1 << 1024), e),
            "e trocado": PublicKey(n, e ^ 2),
        }
        text = self.key.read_text()
        middle = text.index(f"{n:x}") + 256
        swapped = "0" if text[middle] != "0" else "1"
        keys["1 caractere do JSON trocado"] = (
            text[:middle] + swapped + text[middle + 1 :]
        )
        for label, key in keys.items():
            with self.subTest(label):
                self.assertFalse(self.verify_with(key=key))

    def test_comando_verify_recusa_arquivo_adulterado(self) -> None:
        self.file.write_bytes(self.original.replace(b"R$ 1.000", b"R$ 9.000"))
        result = subprocess.run(
            [sys.executable, "-m", "proj02", "verify", "contrato.pdf"],
            cwd=self.dir, capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.file.write_bytes(self.original)


if __name__ == "__main__":
    unittest.main()
