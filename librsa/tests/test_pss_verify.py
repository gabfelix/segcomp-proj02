"""Testes da Parte IV na biblioteca: verificação RSA-PSS passo a passo."""

import contextlib
import hashlib
import io
import unittest

from librsa import PublicKey, pss_sign_digest, rsa_gen_keys
from librsa.primitives import i2osp, mgf1, os2ip, sha3_256, xor_bytes
from librsa.pss_verify import check_public_key, pss_verify_digest

DIGEST = hashlib.sha3_256(b"conteudo").digest()


class PssVerifyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            cls.private_key, cls.public_key = rsa_gen_keys(1024, 16)
            _, cls.other_public_key = rsa_gen_keys(1024, 16)
        cls.signature = pss_sign_digest(cls.private_key, DIGEST)

    def _sign_em(self, *, trailer=0xBC, separator=0x01, ps_byte=0, top_bit=False):
        """Monta um EM com um defeito escolhido e o assina com a chave privada."""
        n = self.private_key.N
        em_bits = n.bit_length() - 1
        em_len = (em_bits + 7) // 8
        salt = bytes(32)
        h = sha3_256(b"\x00" * 8 + DIGEST + salt)
        ps = bytes(em_len - 32 - 32 - 3) + bytes([ps_byte])
        db = ps + bytes([separator]) + salt
        masked = bytearray(xor_bytes(db, mgf1(h, em_len - 33)))
        masked[0] &= 0xFF >> (8 * em_len - em_bits)
        if top_bit:
            masked[0] |= 0x80
        em = os2ip(bytes(masked) + h + bytes([trailer]))
        return i2osp(pow(em, self.private_key.d, n), (n.bit_length() + 7) // 8)

    def test_assinatura_valida(self) -> None:
        self.assertTrue(pss_verify_digest(self.public_key, DIGEST, self.signature))
        self.assertTrue(pss_verify_digest(self.public_key, DIGEST, self._sign_em()))

    def test_digest_ou_chave_diferente(self) -> None:
        other = hashlib.sha3_256(b"Conteudo").digest()
        self.assertFalse(pss_verify_digest(self.public_key, other, self.signature))
        other_key = self.other_public_key
        self.assertFalse(pss_verify_digest(other_key, DIGEST, self.signature))

    def test_cada_passo_da_rfc_recusa_defeito(self) -> None:
        defects = {
            "byte final diferente de 0xbc": {"trailer": 0xBD},
            "separador diferente de 0x01": {"separator": 0x02},
            "padding PS com byte não zero": {"ps_byte": 7},
        }
        if (self.public_key.N.bit_length() - 1) % 8:
            defects["bit excedente ligado"] = {"top_bit": True}
        for label, defect in defects.items():
            with self.subTest(label):
                signature = self._sign_em(**defect)
                self.assertFalse(pss_verify_digest(self.public_key, DIGEST, signature))

    def test_assinatura_malformada(self) -> None:
        k = len(self.signature)
        cases = [b"", self.signature[1:], self.signature + b"\x00", bytes(k),
                 self.public_key.N.to_bytes(k, "big"), b"\xff" * k]
        for signature in cases:
            with self.subTest(size=len(signature)):
                self.assertFalse(pss_verify_digest(self.public_key, DIGEST, signature))

    def test_chave_publica_invalida(self) -> None:
        n, e = self.public_key.N, self.public_key.e
        for key in (PublicKey(n + 1, e), PublicKey((1 << 511) + 1, 3),
                    PublicKey(n, 1), PublicKey(n, e + 1), PublicKey(True, 3)):
            with self.subTest(key=str(key)[:40]):
                with self.assertRaises(ValueError):
                    check_public_key(key)


if __name__ == "__main__":
    unittest.main()
