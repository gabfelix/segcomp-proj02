import argparse
import base64  # Parte IV
import binascii  # Parte IV
import json
import os
import stat
import sys  # Parte IV
from pathlib import Path

from librsa import PrivateKey, PublicKey, pss_sign_file, rsa_gen_keys
from librsa.pss_verify import check_public_key, pss_verify_file  # Parte IV


def _generate_keys() -> None:
    print("Gerando par de chaves RSA de 2048 bits...")
    priv_key, pub_key = rsa_gen_keys(key_length=2048, prime_test_iterations=40)

    print("\nChave Pública Gerada:")
    print(pub_key)

    pub_path = "public_key.json"
    priv_path = "private_key.json"

    with open(pub_path, "w", encoding="utf-8") as f:
        pub_key.save(f)

    fd = os.open(
        priv_path,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        stat.S_IRUSR | stat.S_IWUSR,
    )
    with open(fd, "w", encoding="utf-8") as f:
        priv_key.save(f)

    print(f"\nChaves salvas em '{pub_path}' e '{priv_path}'.")

    with open(pub_path, "r", encoding="utf-8") as f:
        loaded_pub = PublicKey.load(f)

    assert loaded_pub.N == pub_key.N
    print("Validação de leitura de chave pública: OK")


def _sign_file(
    file_path: Path,
    private_key_path: Path,
    output_path: Path,
    parser: argparse.ArgumentParser,
) -> None:
    try:
        with private_key_path.open("r", encoding="utf-8") as key_file:
            private_key = PrivateKey.load(key_file)

        signature_b64 = pss_sign_file(private_key, file_path)
        signed_data = {
            "version": 1,
            "algorithm": "RSASSA-PSS",
            "hash": "SHA3-256",
            "mgf": "MGF1-SHA3-256",
            "salt_length": 32,
            "signature": signature_b64,
        }
        with output_path.open("x", encoding="utf-8") as output_file:
            json.dump(signed_data, output_file, indent=2)
            output_file.write("\n")
    except (OSError, ValueError, TypeError) as error:
        parser.error(str(error))

    print(f"Assinatura salva em '{output_path}'.")


# --- Parte IV: parsing da assinatura e verificação -------------------------

# Mesmos parâmetros gravados por _sign_file. Outros valores são recusados
# para o arquivo não poder escolher um algoritmo mais fraco (downgrade).
EXPECTED = {
    "version": 1,
    "algorithm": "RSASSA-PSS",
    "hash": "SHA3-256",
    "mgf": "MGF1-SHA3-256",
    "salt_length": 32,
}
MAX_JSON_BYTES = 64 * 1024  # um .sig.json real tem menos de 1 KB


def _read_json(path: Path) -> dict:
    """Lê um objeto JSON pequeno; recusa arquivo grande e campo repetido."""
    with path.open("rb") as f:
        raw = f.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError(f"'{path}' é grande demais")

    def no_duplicates(pairs: list) -> dict:
        if len(pairs) != len(dict(pairs)):
            raise ValueError("campo repetido")
        return dict(pairs)

    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    except ValueError as error:
        raise ValueError(f"JSON inválido em '{path}': {error}") from error
    if not isinstance(data, dict):
        raise ValueError(f"'{path}' deve conter um objeto JSON")
    return data


def parse_signature(data: dict) -> str:
    """Confere os campos do .sig.json e devolve a assinatura em Base64."""
    fields = EXPECTED.keys() | {"signature"}
    if data.keys() != fields:
        missing, unknown = sorted(fields - data.keys()), sorted(data.keys() - fields)
        raise ValueError(f"campos ausentes {missing}, desconhecidos {unknown}")
    for field, expected in EXPECTED.items():
        # "type(...) is": recusa true no lugar de 1, 1.0, "32", NaN etc.
        if type(data[field]) is not type(expected) or data[field] != expected:
            raise ValueError(f"campo '{field}' não suportado: {data[field]!r}")
    signature = data["signature"]
    if not isinstance(signature, str) or not signature:
        raise ValueError("campo 'signature' não contém Base64 válido")
    try:
        base64.b64decode(signature, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("campo 'signature' não contém Base64 válido") from error
    return signature


def load_public_key(path: Path) -> PublicKey:
    """Importa a chave pública no formato da Parte I e confere N e e."""
    public_key = PublicKey.from_json(json.dumps(_read_json(path)))
    check_public_key(public_key)
    return public_key


def verify_signature(
    file_path: Path, signature_path: Path, public_key_path: Path
) -> bool:
    """True se a assinatura confere com o arquivo e com a chave pública."""
    public_key = load_public_key(public_key_path)
    signature_b64 = parse_signature(_read_json(signature_path))
    return pss_verify_file(public_key, file_path, signature_b64)


def _verify_file(
    file_path: Path,
    public_key_path: Path,
    signature_path: Path,
    parser: argparse.ArgumentParser,
) -> None:
    """Comando verify. Saída: 0 = válida, 1 = inválida, 2 = erro de entrada."""
    try:
        valid = verify_signature(file_path, signature_path, public_key_path)
    except (OSError, ValueError, TypeError) as error:
        parser.error(str(error))  # código 2

    if not valid:
        sys.exit(f"Assinatura INVÁLIDA para '{file_path}'.")  # código 1
    print(f"Assinatura VÁLIDA para '{file_path}'.")

# --- fim da Parte IV -------------------------------------------------------


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Sistema RSA do projeto")
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("generate", help="gerar e salvar um par de chaves RSA")
    sign_parser = commands.add_parser("sign", help="assinar um arquivo com RSA-PSS")
    sign_parser.add_argument("file", type=Path, help="arquivo a ser assinado")
    sign_parser.add_argument(
        "--private-key",
        type=Path,
        default=Path("private_key.json"),
        help="chave privada JSON (padrão: private_key.json)",
    )
    sign_parser.add_argument(
        "--output",
        type=Path,
        help="arquivo JSON de saída (padrão: ARQUIVO.sig.json)",
    )
    # Parte IV: comando verify
    verify_parser = commands.add_parser(
        "verify", help="verificar a assinatura RSA-PSS de um arquivo"
    )
    verify_parser.add_argument("file", type=Path, help="arquivo assinado")
    verify_parser.add_argument(
        "--public-key",
        type=Path,
        default=Path("public_key.json"),
        help="chave pública JSON (padrão: public_key.json)",
    )
    verify_parser.add_argument(
        "--signature",
        type=Path,
        help="assinatura JSON (padrão: ARQUIVO.sig.json)",
    )

    args = parser.parse_args(argv)
    if args.command == "sign":
        output_path = args.output or Path(f"{args.file}.sig.json")
        _sign_file(args.file, args.private_key, output_path, parser)
    elif args.command == "verify":  # Parte IV
        signature_path = args.signature or Path(f"{args.file}.sig.json")
        _verify_file(args.file, args.public_key, signature_path, parser)
    else:
        _generate_keys()


if __name__ == "__main__":
    main()
