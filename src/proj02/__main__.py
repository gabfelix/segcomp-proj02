import argparse
import json
import os
import stat
from pathlib import Path

from librsa import PrivateKey, PublicKey, pss_sign_file, rsa_gen_keys


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

    args = parser.parse_args(argv)
    if args.command == "sign":
        output_path = args.output or Path(f"{args.file}.sig.json")
        _sign_file(args.file, args.private_key, output_path, parser)
    else:
        _generate_keys()


if __name__ == "__main__":
    main()
