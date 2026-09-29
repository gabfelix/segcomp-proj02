"""Demonstra as partes executáveis do trabalho com a implementação do grupo."""

from __future__ import annotations

import argparse
import base64
import json
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from librsa import (
    DecryptionError,
    PrivateKey,
    PublicKey,
    max_message_len,
    oaep_decrypt,
    oaep_encrypt,
    sha3_256_file,
)


DEMO_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = DEMO_DIR / "saida"
KEY_DIR = OUTPUT_DIR / "chaves"


def input_path(value: str) -> Path:
    path = Path(value).expanduser().resolve()
    if not path.is_file():
        raise ValueError(f"arquivo não encontrado: {path}")
    return path


def app_command(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "proj02", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


def require_status(result: subprocess.CompletedProcess[str], expected: int) -> None:
    if result.returncode != expected:
        details = (result.stdout + result.stderr).strip()
        raise RuntimeError(
            f"resultado inesperado (código {result.returncode}, esperado {expected}): {details}"
        )


def show_command_result(result: subprocess.CompletedProcess[str], detailed: bool) -> None:
    if not detailed:
        return
    command = [Path(result.args[0]).name, *result.args[1:]]
    print(f"    $ {shlex.join(command)}")
    if result.stdout.strip():
        print(f"    {result.stdout.strip()}")
    if result.stderr.strip():
        print(f"    {result.stderr.strip()}")
    print(f"    Código de saída: {result.returncode}")


def demo_keys(regenerate: bool) -> tuple[PrivateKey, PublicKey, bool]:
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    private_path = KEY_DIR / "private_key.json"
    public_path = KEY_DIR / "public_key.json"

    def load_pair() -> tuple[PrivateKey, PublicKey] | None:
        try:
            with private_path.open(encoding="utf-8") as file:
                private = PrivateKey.load(file)
            with public_path.open(encoding="utf-8") as file:
                public = PublicKey.load(file)
        except (OSError, ValueError, TypeError):
            return None
        if private.N != public.N or private.e != public.e:
            return None
        if public.N.bit_length() != 2048:
            return None
        return private, public

    pair = None if regenerate else load_pair()
    generated = pair is None
    if pair is None:
        print("  Gerando chaves RSA com Miller-Rabin...")
        for _ in range(10):
            result = app_command("generate", cwd=KEY_DIR)
            require_status(result, 0)
            (KEY_DIR / "geracao.log").write_text(
                result.stdout + result.stderr, encoding="utf-8"
            )
            pair = load_pair()
            if pair is not None:
                break
        if pair is None:
            raise RuntimeError("não foi possível gerar uma chave de 2048 bits")

    return pair[0], pair[1], generated


def demo_oaep(
    private: PrivateKey,
    public: PublicKey,
    message_path: Path,
    run_dir: Path,
    detailed: bool,
) -> None:
    print("\n2. CIFRAGEM RSA-OAEP")
    message = message_path.read_bytes()
    maximum = max_message_len(public)
    if len(message) > maximum:
        raise ValueError(
            f"mensagem OAEP tem {len(message)} bytes; máximo para esta chave: {maximum}"
        )

    ciphertext = oaep_encrypt(public, message)
    recovered = oaep_decrypt(private, ciphertext)
    if recovered != message:
        raise RuntimeError("OAEP não recuperou a mensagem original")

    ciphertext_b64 = base64.b64encode(ciphertext).decode("ascii")
    (run_dir / "mensagem-cifrada.b64").write_text(ciphertext_b64 + "\n", encoding="ascii")
    (run_dir / "mensagem-recuperada.bin").write_bytes(recovered)
    print(f"  Mensagem: {message_path.name} ({len(message)} bytes; limite: {maximum})")
    try:
        print(f"  Original:   {message.decode('utf-8').strip()!r}")
        print(f"  Decifrada:  {recovered.decode('utf-8').strip()!r}")
    except UnicodeDecodeError:
        print("  Decifrada:  bytes idênticos à mensagem original")
    print(f"  Cifrado:    {ciphertext_b64[:24]}... ({len(ciphertext)} bytes)")
    if detailed:
        print(f"  Cifrado completo: {run_dir / 'mensagem-cifrada.b64'}")
        print(f"  Mensagem recuperada: {run_dir / 'mensagem-recuperada.bin'}")

    corrupted = bytearray(ciphertext)
    corrupted_position = len(corrupted) // 2
    original_byte = corrupted[corrupted_position]
    corrupted[corrupted_position] ^= 1
    (run_dir / "mensagem-cifrada-alterada.b64").write_text(
        base64.b64encode(corrupted).decode("ascii") + "\n", encoding="ascii"
    )
    try:
        oaep_decrypt(private, bytes(corrupted))
    except DecryptionError:
        print("  Cifrado adulterado (1 byte): RECUSADO")
        if detailed:
            print(
                f"  Byte {corrupted_position}: {original_byte:02x} → "
                f"{corrupted[corrupted_position]:02x}"
            )
            print(f"  Arquivo: {run_dir / 'mensagem-cifrada-alterada.b64'}")
    else:
        raise RuntimeError("OAEP aceitou um texto cifrado alterado")


def demo_verify(
    label: str,
    file_path: Path,
    signature_path: Path,
    public_key_path: Path,
    run_dir: Path,
    expected: int,
    detailed: bool,
) -> None:
    result = app_command(
        "verify",
        str(file_path),
        "--signature",
        signature_path.name,
        "--public-key",
        public_key_path.name,
        cwd=run_dir,
    )
    require_status(result, expected)
    verdict = "VÁLIDA" if result.returncode == 0 else "INVÁLIDA"
    print(f"  {label:<33} {verdict}")
    show_command_result(result, detailed)


def demo_pss(file_path: Path, public: PublicKey, run_dir: Path, detailed: bool) -> None:
    print("\n3. ASSINATURA RSA-PSS")
    file_digest = sha3_256_file(file_path)
    print(f"  Arquivo: {file_path.name}")
    print(f"  SHA3-256: {file_digest.hex()[:24]}... (32 bytes)")
    if detailed:
        print(f"  Caminho: {file_path}")
        print(f"  Resumo completo: {file_digest.hex()}")
    private_key_path = run_dir / "private_key.json"
    public_key_path = run_dir / "public_key.json"
    signature_path = run_dir / "assinatura.sig.json"
    second_signature_path = run_dir / "segunda-assinatura.sig.json"

    if detailed:
        print(f"  Pasta de execução dos comandos: {run_dir}")
    for number, output in enumerate((signature_path, second_signature_path), start=1):
        result = app_command(
            "sign",
            str(file_path),
            "--private-key",
            private_key_path.name,
            "--output",
            output.name,
            cwd=run_dir,
        )
        require_status(result, 0)
        if detailed:
            print(f"  Chamada de assinatura {number}:")
        show_command_result(result, detailed)
    first = json.loads(signature_path.read_text(encoding="utf-8"))
    second = json.loads(second_signature_path.read_text(encoding="utf-8"))
    signature = base64.b64decode(first["signature"], validate=True)
    second_signature = base64.b64decode(second["signature"], validate=True)
    if (
        len(signature) != 256
        or len(second_signature) != 256
        or signature == second_signature
    ):
        raise RuntimeError("assinaturas PSS não tiveram o resultado esperado")
    for label, output, encoded in (
        ("A", signature_path, first["signature"]),
        ("B", second_signature_path, second["signature"]),
    ):
        print(f"  Assinatura {label}: {encoded[:24]}... → {output.name}")
        if detailed:
            print(f"    Base64 completo no arquivo: {output}")
    print("  Mesmo arquivo e chave; duas assinaturas diferentes pelo salt (256 bytes cada).")

    print("\n4. VERIFICAÇÃO E ADULTERAÇÕES")
    demo_verify("Original + assinatura A", file_path, signature_path, public_key_path, run_dir, 0, detailed)
    demo_verify("Original + assinatura B", file_path, second_signature_path, public_key_path, run_dir, 0, detailed)

    altered_file = run_dir / f"arquivo-alterado{file_path.suffix}"
    shutil.copy2(file_path, altered_file)
    with altered_file.open("r+b") as file:
        size = file.seek(0, 2)
        if size:
            position = size // 2
            file.seek(position)
            original_byte = file.read(1)[0]
            modified_byte = original_byte ^ 1
            file.seek(position)
            file.write(bytes([modified_byte]))
            file_label = f"Arquivo: byte {position} alterado"
            if detailed:
                print(f"  Arquivo: byte {position} alterado de {original_byte:02x} para {modified_byte:02x}.")
        else:
            file.write(b"\x01")
            file_label = "Arquivo vazio: 1 byte acrescentado"
            if detailed:
                print("  Arquivo vazio: acrescentado o byte 01 para demonstrar a alteração.")
    if detailed:
        print(f"  Resumo do original:  {file_digest.hex()}")
        print(f"  Resumo do alterado: {sha3_256_file(altered_file).hex()}")
        print(f"  Cópia alterada: {altered_file}")
    demo_verify(file_label, altered_file, signature_path, public_key_path, run_dir, 1, detailed)

    altered_signature = bytearray(signature)
    signature_position = len(altered_signature) // 2
    original_signature_byte = altered_signature[signature_position]
    altered_signature[signature_position] ^= 1
    changed_signature_data = {
        **first,
        "signature": base64.b64encode(altered_signature).decode("ascii"),
    }
    altered_signature_path = run_dir / "assinatura-alterada.sig.json"
    altered_signature_path.write_text(
        json.dumps(changed_signature_data, indent=2) + "\n", encoding="utf-8"
    )
    if detailed:
        print(
            f"  Assinatura: byte {signature_position} alterado de "
            f"{original_signature_byte:02x} para {altered_signature[signature_position]:02x}."
        )
        print(f"  Assinatura alterada: {altered_signature_path}")
    demo_verify(
        f"Assinatura: byte {signature_position} alterado",
        file_path,
        altered_signature_path,
        public_key_path,
        run_dir,
        1,
        detailed,
    )

    altered_public_key_path = run_dir / "public_key-alterada.json"
    altered_public_key_path.write_text(
        PublicKey(public.N ^ (1 << 1024), public.e).to_json(), encoding="utf-8"
    )
    key_byte = (public.N >> 1024) & 0xFF
    if detailed:
        print(f"  Chave pública: bit 1024 de N invertido (byte {key_byte:02x} para {key_byte ^ 1:02x}).")
        print(f"  Chave pública alterada: {altered_public_key_path}")
    demo_verify(
        "Chave pública: 1 bit alterado",
        file_path,
        signature_path,
        altered_public_key_path,
        run_dir,
        1,
        detailed,
    )
    demo_verify("Original novamente", file_path, signature_path, public_key_path, run_dir, 0, detailed)


def main() -> None:
    parser = argparse.ArgumentParser(description="Demonstração completa do trabalho RSA")
    parser.add_argument(
        "arquivo",
        nargs="?",
        default=str(DEMO_DIR / "contrato.txt"),
        help="arquivo a assinar; padrão: demo/contrato.txt",
    )
    parser.add_argument(
        "--mensagem",
        default=str(DEMO_DIR / "mensagem.txt"),
        help="arquivo com mensagem curta para OAEP; padrão: demo/mensagem.txt",
    )
    parser.add_argument(
        "--novas-chaves",
        action="store_true",
        help="gera um novo par de chaves RSA para mostrar a Parte I ao vivo",
    )
    parser.add_argument(
        "--detalhes",
        action="store_true",
        help="mostra comandos, respostas completas, bytes alterados e caminhos",
    )
    args = parser.parse_args()
    file_path = input_path(args.arquivo)
    message_path = input_path(args.mensagem)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    print("DEMONSTRAÇÃO DO SISTEMA RSA")
    print(f"Mensagem OAEP: {message_path.name} | Arquivo assinado: {file_path.name}")
    print("\n1. CHAVES RSA")
    private, public, generated = demo_keys(args.novas_chaves)
    action = "geradas agora" if generated else "reutilizadas"
    print(f"  RSA 2048 bits; chaves {action} e lidas dos arquivos JSON.")
    if args.detalhes:
        print(f"  Chave pública: {KEY_DIR / 'public_key.json'}")
        print(f"  Chave privada: {KEY_DIR / 'private_key.json'}")
    run_dir = Path(tempfile.mkdtemp(prefix="execucao.", dir=OUTPUT_DIR))
    shutil.copy2(KEY_DIR / "private_key.json", run_dir / "private_key.json")
    shutil.copy2(KEY_DIR / "public_key.json", run_dir / "public_key.json")

    demo_oaep(private, public, message_path, run_dir, args.detalhes)
    demo_pss(file_path, public, run_dir, args.detalhes)
    print(f"\nArquivos gerados: {run_dir.relative_to(DEMO_DIR.parent)}/")
    if not args.detalhes:
        print("Para ver comandos e bytes alterados: adicione --detalhes.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError) as error:
        raise SystemExit(f"Erro na demonstração: {error}") from error
