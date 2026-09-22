import os
import stat

from librsa import PublicKey, rsa_gen_keys


def main() -> None:
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


if __name__ == "__main__":
    main()
