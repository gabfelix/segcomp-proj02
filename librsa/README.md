# librsa

Biblioteca base para geração matemática de parâmetros e chaves RSA.

## Funcionalidades

- Teste probabilístico de primalidade Miller-Rabin.
- Geração de chaves RSA configuráveis (ex: 1024, 2048 bits).
- Cálculo de parâmetros do Teorema Chinês do Resto (CRT) para otimização de chave privada.
- Serialização e desserialização de chaves em JSON utilizando representação hexadecimal.
- Assinatura RSA-PSS de arquivos com SHA3-256 e assinatura codificada em Base64.

## Uso Básico

A biblioteca delega o controle de I/O de arquivos para o chamador, mantendo o foco em operações criptográficas.

```python
import os
import stat
from librsa import rsa_gen_keys, PrivateKey, PublicKey

# 1. Geração das Chaves
priv_key, pub_key = rsa_gen_keys(key_length=2048)

# 2. Exportação da Chave Privada (com permissões restritas 0o600)
fd = os.open("private.json", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
with open(fd, "w") as f:
    priv_key.save(f)

# 3. Exportação da Chave Pública
with open("public.json", "w") as f:
    pub_key.save(f)

# 4. Importação de Chaves Existentes
with open("private.json", "r") as f:
    loaded_priv = PrivateKey.load(f)
```

## Assinatura de arquivo (Parte III)

```python
from librsa import PrivateKey, pss_sign_file, sha3_256_file

with open("private.json", encoding="utf-8") as key_file:
    private_key = PrivateKey.load(key_file)

digest = sha3_256_file("documento.pdf")  # 32 bytes; o arquivo é lido em blocos
signature_b64 = pss_sign_file(private_key, "documento.pdf")
print(digest.hex(), signature_b64)
```

`pss_sign_file` devolve apenas a assinatura Base64; a aplicação principal
decide como armazená-la junto aos demais campos. O algoritmo é
RSASSA-PSS com SHA3-256 tanto no hash da mensagem quanto no MGF1, e usa
salt aleatório de 32 bytes por padrão. O verificador da Parte IV deverá
usar esses mesmos parâmetros. `pss_sign_digest` recebe um digest SHA3-256
de 32 bytes e devolve a assinatura binária de tamanho igual ao módulo RSA.

Os testes podem ser executados com
`uv run --no-editable python -m unittest discover -s librsa/tests -v`.
Para executar também o teste adicional de interoperabilidade, use
`uv run --no-editable --with cryptography python -m unittest discover -s librsa/tests -v`.
`cryptography` não é usada na implementação.

Ver [fundamentação e comparação com Ed25519](../docs/parte3-pss.md).
