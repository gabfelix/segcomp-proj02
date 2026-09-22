# librsa

Biblioteca base para geração matemática de parâmetros e chaves RSA.

## Funcionalidades

- Teste probabilístico de primalidade Miller-Rabin.
- Geração de chaves RSA configuráveis (ex: 1024, 2048 bits).
- Cálculo de parâmetros do Teorema Chinês do Resto (CRT) para otimização de chave privada.
- Serialização e desserialização de chaves em JSON utilizando representação hexadecimal.

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
