# Parte III — assinatura digital RSA-PSS

## Como a assinatura é construída

1. O arquivo é lido em blocos e resumido com SHA3-256. O digest tem 32 bytes.
2. O codificador EMSA-PSS sorteia um salt de 32 bytes com um gerador seguro.
3. Calcula `H = SHA3-256(0x00 × 8 || digest || salt)`.
4. Constrói `DB = PS || 0x01 || salt`, onde `PS` contém zeros, e aplica a
   máscara `MGF1(H, tamanho de DB)` usando SHA3-256.
5. Limpa os bits excedentes à esquerda e termina a codificação com `0xbc`:
   `EM = maskedDB || H || 0xbc`.
6. Interpreta `EM` como inteiro e aplica a operação privada RSA. A assinatura
   é codificada com o tamanho exato do módulo e, para apresentação, em Base64.

O tamanho de `EM` usa `emBits = bit_length(N) - 1`, como determina a
[RFC 8017, seções 8.1.1 e 9.1.1](https://datatracker.ietf.org/doc/html/rfc8017#section-9.1.1).
O verificador recupera `EM` pela operação pública, reconstrói `DB` para obter
o salt e confere a estrutura e o hash. Assim, não basta comparar a assinatura
com uma “cifragem do hash”: o padding é uma parte essencial do esquema.

## Papel do PSS e comparação com Ed25519

O PSS é o esquema de codificação para **assinatura**: associa o digest ao salt
aleatório e ao formato verificável antes da operação RSA. Isso separa o uso
de assinatura do OAEP, que codifica uma mensagem para **cifragem**. A
aleatoriedade do salt faz com que duas assinaturas do mesmo arquivo possam
ser diferentes, mas ambas verificáveis. A RFC 8017 descreve esses parâmetros
e o objetivo de segurança do PSS na [seção 9.1](https://datatracker.ietf.org/doc/html/rfc8017#section-9.1).

| Aspecto | RSA-PSS neste projeto | Ed25519 |
| --- | --- | --- |
| Base matemática | Problema RSA com módulo de pelo menos 2048 bits | Curva elíptica edwards25519 |
| Assinatura | Tamanho do módulo, geralmente 256 bytes para 2048 bits | 64 bytes |
| Aleatoriedade por assinatura | Salt aleatório de 32 bytes | Assinatura determinística no esquema padrão |
| Hash | SHA3-256 + MGF1/SHA3-256, conforme parâmetros escolhidos | SHA-512 integrado ao esquema Ed25519 |

Ed25519 oferece chaves e assinaturas menores e evita a dependência de um
salt aleatório por assinatura. RSA-PSS continua apropriado quando é preciso
usar chaves RSA existentes ou interoperar com sistemas RSA, desde que os
parâmetros de hash, MGF1 e salt sejam acordados. A especificação do Ed25519
está na [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032#section-5.1).
