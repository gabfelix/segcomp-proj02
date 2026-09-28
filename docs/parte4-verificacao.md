# Parte IV — parsing, verificação e testes de adulteração

A Parte IV só **acrescenta** código: nenhuma linha das Partes I a III foi
removida ou modificada. No `__main__.py`, os trechos novos estão marcados
com `# Parte IV`.

| Arquivo | Conteúdo |
| --- | --- |
| `librsa/src/librsa/pss_verify.py` | Verificação RSASSA-PSS (RFC 8017, 8.1.2 e 9.1.2), contraparte de `pss.py` |
| `src/proj02/__main__.py` (acréscimo) | Parsing do `.sig.json`, leitura da chave pública e comando `verify` |
| `librsa/tests/test_pss_verify.py` | Cada passo da verificação recusa o defeito correspondente |
| `tests/test_verify.py` | Parsing e códigos de saída do comando |
| `tests/test_adulteracao.py` | Testes de adulteração exigidos |
| `tests/test_interoperabilidade.py` | Interoperabilidade com a biblioteca `cryptography` |

## Uso

```bash
uv run python -m proj02 generate
uv run python -m proj02 sign contrato.pdf
uv run python -m proj02 verify contrato.pdf --public-key public_key.json
```

A assinatura é lida de `contrato.pdf.sig.json` (ou de `--signature`).
Código de saída: **0** válida, **1** inválida, **2** não foi possível
verificar (arquivo ausente, JSON malformado, parâmetro diferente ou chave
inválida). Em 1 e 2 o arquivo não deve ser considerado autêntico.

## Parsing

`parse_signature` exige exatamente os campos gravados pelo `sign`, com os
mesmos valores e tipos (`1`, `RSASSA-PSS`, `SHA3-256`, `MGF1-SHA3-256`,
`32`) e a assinatura em Base64 estrito. O verificador não deixa o arquivo
escolher o algoritmo (evita *downgrade*) e compara o tipo para recusar
`true`, `1.0` ou `"32"` (em Python, `True == 1`). `_read_json` recusa
arquivo maior que 64 KiB e campo repetido. A chave pública é lida com
`PublicKey.from_json` (Parte I) e conferida por `check_public_key`
(`N` ímpar entre 1023 e 16384 bits, `1 < e < N`, `e` ímpar).

## Verificação

O SHA3-256 do arquivo é recalculado. `pss_verify_digest` exige assinatura
com `k` bytes e `s < N`, calcula `EM = s^e mod N` e confere a codificação
PSS: byte final `0xbc`, bits excedentes zerados, `DB = maskedDB ⊕ MGF1(H)`
igual a `00…00 || 01 || salt` e, por fim,
`H = SHA3-256(0x00×8 || digest || salt)` comparado em tempo constante
(`hmac.compare_digest`). Qualquer falha devolve `False`, nunca exceção.

## Testes de adulteração

Com chave de 2048 bits e arquivo assinado pelo `sign`:

| Adulteração | Casos | Resultado |
| --- | --- | --- |
| 1 byte do arquivo | 3 posições × 3 máscaras; "R$ 1.000" → "R$ 9.000" | Recusada |
| 1 byte da assinatura | **todos** os 256 bytes | Recusada |
| Chave pública | outro par; 1 bit de `N`; `e` trocado; 1 caractere do JSON | Recusada |

Após cada teste o original é verificado de novo e continua válido. Com o
verificador sabotado para aceitar tudo, os testes falham, o que mostra que
eles detectam erros de verdade.

## Interoperabilidade

Com a biblioteca [`cryptography`](https://cryptography.io/), usada só nos
testes: ela aceita as assinaturas do `sign`; o verificador do grupo aceita
as dela (chaves de 2048, 2049 e 3072 bits); o verificador recusa SHA-256,
MGF1-SHA-256, salt 0 e PKCS#1 v1.5; e as duas recusam as adulterações.

```bash
uv run --with cryptography python -m unittest discover -s librsa/tests -v
uv run --with cryptography python -m unittest discover -s tests -v
```

## Observação para a Parte I

`rsa_gen_keys(2048)` força só o bit mais alto de cada primo, então `N` pode
ter 2047 bits. Não quebra nada, mas o usual é forçar os dois bits mais altos.
