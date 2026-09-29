# Demonstração do projeto completo

Na raiz do projeto, execute para mostrar também a geração de chaves ao vivo:

```bash
bash demo/rodar_demo.sh --novas-chaves
```

`--novas-chaves` gera um novo par mesmo que já exista outro em `demo/saida/chaves/`.
Sem essa opção, o roteiro reutiliza o par existente; se ainda não houver
chaves, ele as gera. Cada execução guarda uma cópia do par que usou, então os
resultados antigos continuam associados às chaves corretas.

A saída padrão cabe em quatro blocos para facilitar a apresentação. Se a
professora quiser conferir os comandos executados e os bytes alterados, rode
`bash demo/rodar_demo.sh --detalhes`.

Antes da apresentação, você pode editar `demo/mensagem.txt` (a mensagem curta
que será cifrada) e `demo/contrato.txt` (o arquivo que será assinado). Para
escolher outros arquivos, execute:

```bash
bash demo/rodar_demo.sh caminho/para/arquivo.pdf --mensagem caminho/para/mensagem.txt --novas-chaves
```

A mensagem do OAEP pode ter até 190 bytes com uma chave de 2048 bits. O arquivo
assinado pode ser de qualquer tipo ou tamanho: PDF, imagem, texto etc. O roteiro
não modifica os arquivos escolhidos.

## O que aparece na demonstração

| Parte | O que o roteiro mostra |
| --- | --- |
| I | Geração de chaves RSA de 2048 bits com Miller-Rabin; exportação e leitura dos JSONs. A chave é gerada na primeira execução e reutilizada nas seguintes. |
| II | Cifragem de uma mensagem curta com a chave pública usando OAEP, decifragem com a privada e recusa de um texto cifrado com um byte alterado. |
| III | Assinatura do arquivo com RSA-PSS, SHA3-256 e salt; duas assinaturas do mesmo arquivo com a mesma chave saem diferentes e são gravadas em Base64. |
| IV | Verificação válida do original e inválida após alterar um byte do arquivo, um byte da assinatura ou um bit da chave pública. O original continua válido. |
| V | Análise teórica: por que RSA direto é inseguro, papéis distintos de OAEP e PSS e comparação com Ed25519. Consulte [a análise da Parte III](../docs/parte3-pss.md) e os slides; essa parte não é um comando. |

Cada execução cria uma pasta em `demo/saida/` com as chaves, o texto cifrado,
a mensagem recuperada, as assinaturas e as versões adulteradas. Esses arquivos
são ignorados pelo Git. A chave privada é só para a demonstração e não deve
ser compartilhada.

Nas Partes III e IV, a saída padrão mostra trechos das duas assinaturas em
Base64 e o resultado de cada verificação. Com `--detalhes`, aparecem também
os comandos `sign` e `verify` realmente executados, as respostas e os códigos
de saída da aplicação. Para conferir sem o roteiro, entre na pasta
`demo/saida/execucao.*`
impressa ao final e execute, usando o `contrato.txt` padrão:

```bash
uv run --project ../../.. --no-editable python -m proj02 verify ../../../demo/contrato.txt --signature assinatura.sig.json --public-key public_key.json
uv run --project ../../.. --no-editable python -m proj02 verify arquivo-alterado.txt --signature assinatura.sig.json --public-key public_key.json
```

O primeiro comando deve mostrar **VÁLIDA** e o segundo, **INVÁLIDA**. Se você
escolher outro arquivo para assinar, use seu caminho no primeiro comando.

Na fala da Parte V: RSA aplicado diretamente é determinístico e tem uma
estrutura matemática que permite manipulações; por isso a cifragem usa OAEP.
OAEP prepara e randomiza uma mensagem curta antes da operação RSA. PSS prepara
o resumo de um arquivo com salt para a assinatura. Ed25519 é uma alternativa
baseada em curva elíptica, com assinaturas de 64 bytes, enquanto RSA-PSS com
chave de 2048 bits produz 256 bytes neste projeto.

Para conferir também os testes automatizados e a interoperabilidade com uma
biblioteca independente, rode na raiz do projeto:

```bash
uv run --no-editable --with cryptography python -m unittest discover -s librsa/tests -v
uv run --no-editable --with cryptography python -m unittest discover -s tests -v
```
