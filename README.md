# Sistema de Assinatura Digital RSA

Este repositório principal integra módulos criptográficos isolados utilizando a arquitetura de workspaces do `uv`.

## Arquitetura de Workspaces (uv)

Os workspaces do `uv` permitem gerenciar múltiplos pacotes Python dentro de um único repositório, compartilhando o mesmo arquivo de trava (`uv.lock`) e ambiente virtual, mantendo escopos separados.

O arquivo `pyproject.toml` na raiz do repositório define a estrutura de membros do workspace:

```toml
[tool.uv.workspace]
members = [
    "librsa",
    "proj02"
]

```

### Configurando Dependências Internas

Para que a aplicação principal (`proj02`) utilize o submódulo (`librsa`), adicione a biblioteca como dependência do workspace executando na raiz do projeto:

```bash
uv add --project proj02 librsa

```

Isso cria um link editável para o módulo local no ambiente virtual do repositório.

## Execução da Aplicação

A aplicação principal é estruturada como um pacote executável. O ponto de entrada está definido no arquivo `src/proj02/__main__.py`.

Para gerar as chaves, execute na raiz do repositório:

```bash
uv run --no-editable python -m proj02 generate

```

Para assinar um arquivo escolhido por você:

```bash
uv run --no-editable python -m proj02 sign contrato.pdf --private-key private_key.json
```

O resultado é `contrato.pdf.sig.json`. O arquivo original não é alterado.
O JSON contém o algoritmo, hash, MGF1, comprimento do salt e a assinatura
em Base64. Um caminho alternativo pode ser informado com `--output`.
O comando recusa sobrescrever uma assinatura existente.

Para demonstrar todas as partes executáveis do projeto com arquivos editáveis,
veja [`demo/README.md`](demo/README.md). Na raiz do projeto, execute
`bash demo/rodar_demo.sh --novas-chaves`. O roteiro mostra geração de chaves, OAEP, PSS,
verificação e os testes de adulteração.

## Utilização das APIs

Com a estrutura de workspaces configurada, as bibliotecas locais são tratadas pelo interpretador como pacotes instalados padrão. A importação obedece o escopo global da biblioteca e não exige manipulação do `sys.path`.

```python
from librsa import PrivateKey, PublicKey, rsa_gen_keys


def inicializar_sistema():
    priv, pub = rsa_gen_keys(2048)
    print(pub)

```

**Diretriz de Arquitetura:** A biblioteca (`librsa`) executa exclusivamente os cálculos matemáticos e a formatação de estruturas de dados. A aplicação principal (`proj02`) orquestra as chamadas, gerencia permissões restritas no sistema de arquivos e implementa a lógica de negócios de assinatura digital e verificação.
