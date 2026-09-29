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

## Demonstração do projeto

Para apresentar o fluxo completo na raiz do repositório:

```bash
bash demo/rodar_demo.sh --novas-chaves
```

O roteiro gera as chaves RSA, cifra e decifra uma mensagem curta com OAEP,
assina um arquivo com PSS e verifica o original e versões adulteradas. Por
padrão, usa `demo/mensagem.txt` para a cifragem e `demo/contrato.txt` para a
assinatura. Você pode editar esses arquivos antes de executar ou escolher outros:

```bash
bash demo/rodar_demo.sh caminho/para/arquivo.pdf --mensagem caminho/para/mensagem.txt
```

`--novas-chaves` força a geração de um novo par RSA, útil para mostrar a Parte I
ao vivo. Sem essa opção, o roteiro reutiliza as chaves já geradas; se ainda
não houver chaves, ele as gera. `--detalhes` mostra os comandos executados,
as respostas da aplicação e os bytes alterados. As opções podem ser combinadas.

Cada execução salva seus arquivos em uma nova pasta `demo/saida/execucao.*`,
incluindo uma cópia das chaves usadas. Esses resultados não entram no Git.
Veja o [guia da demonstração](demo/README.md) para os passos e os testes.

## Utilização das APIs

Com a estrutura de workspaces configurada, as bibliotecas locais são tratadas pelo interpretador como pacotes instalados padrão. A importação obedece o escopo global da biblioteca e não exige manipulação do `sys.path`.

```python
from librsa import PrivateKey, PublicKey, rsa_gen_keys


def inicializar_sistema():
    priv, pub = rsa_gen_keys(2048)
    print(pub)

```

**Diretriz de Arquitetura:** A biblioteca (`librsa`) executa exclusivamente os cálculos matemáticos e a formatação de estruturas de dados. A aplicação principal (`proj02`) orquestra as chamadas, gerencia permissões restritas no sistema de arquivos e implementa a lógica de negócios de assinatura digital e verificação.
