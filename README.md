# SecuraPy Platform — entrega da Pessoa 1

**Responsabilidade: módulos A (núcleo) e B (persistência).**

Integrante: **Lucas — preencher nome completo e RM antes da entrega acadêmica**.

Esta pasta pode ser integrada ao projeto do grupo. O núcleo segue os contratos
dos esqueletos publicados pelo professor; a implementação das funções foi feita
nesta entrega, pois os arquivos de referência ainda contêm `pass`.

## O que está implementado

- Leitura e normalização dos três logs originais.
- Regras configuráveis, brute force, port scan e blacklist.
- Servidor TCP com vários consoles, histórico e publicação de alertas críticos.
- Enriquecimento opcional de IP, com cache e tratamento de falha externa.
- MongoDB: eventos, alertas, filtros, paginação, agregação e índices.
- MySQL: CRUD de usuários, e-mail único, nível 1–5 e autenticação com hash.
- Ingestão inicial e relatório JSON, com repetição sem duplicar os mesmos registros.
- Testes de núcleo, erros, sockets e integração com bancos reais.

API REST, tokens da API, ML, dashboard e assistente LLM são responsabilidade
dos outros integrantes. O Compose incluído sobe somente os bancos para apoiar
o desenvolvimento dos módulos A/B. Ele não substitui o módulo F da GS.

## Integração com a branch `Machine_learning` (módulos C, E e G)

Os módulos de ML, dashboard e assistente foram integrados dentro de
`securaPy_platform/` e passam a usar o núcleo e a configuração desta branch:

| Pasta | Módulo | Observação |
|---|---|---|
| `ml/` | C — treino, métricas, hash SHA-256, score de risco, Isolation Forest | features lidas via `core.coletor.atributos_do_evento` |
| `web/` | E — dashboard, XSS, headers, login com hash, log de acesso | eventos/alertas vêm de `servicos.analise.analisar_pasta` |
| `ia/` | G — assistente com validação de rótulos e fallback (modo mock) | sem alteração |
| `logs/` | dados de teste originais da GS do 1º semestre | 58 linhas (23 + 17 + 18) |

Duplicatas descartadas na integração (mantida a versão desta branch):
`core/` da raiz, `config/regras.json` e `config/blacklist.txt` (substituído por
`config/blacklist.json`) e o `requirements.txt` da raiz (dependências somadas ao
`securaPy_platform/requirements.txt`). O login do dashboard ainda usa
`config/usuarios.json`; o repositório MySQL (`db/mysql_repo.py`) já oferece
`autenticar()` para substituí-lo quando a API/integração final for feita.

```powershell
.\.venv\Scripts\python.exe ml\treinar.py      # C1: treina e imprime precisão/recall/F1
.\.venv\Scripts\python.exe ml\classificar.py  # C2/C3/C4: score por IP com hash verificado
.\.venv\Scripts\python.exe web\dashboard.py   # E: http://127.0.0.1:5000
```

**Pendente:** módulos D (API REST com token) e F (Dockerfile, docker-compose
com API + MongoDB + MySQL e verificação pelo SDK) ainda não foram entregues.

## Executar no PowerShell

Requisitos: Python 3.10+ (apostila recomenda 3.11+) e Docker Desktop em execução.

```powershell
cd securaPy_platform
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe baixar_logs.py
Copy-Item .env.example .env
# Edite o .env e escolha as senhas e o token antes de iniciar os bancos.
```

Copie `.env.example` para `.env` e escolha novas senhas e token.
O `.env` com credenciais não é versionado.
Mudar a senha no `.env` não altera automaticamente usuários de um volume MySQL já inicializado.

```powershell
docker compose -p gs-verdadeira-ab -f compose.bancos.yaml up -d --wait
.\.venv\Scripts\python.exe main.py preparar-bancos
.\.venv\Scripts\python.exe main.py analisar --saida relatorios\analise_local.json
.\.venv\Scripts\python.exe migrar_logs.py --saida relatorios\exemplo.json
.\.venv\Scripts\python.exe main.py resumo-banco
```

O comando `analisar` funciona sem bancos e não envia dados externos, a menos
que você acrescente `--enriquecer`. `migrar_logs.py` equivale a `main.py ingerir`.
A segunda ingestão do mesmo lote insere zero novos eventos e alertas.

## Consultas e usuários

```powershell
.\.venv\Scripts\python.exe main.py consultar --fonte auth --tipo FAIL --ip 185.220.101.1
.\.venv\Scripts\python.exe main.py consultar --colecao alertas --severidade critica --tamanho 5
.\.venv\Scripts\python.exe main.py consultar --inicio "2025-02-20T11:15:01Z" --fim "2025-02-20T11:15:45Z"
.\.venv\Scripts\python.exe main.py criar-usuario --nome "Seu Nome" --email "operador@example.test" --nivel 2
.\.venv\Scripts\python.exe main.py autenticar --email "operador@example.test"
.\.venv\Scripts\python.exe main.py listar-usuarios
```

A senha é solicitada sem exibição no terminal. As funções de atualização e
remoção estão em `db/mysql_repo.py` e são exercitadas nos testes; o colega da
API poderá chamá-las sem implementar SQL novamente. Criar usuário pela CLI
é uma operação administrativa local; autorização por nível cabe à camada da API.

## Demonstração TCP: quatro terminais

No primeiro terminal, inicie o servidor:

```powershell
.\.venv\Scripts\python.exe main.py servidor-alertas
```

No segundo e no terceiro, execute:

```powershell
.\.venv\Scripts\python.exe main.py cliente-alertas
```

No quarto, execute:

```powershell
.\.venv\Scripts\python.exe migrar_logs.py --publicar
```

Os dois consoles recebem os críticos. Experimente `/status`, `/historico` e
`/sair`. O token do publicador vem do `.env`, não é digitado nos consoles.
Repetir `--publicar` retransmite os críticos para demonstração, mesmo quando os
registros já existem no banco. O servidor guarda somente dez alertas em memória;
o histórico durável permanece no MongoDB. TCP local sem TLS/autenticação de
leitores: para acesso remoto seria necessário proteger o canal e os assinantes.

## Testes e evidências

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pytest -q --integracao
```

O primeiro comando pula os testes que precisam de bancos. O segundo executa
todos, incluindo bancos reais. MongoDB usa um banco temporário de teste;
MySQL usa usuários com e-mails únicos e remove somente os que criou.
Relatórios gerados ficam apenas no ambiente local; não fazem parte do repositório.

## Dados de laboratório e divergências

Os arquivos originais contêm **58 eventos: 23 auth, 17 firewall e 18 web**.
O primeiro IP tem **11 FAILs**, embora o enunciado cite 10. São sete portas
bloqueadas distintas para ele. Os logs foram preservados; a implementação
calcula os valores reais.

O detector original define ALTA para **mais de dez** falhas: dez seria MEDIA;
onze resulta em ALTA. Esta fronteira também está documentada e testada.
A pontuação combinada das ameaças segue a regra original de cinco pontos por
detecção; isso não é probabilidade ou score de ML.

Timestamps dos logs não trazem fuso. Foi adotado `LOG_TIMEZONE=America/Sao_Paulo`,
configurável. O núcleo mantém o texto original e o banco armazena datas UTC.

Para parar os bancos sem perder os volumes:

```powershell
docker compose -p gs-verdadeira-ab -f compose.bancos.yaml stop
```

As portas 13307/27019 e o projeto Compose são exclusivos desta entrega;
o CP1 existente em `GS_Coding` utiliza outros serviços.

---

## Guia detalhado da minha parte

## 1. O que você construiu

Sua parte transforma arquivos de log em eventos padronizados, identifica sinais
de ataque e guarda o resultado em bancos. Também mantém um canal TCP para
exibir alertas críticos em mais de um console.

O fluxo completo da sua parte é:

```mermaid
flowchart TD
    L[auth.log / firewall.log / web_access.log] --> C[Coletor: validar e normalizar]
    C --> E[Lista de eventos]
    E --> R[Regras: avaliar um evento]
    E --> D[Detector: correlacionar vários eventos por IP]
    R --> A[Lista de alertas]
    D --> A
    E --> M[(MongoDB: eventos)]
    A --> N[(MongoDB: alertas)]
    A --> P[Publicador: filtrar críticos]
    P --> S[Servidor TCP]
    S --> C1[Console 1]
    S --> C2[Console 2]
    U[CRUD e autenticação de operadores] --> SQL[(MySQL: usuários)]
```

Cada bloco tem uma responsabilidade. Isso permite ao colega da API chamar as
mesmas funções que a CLI usa, sem copiar lógica para as rotas.

## 2. O que foi reaproveitado

O professor forneceu formatos, docstrings, nomes de funções, regras e logs.
Nos arquivos publicados, as funções centrais ainda estão em `pass`. Portanto,
você pode dizer: "Reaproveitei o contrato e os dados do primeiro semestre e
implementei o núcleo para integrá-lo à persistência". Não afirme que um núcleo
pronto do seu grupo foi reaproveitado, se esse código não foi fornecido.

Fonte dos esqueletos: https://github.com/fabioBaraDev/coding_for_security/tree/main/GS_1Semestre/securaPy

## 3. Coletor: core/coletor.py

### Por que normalizar?

Cada fonte usa campos diferentes. Em auth, o IP vem em `ip=`. No firewall,
vem em `src=`. O restante do programa não deveria conhecer essa diferença.

Entrada de auth:

```text
2025-02-20 08:15:01 FAIL usuario=admin ip=185.220.101.1
```

Saída do parser:

```python
{
    'timestamp': '2025-02-20 08:15:01',
    'fonte': 'auth',
    'tipo': 'FAIL',
    'ip': '185.220.101.1',
    'detalhes': 'usuario=admin',
    'atributos': {'usuario': 'admin'},
    'linha_original': '2025-02-20 08:15:01 FAIL usuario=admin ip=185.220.101.1'
}
```

`detalhes` mantém a compatibilidade com o esqueleto. `atributos` evita que cada
módulo tenha de separar o mesmo texto novamente. `linha_original` preserva a
evidência recebida.

### Funções

| Função | Entrada | Trabalho e saída |
|---|---|---|
| `_separar_campos` | Linha de texto | Separa data, hora, tipo e pares chave=valor; rejeita campos repetidos |
| `_parsear` | Linha e fonte | Valida data, IP, tipo, porta/status e monta o evento; erro de formato retorna `None` |
| `parsear_linha_auth` | Linha auth | Chama o parser para autenticação |
| `parsear_linha_firewall` | Linha firewall | Usa `src` como IP de origem e converte `dport` para inteiro |
| `parsear_linha_web` | Linha web | Valida método e status HTTP, preservando a URL como dado |
| `carregar_log` | Arquivo e fonte | Lê linha a linha, ignora vazias e avisa sobre linhas inválidas |
| `carregar_todos_os_logs` | Pasta | Reúne os três arquivos conhecidos em uma lista |
| `atributos_do_evento` | Evento | Usa o dicionário novo ou recupera campos do texto antigo |

O prefixo `_` indica uma função auxiliar interna, não uma regra de segurança.

Trecho importante:

```python
chave, valor = parte.split('=', 1)
```

O `1` limita a separação ao primeiro `=`. Uma URL como `/search?q=valor` contém
outro `=`; separar sem esse limite destruiria o valor do campo.

Outro trecho:

```python
if evento is None:
    logger.warning('Linha inválida ignorada: %s, linha %d', nome, numero)
else:
    eventos.append(evento)
```

O código real usa o nome do arquivo no lugar de `nome`. O princípio é continuar
a leitura mesmo quando uma linha está ruim. A mensagem evita registrar a linha
inteira, que poderia conter informação sensível.

## 4. Regras: core/regras.py

Uma regra procura um padrão em **um evento isolado**. Por exemplo, uma URL de
path traversal já é relevante mesmo sem outras requisições.

O JSON original contém cinco regras:

| ID | Condição | Exemplo |
|---|---|---|
| R001 | Usuário privilegiado | usuario=admin |
| R002 | Porta crítica bloqueada | BLOCK com dport=22 |
| R003 | Path traversal | /../../etc/passwd |
| R004 | XSS | URL com `<script>` |
| R005 | Reconhecimento | /wp-admin |

### Funções

- `carregar_regras`: lê o JSON, valida o formato e mantém somente regras ativas.
  Em arquivo inválido retorna lista vazia e avisa. O serviço de análise recusa
  continuar sem regras, para não passar uma falsa impressão de análise completa.
- `classificar_severidade`: transforma pontos em INFO, BAIXA, MEDIA, ALTA ou
  CRITICA. Os limites são 3, 5, 7 e 9.
- `avaliar_regra`: verifica a fonte e a condição; devolve um alerta ou `None`.
- `aplicar_regras`: testa cada regra em cada evento e reúne os alertas.

O laço principal é simples:

```python
for evento in eventos:
    for regra in regras:
        alerta = avaliar_regra(regra, evento)
        if alerta is not None:
            alertas.append(alerta)
```

Um evento pode gerar mais de um alerta. Não usamos `break`, pois isso impediria
avaliar outras regras. Para E eventos e R regras, há aproximadamente E × R
avaliações; com os dados da GS, essa abordagem é suficiente e fácil de explicar.

As URLs passam por `unquote` para reconhecer também caracteres codificados.
Isso não é uma defesa completa contra todas as variações de ataque. É um motor
didático de regras, não um WAF de produção.

## 5. Detector: core/detector.py

O detector olha **um conjunto de eventos**. Uma tentativa de login isolada
pode ser comum; onze falhas do mesmo IP pedem atenção.

### detectar_brute_force

Filtra `fonte == 'auth'` e `tipo == 'FAIL'`. Cria um dicionário por IP:

```python
dados = por_ip.setdefault(evento['ip'], {'tentativas': 0, 'usuarios': set()})
dados['tentativas'] += 1
dados['usuarios'].add(atributos_do_evento(evento)['usuario'])
```

`setdefault` devolve a entrada existente ou cria o valor inicial. O contador
mede todas as falhas; o `set` guarda cada usuário só uma vez.

No retorno, os usuários viram lista ordenada para poder exportar JSON.
O limite padrão de detecção é cinco falhas. A severidade segue o esqueleto:
5 → BAIXA; 6–10 → MEDIA; 11–20 → ALTA; 21+ → CRITICA.

**Divergência para explicar:** o arquivo original tem onze falhas do primeiro
IP. O cenário do enunciado diz dez. Preservamos o log e testamos onze.

### detectar_port_scan

Filtra firewall BLOCK e usa um conjunto de portas por IP:

```python
portas_por_ip.setdefault(evento['ip'], set()).add(int(atributos_do_evento(evento)['dport']))
```

Vinte bloqueios na porta 22 continuam sendo **uma porta distinta**. O `set`
evita confundir repetição de tentativa com varredura de várias portas.
O primeiro IP tem sete portas: 21, 22, 23, 139, 445, 3306 e 8080.

### verificar_blacklist

```python
encontrados = {evento['ip'] for evento in eventos} & set(blacklist)
```

`&` é interseção de conjuntos: seleciona quem aparece nos logs **e** está na
blacklist. Um `Counter` conta quantos eventos esses IPs geraram.

### gerar_resumo_ameacas

Une os IPs encontrados pelos três detectores. Cada detecção soma cinco pontos:
brute force + port scan + blacklist = 15. Depois ordena do maior para o menor.

Essa pontuação é uma regra explícita, não aprendizado de máquina. O colega do
módulo C implementará um score separado para o modelo.

### Limite importante

A contagem considera todo o lote, sem janela temporal. Correlação temporal é
um bônus separado na GS. Não diga que a implementação detecta "cinco falhas por
minuto": ela detecta cinco falhas no conjunto analisado.

## 6. Serviço de análise: servicos/analise.py

`carregar_blacklist` lê uma lista JSON e valida os IPs.

`analisar_eventos` coordena as chamadas: brute force, port scan, blacklist,
resumo e regras. Em seguida cria um alerta de correlação para cada ameaça.
O retorno tem três listas: `eventos`, `alertas` e `ameacas`.

`analisar_pasta` é o atalho que carrega configurações e arquivos antes de chamar
`analisar_eventos`. A API poderá usar a função de eventos para receber um lote
sem precisar gravar um arquivo intermediário.

O serviço não importa Flask nem consulta bancos. Isso permite testar o núcleo
sozinho e reutilizá-lo em CLI, API ou outro processo.

## 7. Por que dois bancos?

```text
MongoDB                         MySQL
eventos e alertas               usuários
campos variam por fonte         estrutura previsível
documentos com atributos       e-mail único + nível válido
filtros e agregações            credenciais e CRUD parametrizado
```

Isso segue a arquitetura da GS. Não significa que MongoDB não tenha transações
ou que MySQL seja incapaz de guardar JSON. São escolhas do projeto para aprender
as duas formas de persistência.

## 8. Conversões: db/documentos.py

### data_utc

Aceita `datetime` ou texto ISO. Se faltar fuso, aplica LOG_TIMEZONE. Converte
para UTC. Por exemplo, 08:15:01 de São Paulo vira 11:15:01 UTC naquele dia.
Assim, o MongoDB pode filtrar datas reais, sem comparar strings de formatos
diferentes.

### para_json

Percorre dicionários e listas. Converte `ObjectId` para texto e `datetime`
para ISO. Renomeia `_id` para `id` na resposta pública.

### preparar_documento

Valida campos obrigatórios, copia o documento sem alterar o original, normaliza
IP e data, valida severidade e calcula uma chave SHA-256 determinística.

```python
texto = json.dumps(para_json(identidade), sort_keys=True,
                   ensure_ascii=False, separators=(',', ':'))
novo['chave_' + tipo] = hashlib.sha256(texto.encode('utf-8')).hexdigest()
```

`sort_keys=True` garante a mesma ordem das chaves antes do hash. O hash aqui serve
como identidade de deduplicação. Não criptografa o log e não deve ser usado
sozinho para guardar senha.

## 9. MongoDB: db/mongo_repo.py

`RepositorioMongo` mantém o cliente e as coleções. `__enter__` / `__exit__`
permitem usar `with`, garantindo o fechamento. `fechar` encerra o cliente.

### preparar

Confere conexão com `ping`; cria índices em `ip`, `timestamp` e nas chaves
únicas. Alertas também recebem índice de severidade. Repetir esse preparo
não apaga os documentos.

Índice custa espaço e trabalho nas escritas, mas permite localizar dados sem
necessariamente varrer a coleção inteira. Não afirmamos ter medido um ganho
de desempenho com apenas 58 eventos.

### salvar_eventos / salvar_alertas / _salvar

Os métodos públicos chamam `_salvar`, que valida o lote e envia operações:

```python
UpdateOne({chave: doc[chave]}, {'$setOnInsert': doc}, upsert=True)
```

Leitura dessa linha:

1. Procure a chave calculada.
2. Se ela já existe, não insira outro documento.
3. Se não existe, insira o documento novo.

O índice único reforça essa identidade no banco. Na primeira ingestão são
inseridos 58 eventos; na segunda, zero. Os dados anteriores continuam lá.

Limite: duas linhas exatamente iguais no mesmo instante são tratadas como o
mesmo evento. Em um coletor real, um ID da origem ou offset do arquivo ajudaria
a distinguir repetições legítimas.

### _filtro / _buscar / buscar_eventos / buscar_alertas

`_filtro` valida os valores e monta um dicionário seguro de consulta. `_buscar`
aplica ordenação, `skip`, `limit` e contagem. Os métodos públicos escolhem a coleção.

```python
repo.buscar_eventos(fonte='auth', tipo='FAIL', ip='185.220.101.1',
                    pagina=1, tamanho=5)
```

Esse filtro encontra onze documentos no total e devolve só cinco na primeira
página. Paginação não significa que os outros foram apagados.

### buscar_alerta

Valida o ID antes de construir um ObjectId. ID malformado gera `ValueError`;
ID válido ausente retorna `None`. A API decide se deve responder 400 ou 404.

### top_ips / contar_por_severidade / contar_por_fonte

Usam pipelines de agregação no MongoDB. A contagem ocorre no banco.

```python
{'$group': {'_id': '$ip', 'total': {'$sum': 1}}}
```

`$group` reúne documentos pelo IP. `$sum: 1` soma uma unidade por documento.
Depois `$sort` ordena e `$limit` limita o resultado.

O primeiro IP tem 25 eventos ao somar as três fontes. Esse ranking é por
**volume**, não por risco. A API/dashboard precisam usar ML para ranking de risco.

### tratar_erros_mongo

É um decorator: envolve operações e converte erros do driver em
`ErroPersistencia`, com mensagem pública genérica. `@wraps` preserva o nome e
metadados da função original. Erros de validação continuam sendo `ValueError`.

## 10. MySQL: db/mysql_repo.py e sql/001_usuarios.sql

A tabela tem ID automático, nome, e-mail único, hash da senha, nível 1–5 e data
de criação. O `CHECK` impede nível fora da faixa mesmo em SQL direto.

### Conexões e transações

`_cursor` é um context manager criado com `@contextmanager`. Abre conexão,
entrega um cursor e fecha tudo no final. Nas escritas faz `commit`; em erro
de banco tenta `rollback`. O schema usa InnoDB.

```text
abrir conexão → executar SQL → sucesso? → commit
                              erro?    → rollback
                   sempre → fechar cursor e conexão
```

`preparar` lê o arquivo SQL e cria a tabela se ela ainda não existir. Não apaga
usuários já existentes.

### Validações auxiliares

- `_validar_id`: inteiro positivo; rejeita inclusive bool.
- `_validar_nome`: texto não vazio, até cem caracteres.
- `_validar_email`: formato básico, até 254 caracteres, remove espaços externos
  e normaliza para minúsculas. Não verifica se a caixa postal realmente existe.
- `_validar_nivel`: inteiro de 1 a 5.
- `_hash_senha`: valida tamanho de 10 a 128 e gera hash scrypt com salt.
- `_hash_ficticio`: hash reutilizado para verificar uma senha mesmo quando o
  e-mail não existe; aproxima o trabalho dos dois caminhos, sem prometer tempo constante.

### criar_usuario

```python
cursor.execute(
    'INSERT INTO usuarios (nome,email,senha_hash,nivel_acesso) VALUES (%s,%s,%s,%s)',
    valores,
)
```

Os `%s` são placeholders do driver. A SQL e os valores são enviados separados.
Não é formatação de string com `%`; não coloque aspas em volta dos placeholders.
O retorno contém os dados públicos, não o hash.

Se o e-mail já existe, o erro 1062 vira `UsuarioDuplicado`. Os testes também
provam que é possível continuar usando o repositório depois dessa falha.

### buscar_usuario / listar_usuarios

Selecionam apenas ID, nome, e-mail e nível. A listagem é paginada. ID válido
não encontrado retorna `None`.

### atualizar_usuario

Aceita apenas nome, e-mail, senha e nível como argumentos nomeados. Monta as
atribuições com nomes internos de coluna; todos os valores continuam em
parâmetros. Se mudar senha, gera outro hash. Se não houver campos, rejeita.

Não há função que aceite uma coluna arbitrária enviada pelo usuário.

### remover_usuario

Executa DELETE com ID parametrizado. Retorna `True` se removeu e `False` se o
ID já não existia. Não confunda False com erro de conexão.

### autenticar

```python
cursor.execute(
    'SELECT id,nome,email,nivel_acesso,senha_hash FROM usuarios WHERE email=%s',
    (email.strip().lower(),),
)
```

A vírgula em `(valor,)` cria uma tupla de um elemento. Sem a vírgula seriam
apenas parênteses em volta de uma string.

Depois o código compara a senha com `check_password_hash`. Se não achar usuário,
usa o hash fictício. Tanto usuário ausente quanto senha errada devolvem `None`.
A CLI apresenta "Credenciais inválidas"; a API fará o mesmo com status 401.

A entrada `' OR '1'='1` é tratada como texto de e-mail, não como parte da SQL.
Por isso não retorna todos os usuários nem autentica.

Autenticação confirma quem é a pessoa. Autorização decide o que ela pode fazer.
Seu módulo guarda o nível; o colega da API vai aplicar permissões e emitir tokens.

## 11. Alertas TCP: alertas/

### Por que JSONL?

TCP é um fluxo de bytes. Um `recv` pode conter metade de um JSON ou dois JSONs
juntos. Cada mensagem termina com `\\n`, e `receber_mensagens` acumula bytes até
encontrar o delimitador. Há limite de tamanho para não acumular indefinidamente.

### Funções e classe do servidor

| Função/método | Papel |
|---|---|
| `enviar_json` | Codifica UTF-8, acrescenta newline, verifica tamanho e usa sendall |
| `receber_mensagens` | Reconstrói mensagens completas e decodifica JSON |
| `formatar_alerta` | Monta a linha amigável para o console |
| `ServidorAlertas.__init__` | Valida token, cria estado e abre a porta |
| `servir` | Aceita conexões e cria uma thread por cliente, com limite |
| `_tratar` | Interpreta assinar, publicar, status, histórico e sair |
| `_enviar` | Serializa envios para uma conexão usando lock individual |
| `broadcast_alerta` | Valida crítico, guarda histórico e envia a todos os assinantes |
| `remover_cliente` | Remove da coleção compartilhada e fecha o socket |
| `fechar` | Sinaliza parada e fecha servidor e conexões |

O dicionário de clientes e o histórico são compartilhados entre threads. Um
`Lock` protege essas alterações. Cada cliente tem outro lock para impedir que
duas threads misturem bytes no mesmo socket.

`deque(maxlen=10)` mantém os dez últimos alertas sem crescer para sempre.
Um cliente que falha ao receber é removido sem impedir os demais.

### Publicador e cliente

`publicar_criticos` filtra a lista e abre uma conexão ao servidor. Para cada
crítico, envia o token e aguarda confirmação. Esse desenho resolve um problema:
a ingestão e o servidor são processos diferentes; um dicionário global no
processo da ingestão não contém os consoles do outro processo.

`conectar_servidor` abre o console e cria uma thread de recepção. Enquanto ela
ouve alertas, a thread principal lê `/status`, `/historico` e `/sair`.
`receber_alertas` converte as mensagens em texto visível.

O token autentica publicação, não leitura. A configuração padrão é localhost.
Não apresente esse canal como seguro para uma rede pública: faltam TLS e
controle de acesso de leitores. Isso está fora da demonstração local.

## 12. Enriquecimento: core/enriquecimento.py

`eh_ip_privado` usa a biblioteca ipaddress. `consultar_ip` valida o IP, usa o
cache quando existe e consulta ipinfo somente para endereços globais. A
requisição tem timeout. Falhas resultam em valores "Desconhecido".

`enriquecer_alertas` cria cópias dos alertas com a geolocalização. O núcleo
funciona sem Internet; na CLI, você precisa pedir `--enriquecer` explicitamente.
O cache atual vive em memória durante a sessão, sem TTL ou persistência.

## 13. Ingestão e CLI

`persistir_analise` chama `salvar_eventos` e `salvar_alertas` e devolve contagens.
São duas operações, não uma transação distribuída. Se a segunda falhar, os
eventos podem já estar salvos. A reexecução idempotente permite completar o lote.

Em `main.py`:

- `montar_parser` define os comandos e argumentos.
- `executar` escolhe o serviço, consulta ou demonstração correspondente.
- `exibir` serializa a saída em JSON legível.
- `main` configura logging, interpreta argumentos e trata os erros esperados.

`migrar_logs.py` é um atalho: insere `ingerir` na lista de argumentos e chama a
mesma função principal. Não há uma segunda implementação da ingestão.

Os segredos ficam no `.env`, carregado por `configuracao.py`. As funções
`configuracao_mysql` e `configuracao_mongo` devolvem opções de conexão. Importar
os módulos não inicia servidor ou banco.

## 14. O que os testes demonstram

Os testes puros cobrem parsing, dados originais, regras, severidades, sets,
datas UTC, hash de identidade, fallback externo e protocolo TCP.

Os testes de integração usam bancos reais para conferir ingestão duplicada,
filtros, paginação, agregações, índices, CRUD, hash de senha, duplicatas,
SQL Injection e restrição de nível. Também verificam erros de conexão.

O teste TCP abre dois consoles reais via socket na mesma máquina, publica um
alerta e confere o recebimento em ambos. Outro teste envia JSON em pedaços,
demonstrando que o código não depende de um recv por mensagem.

Passar nos testes não garante ausência de defeitos. As evidências confirmam
esses cenários e ainda precisam ser complementadas pela integração do grupo.

## 15. Roteiro sugerido para sua fala

1. "Minha responsabilidade é núcleo e persistência, módulos A e B."
2. Mostre uma linha auth e o evento normalizado.
3. Explique a diferença entre regra de um evento e correlação de vários.
4. Mostre o `set` das portas e a interseção da blacklist.
5. Execute a ingestão e mostre as 58 entradas; repita e mostre zero novos.
6. Execute o resumo do banco e a busca por IP.
7. Mostre os placeholders `%s`, o UNIQUE de e-mail e a senha em hash.
8. Abra dois consoles e publique críticos.
9. Mostre os testes e os contratos entregues aos colegas.

## 16. Perguntas que você deve saber responder

**Por que set nas portas?** Para contar portas diferentes, não quantidade total
de tentativas para a mesma porta.

**Por que dict por IP?** Para reunir contadores e conjuntos sob uma chave comum.

**Por que o hash SHA-256 não é a senha?** Aqui ele identifica documentos;
senhas usam scrypt, com salt e custo de computação apropriado.

**O que acontece se o banco cair?** O repositório gera ErroPersistencia; o
chamador decide a resposta. A CLI apresenta erro e encerra com código não zero.

**E se o TCP cair depois da gravação?** Os registros permanecem no banco e a
CLI avisa. Não há fila durável de entrega; repetir a publicação é manual.

**O índice garante que toda consulta será instantânea?** Não. Ajuda buscas
adequadas; o plano e o volume influenciam. Não medimos desempenho de produção.

**Por que onze falhas se o enunciado diz dez?** Porque contamos o arquivo
original sem adulterá-lo e registramos a divergência.

**O score 15 já é ML?** Não. São três detecções de cinco pontos, calculadas por
regras. O colega responsável por ML adicionará a saída do modelo.

**Está pronto para produção?** É uma entrega de laboratório dos módulos A/B.
A plataforma final depende dos outros módulos e de controles adicionais.

**Eu posso dizer que programei tudo sozinho?** Explique com honestidade o uso
de assistência e mostre que compreende as decisões. O objetivo deste guia é
permitir que você leia, modifique e defenda o código, não apenas o execute.
