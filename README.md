# SecuraPy Platform — Minha parte: Módulos C + E + G

> **Disciplina:** Coding for Security · **Trabalho:** GS 2º semestre — SIEM como Plataforma de Segurança
> **Escopo deste repositório:** os três módulos sob minha responsabilidade, com um **núcleo mínimo funcional** (reaproveitado do 1º semestre) para rodar ponta a ponta.

| Integrante | Responsabilidade | Módulos |
| --- | --- | --- |
| *(preencher: nome do integrante)* | **Machine Learning** | **Módulo C** — treino, métricas, integridade, score de risco, anomalias |
| *(preencher: nome do integrante)* | **Web + LLM** | **Módulo E** — dashboard seguro (XSS, headers, login, logging) e **Módulo G** — assistente LLM |
| *(colegas de equipe)* | Núcleo + Persistência | Módulos A e B |
| *(colegas de equipe)* | API + Docker | Módulos D e F |

> **Nota sobre idioma:** os arquivos que **já tinham nome definido pela GS** (`treinar.py`, `classificar.py`, `modelo.pkl`, `assistente.py`, `coletor.py`, `regras.py`, `detector.py`) mantêm os nomes/contratos do enunciado para o professor localizar direto; o **código interno** (comentários, docstrings, variáveis) está em **inglês**, e a interface web + este README estão em **português**.

---

## 1. O que foi entregue

```
securaPy_platform/
├── core/                        # NÚCLEO mínimo funcional (contratos do 1º sem)
│   ├── coletor.py               #   eventos normalizados dos 3 logs
│   ├── regras.py                #   motor de regras -> alertas
│   └── detector.py              #   brute force, port scan, blacklist, resumo
│
├── ml/                          # ★ MÓDULO C — Machine Learning (Aulas 4, 12)
│   ├── features.py              #   extração de features por IP (única fonte)
│   ├── treinar.py               #   Pipeline + validação cruzada + joblib + SHA-256  (C1)
│   ├── modelo.pkl               #   modelo persistido (entregável 5)
│   ├── modelo.sha256            #   hash de integridade SHA-256                  (C4)
│   ├── relatorio_metricas.json  #   precisão/recall/F1 (entregável 5)
│   ├── dataset_treino.csv       #   dataset usado no treino (reprodutibilidade)
│   ├── classificar.py           #   carrega modelo COM verificação de hash + score (C2, C3)
│   └── anomalias.py             #   bônus: Isolation Forest (+0,30)
│
├── ia/                          # ★ MÓDULO G — Assistente LLM (Aula 13)
│   └── assistente.py            #   classificação NORMAL/SUSPEITO/CRÍTICO + explicação,
│                                #   fallback por regras (modo mock aceito pela GS)
│
├── web/                         # ★ MÓDULO E — Dashboard seguro (Aula 8)
│   ├── dashboard.py             #   Flask: rotas, headers, login, logging (A09)
│   ├── usuarios.py              #   PBKDF2-SHA256, anti-enumeração; CLI `python web/usuarios.py add`
│   ├── providers.py             #   DataProvider plugável (memória ↔ MongoDB do Módulo B)
│   ├── templates/               #   Jinja2 com escaping total (defesa XSS)
│   └── static/style.css
│
├── config/
│   ├── regras.json              # regras do 1º sem (fonte única dos padrões de ataque)
│   ├── blacklist.txt            # 3 IPs maliciosos conhecidos
│   └── usuarios.json            # operadores (apenas hashes, nunca senhas)
├── logs/                        # auth.log, firewall.log, web_access.log (dados da GS)
├── tests/                       # pytest: C1–C4, E1–E4, G1–G4 + extras (bônus testes)
├── requirements.txt
└── README.md
```

---

## 2. Como executar (sem Docker — integração depois via Módulo F)

```bash
# 1) dependências
pip install -r requirements.txt

# 2) treinar e avaliar o modelo (C1) — imprime precisão/recall/F1 e salva modelo.pkl + hash
python ml/treinar.py

# 3) classificar os IPs dos logs (C2/C3) e verificar a integridade (C4)
python ml/classificar.py
python ml/classificar.py --ip 185.220.101.1     # relatório detalhado de um IP

# 4) bônus: anomalias com Isolation Forest
python ml/anomalias.py

# 5) subir o dashboard seguro (Módulo E)
python web/dashboard.py
# -> http://127.0.0.1:5000  (redireciona para o login)

# 6) testes automatizados (cenários oficiais da GS)
python -m pytest tests/ -v
```

**Credenciais de desenvolvimento** (troque em produção com `python web/usuarios.py add`):

| Login | Senha | Nível |
| --- | --- | --- |
| `admin` | `SecuraPy@2025` | 5 |
| `analista` | `Analista@2025` | 3 |

Variáveis de ambiente suportadas: `SECRET_KEY` (assinatura da sessão — em dev é gerada aleatória com aviso), `OPENAI_API_KEY` (ativa o LLM real do Módulo G), `OPENAI_MODEL` (default `gpt-4o-mini`), `SECURAPY_ACCESS_LOG` (caminho do log de acesso).

---

## 3. Cenários de teste da GS — como são atendidos

### Módulo C — Machine Learning

| # | Cenário | Como validar | Status |
| --- | --- | --- | --- |
| C1 | Treinar e avaliar | `python ml/treinar.py` imprime **precisão, recall e F1** de 5-fold CV; relatório também em `ml/relatorio_metricas.json` | ✅ (P≈1,00 / R≈0,99 / F1≈0,99) |
| C2 | `185.220.101.1` (11 FAILs + port scan + blacklist) | score **1.0000 → nível ALTO / rótulo "ataque"** | ✅ |
| C3 | `192.168.1.10` (tráfego interno normal) | score 0,0034 → rótulo **"normal"** | ✅ |
| C4 | Integridade do modelo | `classificar.py` recalcula o **SHA-256** e compara com `modelo.sha256`; arquivo alterado → `ModelIntegrityError` (fail closed) | ✅ (testado no pytest) |
| Bônus | Anomalias | `ml/anomalias.py`: Isolation Forest treinado **só em tráfego benigno** marca os 3 atacantes como outliers | ✅ (+0,30) |

**Decisões de projeto do ML** (importante para a apresentação):
- O dataset real tem **7 IPs** — insuficiente para treino/validação cruzada. O `treinar.py` **aumenta os dados** com amostras sintéticas ancoradas nas distribuições reais (300 por classe + os 7 IPs reais rotulados). O CSV do dataset é salvo para auditoria.
- Features por IP: nº de FAILs no auth, nº de **portas distintas** bloqueadas (set), erros web (status ≥ 400), total web, URLs com padrão de ataque (de `regras.json`) e presença na blacklist (dict + set, critério de qualidade da GS).
- Pipeline exigido: `StandardScaler + LogisticRegression` dentro de `sklearn.Pipeline`; seed fixa (42) para reprodutibilidade.

### Módulo E — Segurança Web / Dashboard

| # | Cenário | Como validar | Status |
| --- | --- | --- | --- |
| E1 | Alerta com `<script>alert(1)</script>` | Formulário em **/alertas** (com CSRF); Jinja2 escapa → texto literal na tela, script **não executa**; CSP bloqueia inline | ✅ |
| E2 | Headers de segurança | `after_request` injeta em **toda** resposta: `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy` (+ `Referrer-Policy`) | ✅ |
| E3 | Senha errada × usuário inexistente | **Mesma mensagem genérica** "Credenciais inválidas." + **mesmo 401**; PBKDF2-SHA210k… 210k iterações + tempo de resposta equalizado (anti-enumeração) | ✅ |
| E4 | Logging de acesso (OWASP A09) | Cada requisição gera linha em `logs/access.log` (IP, método, path, status, usuário, duração) + tentativas de login | ✅ |

Extras de segurança: cookie de sessão `HttpOnly` + `SameSite=Lax`, `SECRET_KEY` de ambiente, CSRF no formulário, validação de IP com `ipaddress`, limite de tamanho de request, handlers 400/404/500 **sem vazar traceback**.

### Módulo G — Assistente LLM

| # | Cenário | Como validar | Status |
| --- | --- | --- | --- |
| G1 | `GET /../../etc/passwd` | **CRÍTICO** + explicação (path traversal) | ✅ |
| G2 | Acesso interno normal | **NORMAL** | ✅ |
| G3 | Sem API key | modo **mock** (fallback por regras), interface idêntica, não quebra; falha da API → fallback automático | ✅ |
| G4 | Prompt injection | entrada tratada como **dado** (delimitada no prompt + instrução de ignorar); padrões de injection → no mínimo **SUSPEITO**; saída validada contra rótulos fixos | ✅ |

Boas práticas: `OPENAI_API_KEY` só de ambiente, `temperature=0.1`, `max_tokens` baixo, **payload sanitizado e truncado** (sem linha bruta/dados sensíveis), saída validada contra `{NORMAL, SUSPEITO, CRÍTICO}` antes de qualquer uso.

---

## 4. Pontos de integração com os módulos dos colegas

| Módulo do colega | Como conecta na minha parte |
| --- | --- |
| **B — MongoDB** (`mongo_repo.py`) | O dashboard consome dados **só via `DataProvider`** (`web/providers.py`). Quando o MongoDB estiver pronto, basta instanciar `MongoDataProvider(uri, database, scores_por_ip, ...)` e passar em `criar_app(data_provider=...)` — **nenhuma linha do dashboard muda**. |
| **A — Enriquecimento** (`enriquecimento.py`) | A página de busca já tem o bloco "Enriquecimento" lendo `DataProvider.geo_do_ip(ip)`; devolve `None` hoje e mostra aviso. Plug o retorno do Módulo A (país/cidade/org) que a UI passa a exibir. |
| **D — API REST** (`app.py`) | `ml.classificar.pontuar_ips()` e `ordenar_alertas_por_risco()` são importáveis pela API (ex.: `GET /api/ip/<ip>` usa `score_do_ip`); `ia.assistente.obter_assistente()` pode ser reutilizado nas rotas de explicação. |
| **F — Docker** | `python web/dashboard.py` é o entrypoint do container web; leia `SECRET_KEY` e `OPENAI_API_KEY` do ambiente do compose. |

Contratos preservados do 1º semestre (a "cola" dos módulos): dicionário de **evento** (`timestamp, fonte, tipo, ip, detalhes, linha_original`), dicionário de **alerta** (`timestamp, regra_id, regra_nome, severidade, ip, descricao`) e **resumo de ameaças** (`ip, deteccoes, pontuacao, severidade, detalhes`).

## 5. O que foi reaproveitado do 1º semestre

- **Contratos de evento/alerta/ameaça** e assinaturas das funções (`carregar_todos_os_logs`, `aplicar_regras`, `gerar_resumo_ameacas`) — o Módulo C e o dashboard consomem exatamente essas estruturas.
- **Ideia do `hashlib`** (Aula 11 do 1º sem) reaproveitada para a integridade do modelo (C4).
- **Dados de teste** `logs/` e `config/regras.json` idênticos aos da GS anterior (58 eventos: 23 auth + 17 firewall + 18 web).

## 6. Resultados de referência (seed 42)

```
CV 5-fold : precision 1.0000 · recall 0.9967 · F1 0.9983
IPs reais : 7/7 corretos
185.220.101.1 -> score 1.0000 (ALTO, ataque) | anomalia sim (1.0)
192.168.1.10  -> score 0.0034 (BAIXO, normal) | anomalia não
pytest        : 24 passed
```
