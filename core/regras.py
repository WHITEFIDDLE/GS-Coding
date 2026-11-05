"""
Core Module 2 - Rules Engine (reused from the 1st-semester GS).

Loads detection rules from a JSON file, evaluates every event against the
active rules and generates alerts whenever a rule is violated.

Alert format (contract between all platform modules):
{
    "timestamp": "2025-02-20 08:15:01",
    "regra_id": "R001",
    "regra_nome": "Login com Usuario Privilegiado",
    "severidade": "MEDIA",
    "ip": "185.220.101.1",
    "descricao": "Tentativa de login com usuario admin"
}

Severity levels (based on the numeric score):
    >= 9: CRITICA | >= 7: ALTA | >= 5: MEDIA | >= 3: BAIXA | < 3: INFO
"""

import json


def carregar_regras(caminho_config):
    """
    Read regras.json and return the list of ACTIVE rules.

    Returns [] if the file does not exist or the JSON is invalid
    (a broken config must never crash the platform).
    """
    try:
        with open(caminho_config, "r", encoding="utf-8") as f:
            dados = json.load(f)
    except FileNotFoundError:
        print(f"[regras] ERROR: rules file not found: {caminho_config}")
        return []
    except json.JSONDecodeError as exc:
        print(f"[regras] ERROR: invalid JSON in {caminho_config}: {exc}")
        return []

    regras = dados.get("regras", [])
    return [r for r in regras if r.get("ativa", False)]


def classificar_severidade(pontuacao):
    """
    Convert a numeric score into a severity level string.
    Mapping: >= 9 CRITICA | >= 7 ALTA | >= 5 MEDIA | >= 3 BAIXA | < 3 INFO
    """
    if pontuacao >= 9:
        return "CRITICA"
    if pontuacao >= 7:
        return "ALTA"
    if pontuacao >= 5:
        return "MEDIA"
    if pontuacao >= 3:
        return "BAIXA"
    return "INFO"


def _extrair_valor(detalhes, chave):
    """Extract the value of 'chave=value' from a details string."""
    for parte in detalhes.split():
        if parte.startswith(f"{chave}="):
            return parte.split("=", 1)[1]
    return ""


def avaliar_regra(regra, evento):
    """
    Evaluate whether one event violates one specific rule.

    Returns:
        dict: alert generated if the rule was violated
        None: if the event does not violate the rule
    """
    # The rule only applies to events of its own source
    if evento.get("fonte") != regra.get("fonte"):
        return None

    condicao = regra.get("condicao")
    detalhes = evento.get("detalhes", "")
    violou = False

    if condicao == "usuario_privilegiado":
        usuario = _extrair_valor(detalhes, "usuario")
        violou = usuario in regra.get("usuarios_alvo", [])
    elif condicao == "porta_critica":
        porta = _extrair_valor(detalhes, "dport")
        violou = porta.isdigit() and int(porta) in regra.get("portas_criticas", [])
    elif condicao == "path_traversal":
        url = _extrair_valor(detalhes, "url")
        violou = any(padrao in url for padrao in regra.get("padroes", []))
    elif condicao == "xss":
        url = _extrair_valor(detalhes, "url")
        violou = any(padrao in url for padrao in regra.get("padroes", []))
    elif condicao == "reconhecimento":
        url = _extrair_valor(detalhes, "url")
        violou = any(padrao == url or padrao in url
                     for padrao in regra.get("urls_suspeitas", []))

    if not violou:
        return None

    return {
        "timestamp": evento.get("timestamp"),
        "regra_id": regra.get("id"),
        "regra_nome": regra.get("nome"),
        "severidade": classificar_severidade(regra.get("severidade_base", 3)),
        "ip": evento.get("ip"),
        "fonte": evento.get("fonte"),
        "descricao": f"{regra.get('descricao')} | {detalhes}".strip(" |"),
    }


def aplicar_regras(eventos, regras):
    """
    Apply every rule to every event and return the list of generated alerts.
    One event may generate multiple alerts (if it violates several rules).
    """
    alertas = []
    for evento in eventos:
        for regra in regras:
            alerta = avaliar_regra(regra, evento)
            if alerta is not None:
                alertas.append(alerta)
    return alertas
