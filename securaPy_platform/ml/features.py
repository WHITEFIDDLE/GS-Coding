"""
ML Module C - Feature Extraction.

Turns raw platform events into ONE numeric feature vector per IP. The same
extraction is used at training time (ml/treinar.py) and at inference time
(ml/classificar.py), which guarantees the model always sees features in the
same format - a critical requirement for trustworthy ML in security.

Feature vector (order defined by FEATURE_NAMES):
    auth_fails             - number of failed logins (auth / FAIL)
    distinct_blocked_ports - distinct ports blocked by the firewall (set)
    web_errors             - web requests answered with status >= 400
    web_total              - total web requests
    suspicious_urls        - web requests matching attack patterns
                             (path traversal, XSS, recon - from regras.json)
    in_blacklist           - IP present in the known blacklist (1/0)
"""

import json
import os

from core.coletor import atributos_do_evento

# Feature order is part of the model contract: training and inference MUST
# use exactly this sequence.
FEATURE_NAMES = [
    "auth_fails",
    "distinct_blocked_ports",
    "web_errors",
    "web_total",
    "suspicious_urls",
    "in_blacklist",
]

# Fallback patterns consistent with config/regras.json. The file is the
# single source of truth; these defaults keep the extractor functional if
# the config is missing or corrupted.
DEFAULT_SUSPICIOUS_PATTERNS = [
    "../", "..\\", "/etc/passwd", "/etc/shadow",
    "<script>", "javascript:", "onerror=", "onload=",
    "/wp-admin", "/phpmyadmin", "/shell.php", "/.env", "/admin", "/wp-login.php",
]


def load_suspicious_patterns(caminho_config):
    """
    Load the attack URL patterns from config/regras.json (rules R003, R004
    and R005). Falls back to DEFAULT_SUSPICIOUS_PATTERNS if unavailable.
    """
    padroes = []
    try:
        with open(caminho_config, "r", encoding="utf-8") as f:
            dados = json.load(f)
        for regra in dados.get("regras", []):
            if not regra.get("ativa", False):
                continue
            padroes.extend(regra.get("padroes", []))
            padroes.extend(regra.get("urls_suspeitas", []))
        return padroes or DEFAULT_SUSPICIOUS_PATTERNS
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return DEFAULT_SUSPICIOUS_PATTERNS


def _extract_value(evento, chave):
    """Valor estruturado do evento, reaproveitando o parser do núcleo (módulo A)."""
    return str(atributos_do_evento(evento).get(chave, ""))


def extract_features_by_ip(eventos, blacklist, padroes_suspeitos=None):
    """
    Aggregate events per IP and compute the feature dict for each IP.

    Args:
        eventos: list of normalized event dicts (from core/coletor.py)
        blacklist: SET of known malicious IPs (core/detector.py)
        padroes_suspeitos: list of attack URL patterns (regras.json)

    Returns:
        dict: {ip: {feature_name: numeric_value}} - dict/set structures
        as required by the GS data-structure quality criterion.
    """
    if padroes_suspeitos is None:
        padroes_suspeitos = DEFAULT_SUSPICIOUS_PATTERNS

    # dict of SETS - distinct ports per IP (duplicates collapse in O(1))
    portas_por_ip = {}
    # dict of dicts - counters per IP (auth fails / web totals / errors / suspicious)
    stats_por_ip = {}

    for evento in eventos:
        ip = evento.get("ip", "")
        fonte = evento.get("fonte", "")

        stats = stats_por_ip.setdefault(
            ip, {"auth_fails": 0, "web_errors": 0, "web_total": 0, "suspicious_urls": 0}
        )

        if fonte == "auth" and evento.get("tipo") == "FAIL":
            stats["auth_fails"] += 1

        elif fonte == "firewall" and evento.get("tipo") == "BLOCK":
            porta = _extract_value(evento, "dport")
            if porta:
                portas_por_ip.setdefault(ip, set()).add(porta)

        elif fonte == "web":
            stats["web_total"] += 1
            status = _extract_value(evento, "status")
            if status.isdigit() and int(status) >= 400:
                stats["web_errors"] += 1
            url = _extract_value(evento, "url")
            if any(padrao in url for padrao in padroes_suspeitos):
                stats["suspicious_urls"] += 1

    # Assemble the final feature dict for every IP seen in the logs
    features_por_ip = {}
    for ip, stats in stats_por_ip.items():
        features_por_ip[ip] = {
            "auth_fails": stats["auth_fails"],
            "distinct_blocked_ports": len(portas_por_ip.get(ip, set())),
            "web_errors": stats["web_errors"],
            "web_total": stats["web_total"],
            "suspicious_urls": stats["suspicious_urls"],
            "in_blacklist": 1 if ip in blacklist else 0,
        }
    return features_por_ip


def feature_matrix(features_por_ip):
    """
    Convert the feature dict into (matrix, ips) ready for sklearn:
    matrix shape = (n_ips, len(FEATURE_NAMES)), columns in FEATURE_NAMES order.
    """
    ips = list(features_por_ip.keys())
    matriz = [[features_por_ip[ip][nome] for nome in FEATURE_NAMES] for ip in ips]
    return matriz, ips


def vectorize_feature_dict(feature_dict):
    """Convert ONE feature dict into a single row (list) in FEATURE_NAMES order."""
    return [feature_dict[nome] for nome in FEATURE_NAMES]
