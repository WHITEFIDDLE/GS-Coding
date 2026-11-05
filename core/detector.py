"""
Core Module 3 - Threat Detector (reused from the 1st-semester GS).

Correlates multiple events to identify attack patterns that are only visible
across several lines:
  - Brute Force: many failed logins from the same IP
  - Port Scan: the same IP trying many distinct ports
  - Blacklist: IPs known to be malicious present in the logs

Threat summary format (contract between all platform modules):
{
    "ip": "185.220.101.1",
    "deteccoes": ["brute_force", "port_scan", "blacklist"],
    "pontuacao": 15,
    "severidade": "CRITICA",
    "detalhes": { ... summary of each detection ... }
}
"""

import os


def carregar_blacklist(caminho_blacklist):
    """
    Load the blacklist file (one IP per line) into a SET - the adequate
    structure for fast membership tests (O(1)) during the intersection.
    """
    blacklist = set()
    try:
        with open(caminho_blacklist, "r", encoding="utf-8") as f:
            for linha in f:
                ip = linha.strip()
                if ip:
                    blacklist.add(ip)
    except FileNotFoundError:
        print(f"[detector] WARNING: blacklist file not found: {caminho_blacklist}")
    except OSError as exc:
        print(f"[detector] WARNING: could not read blacklist: {exc}")
    return blacklist


def detectar_brute_force(eventos, threshold=5):
    """
    Identify IPs with many failed login attempts.

    Returns:
        dict: {ip: {"tentativas": N, "usuarios": [...], "severidade": "..."}}
        Only IPs with tentativas >= threshold are included.
    Severity: > 20 CRITICA | > 10 ALTA | > 5 MEDIA | >= threshold BAIXA
    """
    contagem = {}          # dict: ip -> failure count
    usuarios = {}          # dict: ip -> set of attempted users (no duplicates)

    for evento in eventos:
        if evento.get("fonte") == "auth" and evento.get("tipo") == "FAIL":
            ip = evento.get("ip")
            contagem[ip] = contagem.get(ip, 0) + 1
            usuarios.setdefault(ip, set()).add(
                _extrair_valor(evento.get("detalhes", ""), "usuario")
            )

    resultado = {}
    for ip, tentativas in contagem.items():
        if tentativas >= threshold:
            if tentativas > 20:
                severidade = "CRITICA"
            elif tentativas > 10:
                severidade = "ALTA"
            elif tentativas > 5:
                severidade = "MEDIA"
            else:
                severidade = "BAIXA"
            resultado[ip] = {
                "tentativas": tentativas,
                "usuarios": sorted(usuarios[ip]),
                "severidade": severidade,
            }
    return resultado


def detectar_port_scan(eventos, threshold=3):
    """
    Identify IPs that tried to reach many DISTINCT ports.

    Returns:
        dict: {ip: {"portas": set(...), "quantidade": N, "severidade": "..."}}
        Only IPs with unique ports >= threshold are included.
    Severity: > 10 CRITICA | > 5 ALTA | >= threshold MEDIA
    """
    portas_por_ip = {}     # dict of SETS: ip -> set of distinct destination ports

    for evento in eventos:
        if evento.get("fonte") == "firewall" and evento.get("tipo") == "BLOCK":
            ip = evento.get("ip")
            porta = _extrair_valor(evento.get("detalhes", ""), "dport")
            if porta:
                portas_por_ip.setdefault(ip, set()).add(porta)

    resultado = {}
    for ip, portas in portas_por_ip.items():
        if len(portas) >= threshold:
            if len(portas) > 10:
                severidade = "CRITICA"
            elif len(portas) > 5:
                severidade = "ALTA"
            else:
                severidade = "MEDIA"
            resultado[ip] = {
                "portas": portas,
                "quantidade": len(portas),
                "severidade": severidade,
            }
    return resultado


def verificar_blacklist(eventos, blacklist):
    """
    Cross-reference the IPs found in the events with the known blacklist.

    Returns:
        tuple: (ips_encontrados, contagem_por_ip)
        - ips_encontrados (set): IPs present in BOTH the events and the blacklist
        - contagem_por_ip (dict): {ip: number_of_events} for each blacklisted IP
    """
    ips_eventos = {evento.get("ip") for evento in eventos}   # set comprehension
    ips_encontrados = ips_eventos & blacklist                # set intersection

    contagem_por_ip = {ip: 0 for ip in ips_encontrados}
    for evento in eventos:
        if evento.get("ip") in ips_encontrados:
            contagem_por_ip[evento["ip"]] += 1

    return ips_encontrados, contagem_por_ip


def gerar_resumo_ameacas(brute_force, port_scan, blacklist_resultado):
    """
    Consolidate every detection into one unified threat summary.

    Score rule: brute_force = 5 pts, port_scan = 5 pts, blacklist = 5 pts
    (IPs detected by multiple detectors accumulate the score).
    Returns a list of threats sorted by score (highest first).
    """
    blacklist_ips, contagem_blacklist = blacklist_resultado
    todos_ips = set(brute_force.keys()) | set(port_scan.keys()) | set(blacklist_ips)

    ameacas = []
    for ip in todos_ips:
        deteccoes, detalhes, pontuacao = [], {}, 0

        if ip in brute_force:
            deteccoes.append("brute_force")
            pontuacao += 5
            detalhes["brute_force"] = {
                "tentativas": brute_force[ip]["tentativas"],
                "usuarios": brute_force[ip]["usuarios"],
            }
        if ip in port_scan:
            deteccoes.append("port_scan")
            pontuacao += 5
            detalhes["port_scan"] = {
                "quantidade_portas": port_scan[ip]["quantidade"],
                "portas": sorted(port_scan[ip]["portas"]),
            }
        if ip in blacklist_ips:
            deteccoes.append("blacklist")
            pontuacao += 5
            detalhes["blacklist"] = {"eventos": contagem_blacklist.get(ip, 0)}

        ameacas.append({
            "ip": ip,
            "deteccoes": deteccoes,
            "pontuacao": pontuacao,
            "severidade": classificar_severidade_ameaca(pontuacao),
            "detalhes": detalhes,
        })

    # Deterministic ordering: highest score first; ties broken by the number
    # of distinct detections, then alphabetically by IP (stable output).
    return sorted(
        ameacas,
        key=lambda ameaca: (-ameaca["pontuacao"], -len(ameaca["deteccoes"]), ameaca["ip"]),
    )


def classificar_severidade_ameaca(pontuacao):
    """Severity of a consolidated threat based on its total score."""
    if pontuacao >= 15:
        return "CRITICA"
    if pontuacao >= 10:
        return "ALTA"
    if pontuacao >= 5:
        return "MEDIA"
    return "BAIXA"


def _extrair_valor(detalhes, chave):
    """Extract the value of 'chave=value' from a details string."""
    for parte in detalhes.split():
        if parte.startswith(f"{chave}="):
            return parte.split("=", 1)[1]
    return ""


def executar_pipeline_deteccao(diretorio_logs, caminho_config, caminho_blacklist):
    """
    Convenience orchestration of the whole 1st-semester core pipeline:
    logs -> events -> rules -> detections -> threat summary.
    Returns (eventos, alertas, ameacas).
    """
    from core import coletor, regras

    eventos = coletor.carregar_todos_os_logs(diretorio_logs)
    regras_ativas = regras.carregar_regras(caminho_config)
    alertas = regras.aplicar_regras(eventos, regras_ativas)

    blacklist = carregar_blacklist(caminho_blacklist)
    brute_force = detectar_brute_force(eventos)
    port_scan = detectar_port_scan(eventos)
    blacklist_resultado = verificar_blacklist(eventos, blacklist)
    ameacas = gerar_resumo_ameacas(brute_force, port_scan, blacklist_resultado)

    return eventos, alertas, ameacas
