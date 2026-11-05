"""
Core Module 1 - Log Collector (reused from the 1st-semester GS).

Reads log files from different sources (auth, firewall, web), parses each line
and normalizes the events into a standardized dict format.

Standardized event format (the "glue" contract between all platform modules):
{
    "timestamp": "2025-02-20 08:15:01",
    "fonte": "auth",              # auth | firewall | web
    "tipo": "FAIL",               # OK | FAIL | BLOCK | ALLOW | GET | POST | DELETE
    "ip": "185.220.101.1",
    "detalhes": "usuario=admin",  # extra info depending on the source
    "linha_original": "..."       # raw log line
}

This implementation keeps the 1st-semester function names/signatures so the
rest of the platform (db, api, ml, web, ia) can consume events unchanged.
"""

import os

# Mapping between logical sources and their log file names
LOG_FILES = {
    "auth": "auth.log",
    "firewall": "firewall.log",
    "web": "web_access.log",
}


def parsear_linha_auth(linha):
    """
    Parse one auth.log line and return a normalized event dict.

    Expected line format:
        "2025-02-20 08:15:01 FAIL usuario=admin ip=185.220.101.1"

    Returns:
        dict with keys: timestamp, fonte, tipo, ip, detalhes, linha_original
        None if the line has an invalid format.
    """
    parts = linha.split()
    if len(parts) < 4:
        return None

    timestamp, tipo = f"{parts[0]} {parts[1]}", parts[2]
    usuario, ip = None, None
    for part in parts[3:]:
        if part.startswith("usuario="):
            usuario = part.split("=", 1)[1]
        elif part.startswith("ip="):
            ip = part.split("=", 1)[1]

    if not ip or not timestamp.startswith("20"):
        return None

    return {
        "timestamp": timestamp,
        "fonte": "auth",
        "tipo": tipo,
        "ip": ip,
        "detalhes": f"usuario={usuario}" if usuario else "",
        "linha_original": linha.strip(),
    }


def parsear_linha_firewall(linha):
    """
    Parse one firewall.log line and return a normalized event dict.

    Expected line format:
        "2025-02-20 08:10:02 BLOCK proto=TCP src=185.220.101.1 dst=10.0.0.1 dport=22"

    The relevant IP for security is the SOURCE (src) of the connection.
    Returns:
        dict with keys: timestamp, fonte, tipo, ip, detalhes, linha_original
        None if the line has an invalid format.
    """
    parts = linha.split()
    if len(parts) < 5:
        return None

    timestamp, tipo = f"{parts[0]} {parts[1]}", parts[2]
    proto, src, dst, dport = None, None, None, None
    for part in parts[3:]:
        key, _, value = part.partition("=")
        if key == "proto":
            proto = value
        elif key == "src":
            src = value
        elif key == "dst":
            dst = value
        elif key == "dport":
            dport = value

    if not src or not timestamp.startswith("20"):
        return None

    detalhes = f"proto={proto} dst={dst} dport={dport}"
    return {
        "timestamp": timestamp,
        "fonte": "firewall",
        "tipo": tipo,
        "ip": src,
        "detalhes": detalhes,
        "linha_original": linha.strip(),
    }


def parsear_linha_web(linha):
    """
    Parse one web_access.log line and return a normalized event dict.

    Expected line format:
        "2025-02-20 08:20:01 GET url=/index.html ip=192.168.1.10 status=200"

    The URL may contain special characters (e.g. <script>, ../etc/passwd),
    therefore the value of "url=" is everything between "url=" and the next
    known key ("ip=" / "status=").
    Returns:
        dict with keys: timestamp, fonte, tipo, ip, detalhes, linha_original
        None if the line has an invalid format.
    """
    parts = linha.split()
    if len(parts) < 5:
        return None

    timestamp, tipo = f"{parts[0]} {parts[1]}", parts[2]

    # Locate the key positions so URLs containing spaces survive the split
    url_idx = ip_idx = status_idx = None
    for i, part in enumerate(parts[3:], start=3):
        if part.startswith("url=") and url_idx is None:
            url_idx = i
        elif part.startswith("ip=") and ip_idx is None:
            ip_idx = i
        elif part.startswith("status=") and status_idx is None:
            status_idx = i

    if ip_idx is None or not timestamp.startswith("20"):
        return None

    # URL value: text right after "url=" (may span multiple tokens)
    url_value = " ".join([parts[url_idx][4:]] + parts[url_idx + 1: ip_idx])
    status_value = parts[status_idx].split("=", 1)[1] if status_idx is not None else ""

    return {
        "timestamp": timestamp,
        "fonte": "web",
        "tipo": tipo,
        "ip": parts[ip_idx].split("=", 1)[1],
        "detalhes": f"url={url_value} status={status_value}",
        "linha_original": linha.strip(),
    }


def carregar_eventos(caminho_log, fonte):
    """
    Read one log file and return the list of normalized events.

    Invalid/malformed lines are skipped (ingestion must never crash on bad
    input - error handling criterion of the GS), but the number of skipped
    lines is reported back to the caller.
    """
    parser = {
        "auth": parsear_linha_auth,
        "firewall": parsear_linha_firewall,
        "web": parsear_linha_web,
    }.get(fonte)

    if parser is None:
        raise ValueError(f"Unknown log source: {fonte}")

    eventos, ignoradas = [], 0
    try:
        with open(caminho_log, "r", encoding="utf-8", errors="replace") as f:
            for linha in f:
                linha = linha.strip()
                if not linha:
                    continue
                evento = parser(linha)
                if evento is None:
                    ignoradas += 1
                    continue
                eventos.append(evento)
    except FileNotFoundError:
        print(f"[coletor] WARNING: log file not found: {caminho_log}")
    except OSError as exc:
        print(f"[coletor] WARNING: could not read {caminho_log}: {exc}")

    if ignoradas:
        print(f"[coletor] WARNING: {ignoradas} invalid line(s) skipped in {caminho_log}")
    return eventos


def carregar_todos_os_logs(diretorio_logs):
    """
    Read the 3 log files and return ONE unified list of events
    (with the "fonte" field correctly set for each event).
    """
    eventos = []
    for fonte, arquivo in LOG_FILES.items():
        caminho = os.path.join(diretorio_logs, arquivo)
        eventos.extend(carregar_eventos(caminho, fonte))
    return eventos
