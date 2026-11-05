"""
ML Module C - Risk Classification / Alert Prioritization (GS Aulas 4 & 12).

Loads the persisted Pipeline (ml/modelo.pkl), VERIFYING the SHA-256 hash
registered at training time (test scenario C4: hash must match; if the file
was altered, an alert is raised and loading is REFUSED - fail closed),
then assigns every IP a risk score used to sort/prioritize alerts
(reducing alert fatigue: the analyst sees what matters first).

Usage (from the project root):
    python ml/classificar.py                       # scores every IP in the logs
    python ml/classificar.py --ip 185.220.101.1    # detailed report for one IP

API used by the rest of the platform (web dashboard, api module):
    from ml.classificar import carregar_modelo, pontuar_ips, ordenar_alertas_por_risco
"""

import os
import sys

import joblib
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.coletor import carregar_todos_os_logs                     # noqa: E402
from core.detector import carregar_blacklist                        # noqa: E402
from ml.features import (FEATURE_NAMES, feature_matrix,             # noqa: E402
                         extract_features_by_ip, load_suspicious_patterns,
                         vectorize_feature_dict)
from ml.treinar import (CONFIG_DIR, HASH_PATH, LOGS_DIR, MODEL_PATH,  # noqa: E402
                        sha256_do_arquivo)

# Risk bands applied on top of the predicted probability of the "ataque" class
LIMIARES_NIVEL = {"ALTO": 0.75, "MEDIO": 0.35}
LIMIAR_ROTULO = 0.50


class ModelIntegrityError(Exception):
    """Raised when modelo.pkl does not match its registered SHA-256 hash (C4)."""


def verificar_integridade(diretorio_ml=None):
    """
    Compare the current SHA-256 of modelo.pkl against the registered hash.

    Returns the hash string when it matches.
    Raises ModelIntegrityError when the file was altered or the hash is
    missing - a tampered security model must NEVER be silently loaded.
    """
    modelo = os.path.join(diretorio_ml, "modelo.pkl") if diretorio_ml else MODEL_PATH
    hash_arquivo = os.path.join(diretorio_ml, "modelo.sha256") if diretorio_ml else HASH_PATH

    if not os.path.exists(modelo):
        raise FileNotFoundError(
            "modelo.pkl not found - run 'python ml/treinar.py' first."
        )
    if not os.path.exists(hash_arquivo):
        raise ModelIntegrityError(
            "model hash file (modelo.sha256) is missing - refusing to load "
            "an unverified model."
        )

    hash_atual = sha256_do_arquivo(modelo)
    with open(hash_arquivo, "r", encoding="utf-8") as f:
        hash_registrado = f.read().strip()

    if hash_atual != hash_registrado:
        raise ModelIntegrityError(
            "[C4] MODEL INTEGRITY ALERT: SHA-256 of modelo.pkl does NOT match "
            f"the registered hash.\n  expected: {hash_registrado}\n  actual:   {hash_atual}\n"
            "The model file may have been tampered with. Do NOT load it; "
            "retrain with 'python ml/treinar.py'."
        )
    return hash_atual


def carregar_modelo(diretorio_ml=None):
    """
    Load the joblib Pipeline AFTER verifying its integrity hash (C4).
    Returns the fitted sklearn Pipeline.
    """
    hash_atual = verificar_integridade(diretorio_ml)
    modelo = joblib.load(os.path.join(diretorio_ml, "modelo.pkl") if diretorio_ml
                         else MODEL_PATH)
    print(f"[ml] model loaded (integrity verified: {hash_atual[:16]}...)")
    return modelo


def pontuar_ips(features_por_ip, modelo=None):
    """
    Score every IP with the trained classifier.

    Args:
        features_por_ip: {ip: feature_dict} from ml.features.extract_features_by_ip
        modelo: fitted Pipeline (loads + verifies if omitted)

    Returns:
        dict: {ip: {"score": float(0-1), "rotulo": "ataque"|"normal",
                     "nivel": "ALTO"|"MEDIO"|"BAIXO", "features": dict}}
        The score is P(classe=ataque) - used by the dashboard to sort alerts.
    """
    if modelo is None:
        modelo = carregar_modelo()

    matriz, ips = feature_matrix(features_por_ip)
    if not ips:
        return {}

    probas = modelo.predict_proba(np.array(matriz, dtype=float))
    # Locate the "ataque" column robustly (class order depends on training)
    idx_ataque = list(modelo.classes_).index("ataque")

    scores = {}
    for ip, proba in zip(ips, probas):
        score = float(proba[idx_ataque])
        rotulo = "ataque" if score >= LIMIAR_ROTULO else "normal"
        if score >= LIMIARES_NIVEL["ALTO"]:
            nivel = "ALTO"
        elif score >= LIMIARES_NIVEL["MEDIO"]:
            nivel = "MEDIO"
        else:
            nivel = "BAIXO"
        scores[ip] = {
            "score": round(score, 4),
            "rotulo": rotulo,
            "nivel": nivel,
            "features": features_por_ip[ip],
        }
    return scores


def pontuar_ip(ip, eventos, blacklist, modelo=None, padroes=None):
    """
    Score ONE IP by extracting its features from the given events.
    Convenience for the dashboard IP-search endpoint.
    """
    if modelo is None:
        modelo = carregar_modelo()
    if padroes is None:
        padroes = load_suspicious_patterns(os.path.join(CONFIG_DIR, "regras.json"))

    do_ip = [ev for ev in eventos if ev.get("ip") == ip]
    features_do_ip = extract_features_by_ip(do_ip, blacklist, padroes)
    if ip not in features_do_ip:
        return {"ip": ip, "score": 0.0, "rotulo": "normal", "nivel": "BAIXO",
                "features": {nome: 0 for nome in FEATURE_NAMES}}

    resultado = pontuar_ips(features_do_ip, modelo)
    saida = resultado[ip]
    saida["ip"] = ip
    return saida


def ordenar_alertas_por_risco(alertas, scores):
    """
    Sort alerts by the ML risk score of their IP (descending) - the core
    prioritization loop that reduces alert fatigue. Alerts whose IP has no
    score keep their position at the end, ordered by severity.
    """
    ordem_severidade = {"CRITICA": 0, "ALTA": 1, "MEDIA": 2, "BAIXA": 3, "INFO": 4}

    def chave(alerta):
        score = scores.get(alerta.get("ip"), {}).get("score", -1)
        return (-score, ordem_severidade.get(alerta.get("severidade"), 9))

    return sorted(alertas, key=chave)


def _imprimir_tabela(scores):
    """Pretty-print the risk table (CLI output for scenario C2/C3 checks)."""
    print(f"\n{'IP':<18} {'score':>7} {'rotulo':>8} {'nivel':>6}  "
          f"{'fails':>5} {'ports':>5} {'web_err':>7} {'bl':>3}")
    print("-" * 70)
    for ip, info in sorted(scores.items(), key=lambda kv: -kv[1]["score"]):
        feat = info["features"]
        print(f"{ip:<18} {info['score']:>7.4f} {info['rotulo']:>8} {info['nivel']:>6}  "
              f"{feat['auth_fails']:>5} {feat['distinct_blocked_ports']:>5} "
              f"{feat['web_errors']:>7} {feat['in_blacklist']:>3}")


def main():
    print("=" * 64)
    print("SecuraPy ML - Module C: risk scoring (hash-verified model)")
    print("=" * 64)

    eventos = carregar_todos_os_logs(LOGS_DIR)
    blacklist = carregar_blacklist(os.path.join(CONFIG_DIR, "blacklist.txt"))
    padroes = load_suspicious_patterns(os.path.join(CONFIG_DIR, "regras.json"))

    features_por_ip = extract_features_by_ip(eventos, blacklist, padroes)
    modelo = carregar_modelo()
    scores = pontuar_ips(features_por_ip, modelo)

    _imprimir_tabela(scores)

    ip_alvo = None
    if "--ip" in sys.argv:
        ip_alvo = sys.argv[sys.argv.index("--ip") + 1]
        if ip_alvo in scores:
            info = scores[ip_alvo]
            print(f"\n[C2/C3] detailed report for {ip_alvo}:")
            print(f"  risk score : {info['score']}  ({info['nivel']})")
            print(f"  label      : {info['rotulo']}")
            print(f"  features   : {info['features']}")
        else:
            print(f"\nIP {ip_alvo} not present in the logs.")

    print("\nDone. Scores available for alert prioritization "
          "(ml.classificar.ordenar_alertas_por_risco).")


if __name__ == "__main__":
    main()
