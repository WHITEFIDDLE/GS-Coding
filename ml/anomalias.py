"""
ML Module C (BONUS) - Anomaly Detection with Isolation Forest (+0.30).

The rules engine + supervised classifier detect KNOWN patterns. The Isolation
Forest adds an unsupervised layer: it learns what "normal traffic" looks like
and flags IPs whose feature profile is an OUTLIER - catching unknown patterns
that no rule covers yet (zero-day-ish behavior).

Approach:
    - Fit ONLY on "normal" class rows of the training dataset
      (ml/dataset_treino.csv). This is the classic anomaly-detection setup:
      the model learns what benign traffic looks like, and anything that
      deviates from it becomes an outlier - catching unknown patterns that
      no rule covers yet (zero-day-ish behavior).
    - Score the REAL IPs observed in the logs; outliers are reported as
      "anomalia" with a normalized anomaly score in [0, 1] (0.5 = boundary).

Usage (from the project root, after running ml/treinar.py):
    python ml/anomalias.py
"""

import csv
import os
import sys

import numpy as np
from sklearn.ensemble import IsolationForest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.coletor import carregar_todos_os_logs                     # noqa: E402
from core.detector import carregar_blacklist                        # noqa: E402
from ml.features import (FEATURE_NAMES, extract_features_by_ip,     # noqa: E402
                         load_suspicious_patterns)
from ml.treinar import CONFIG_DIR, DATASET_PATH, LOGS_DIR           # noqa: E402

RANDOM_STATE = 42
CONTAMINATION = 0.05


def _carregar_matriz_dataset():
    """
    Load the training dataset CSV and return the matrix of features of the
    'normal' rows only - Isolation Forest models BENIGN traffic and flags
    anything that deviates from it.
    """
    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        colunas = next(reader)
        idx_features = [colunas.index(nome) for nome in FEATURE_NAMES]
        idx_rotulo = colunas.index("rotulo")
        linhas = [[float(linha[i]) for i in idx_features]
                  for linha in reader if linha and linha[idx_rotulo] == "normal"]
    return np.array(linhas)


def detectar_anomalias(features_por_ip, contamination=CONTAMINATION):
    """
    Fit Isolation Forest on BENIGN traffic and score the given IPs.

    Args:
        features_por_ip: {ip: feature_dict} from ml.features.extract_features_by_ip
        contamination: expected fraction of outliers inside the benign sample

    Returns:
        dict: {ip: {"anomalia": bool, "score_anomalia": float(0-1)}}
        score_anomalia >= 0.5 means OUTLIER (unknown traffic profile).
    """
    X_treino = _carregar_matriz_dataset()

    floresta = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=RANDOM_STATE,
    )
    floresta.fit(X_treino)
    print(f"[anomalias] fitted on {len(X_treino)} benign samples "
          f"(contamination={contamination})")

    from ml.features import feature_matrix  # local import avoids cycle noise
    matriz, ips = feature_matrix(features_por_ip)
    if not ips:
        return {}

    predicoes = floresta.predict(np.array(matriz, dtype=float))   # 1 normal / -1 outlier
    cru = floresta.score_samples(np.array(matriz, dtype=float))   # higher = more normal

    # Normalize raw scores to [0, 1]: 0.5 = boundary, > 0.5 = anomalous
    cru_min, cru_max = cru.min(), cru.max()
    resultados = {}
    for ip, pred, valor in zip(ips, predicoes, cru):
        norm = 1.0 - (valor - cru_min) / (cru_max - cru_min) if cru_max > cru_min else 0.5
        resultados[ip] = {
            "anomalia": bool(pred == -1),
            "score_anomalia": round(float(norm), 4),
        }
    return resultados


def main():
    print("=" * 64)
    print("SecuraPy ML - Module C bonus: Isolation Forest anomaly detection")
    print("=" * 64)

    eventos = carregar_todos_os_logs(LOGS_DIR)
    blacklist = carregar_blacklist(os.path.join(CONFIG_DIR, "blacklist.txt"))
    padroes = load_suspicious_patterns(os.path.join(CONFIG_DIR, "regras.json"))

    features_por_ip = extract_features_by_ip(eventos, blacklist, padroes)
    resultados = detectar_anomalias(features_por_ip)

    print(f"\nIsolation Forest fitted on benign traffic rows of {DATASET_PATH} "
          f"(contamination={CONTAMINATION})\n")
    print(f"{'IP':<18} {'anomaly':>8} {'anomaly_score':>14}  in_blacklist")
    print("-" * 58)
    for ip, info in sorted(resultados.items(), key=lambda kv: -kv[1]["score_anomalia"]):
        marca = "YES" if info["anomalia"] else "no"
        bl = "yes" if features_por_ip[ip]["in_blacklist"] else "no"
        print(f"{ip:<18} {marca:>8} {info['score_anomalia']:>14.4f}  {bl}")

    anomalias = [ip for ip, info in resultados.items() if info["anomalia"]]
    print(f"\nOutliers flagged as unknown-pattern anomalies: {len(anomalias)}")
    for ip in anomalias:
        print(f"  -> {ip} (investigate: profile not seen in normal traffic)")


if __name__ == "__main__":
    main()
