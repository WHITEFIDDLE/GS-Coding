"""
ML Module C - Model Training, Evaluation and Persistence (GS Aulas 4 & 12).

Pipeline of this script:
    1. Load the real events through the 1st-semester core (reused).
    2. Extract the numeric feature vector per IP (ml/features.py).
    3. Label the REAL IPs (ground truth: known malicious vs internal traffic).
    4. AUGMENT the dataset with synthetic samples anchored on the real
       feature distributions - 7 real IPs alone are not enough to train or
       cross-validate a classifier (documented limitation, avoids overfitting
       the report on 7 rows).
    5. Train a Pipeline(StandardScaler + LogisticRegression) inside sklearn -
       exactly the structure required by the GS.
    6. Evaluate with StratifiedKFold cross-validation and PRINT
       precision / recall / F1 (test scenario C1).
    7. Persist with joblib -> ml/modelo.pkl and register the SHA-256 hash of
       the file (integrity, reusing hashlib from the 1st semester).
    8. Save the metrics report JSON (deliverable #5 of the GS) and the
       training dataset CSV (reproducibility).

Usage (from the project root):
    python ml/treinar.py
"""

import csv
import hashlib
import json
import os
import random
import sys
from datetime import datetime, timezone

import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (f1_score, make_scorer, precision_score,
                             recall_score)
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.coletor import carregar_todos_os_logs                     # noqa: E402
from servicos.analise import carregar_blacklist                       # noqa: E402
from ml.features import (FEATURE_NAMES, feature_matrix,             # noqa: E402
                         extract_features_by_ip, load_suspicious_patterns)

ML_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(ML_DIR)
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
CONFIG_DIR = os.path.join(PROJECT_ROOT, "config")

MODEL_PATH = os.path.join(ML_DIR, "modelo.pkl")
HASH_PATH = os.path.join(ML_DIR, "modelo.sha256")
REPORT_PATH = os.path.join(ML_DIR, "relatorio_metricas.json")
DATASET_PATH = os.path.join(ML_DIR, "dataset_treino.csv")

RANDOM_STATE = 42
N_SYNTHETIC_PER_CLASS = 300


def sha256_do_arquivo(caminho):
    """SHA-256 hex digest of a file - integrity mechanism (hashlib, 1st sem)."""
    sha256 = hashlib.sha256()
    with open(caminho, "rb") as f:
        for bloco in iter(lambda: f.read(8192), b""):
            sha256.update(bloco)
    return sha256.hexdigest()


def gerar_amostras_sinteticas(rotulo, n_amostras, rng):
    """
    Generate synthetic feature rows anchored on the real distributions.

    "ataque"  -> many failed logins, several blocked ports, web errors,
                 attack URLs, usually blacklisted (20% of new attackers are NOT
                 yet in the blacklist, so the model does not rely on it alone).
    "normal"  -> internal traffic: few failures, at most 1 blocked port,
                 few/no web errors, no attack patterns, never blacklisted.
    """
    amostras = []
    for _ in range(n_amostras):
        if rotulo == "ataque":
            linha = [
                min(15, max(2, rng.gauss(8, 3))),      # auth_fails
                min(9, max(0, rng.gauss(3.5, 1.8))),   # distinct_blocked_ports
                min(12, max(0, rng.gauss(3, 1.8))),    # web_errors
                max(1, rng.gauss(6, 2.5)),             # web_total
                min(6, max(0, rng.gauss(1.8, 1.2))),   # suspicious_urls
                1 if rng.random() < 0.80 else 0,       # in_blacklist
            ]
        else:
            linha = [
                min(2, max(0, rng.gauss(0.25, 0.45))),   # auth_fails
                min(2, max(0, rng.gauss(0.18, 0.35))),   # distinct_blocked_ports
                min(2, max(0, rng.gauss(0.30, 0.50))),   # web_errors
                max(1, rng.gauss(1.8, 0.8)),             # web_total
                1 if rng.random() < 0.02 else 0,         # suspicious_urls
                0,                                       # in_blacklist
            ]
        amostras.append([round(valor, 4) for valor in linha])
    return amostras


def construir_dataset(eventos, blacklist, padroes):
    """
    Build the final training dataset = real labeled IPs + synthetic augmentation.
    Returns (X, y) as numpy arrays.
    """
    features_por_ip = extract_features_by_ip(eventos, blacklist, padroes)
    matriz, ips = feature_matrix(features_por_ip)

    # Ground truth for the REAL IPs: blacklist membership is the strongest
    # known-bad signal (same 3 malicious IPs of the 1st-semester GS).
    X_real, y_real = [], []
    for ip, linha in zip(ips, matriz):
        rotulo = "ataque" if ip in blacklist else "normal"
        X_real.append(linha)
        y_real.append(rotulo)

    rng = random.Random(RANDOM_STATE)
    X_sint = (
        gerar_amostras_sinteticas("ataque", N_SYNTHETIC_PER_CLASS, rng)
        + gerar_amostras_sinteticas("normal", N_SYNTHETIC_PER_CLASS, rng)
    )
    y_sint = ["ataque"] * N_SYNTHETIC_PER_CLASS + ["normal"] * N_SYNTHETIC_PER_CLASS

    X = np.array(X_real + X_sint, dtype=float)
    y = np.array(y_real + y_sint)
    return X, y, features_por_ip, dict(zip(ips, y_real))


def treinar_e_avaliar(X, y):
    """
    Train the Pipeline and evaluate it with 5-fold StratifiedKFold
    cross-validation. Returns (pipeline, metricas) where metricas holds the
    mean and standard deviation of precision / recall / F1 (scenario C1).
    """
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", LogisticRegression(max_iter=1000, random_state=RANDOM_STATE)),
    ])

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    # String labels ("ataque"/"normal") need explicit pos_label in the scorers
    scorers = {
        "precision": make_scorer(precision_score, pos_label="ataque"),
        "recall": make_scorer(recall_score, pos_label="ataque"),
        "f1": make_scorer(f1_score, pos_label="ataque"),
    }
    metricas = {}
    for nome_metrica, scorer in scorers.items():
        scores = cross_val_score(pipeline, X, y, cv=cv, scoring=scorer)
        metricas[nome_metrica] = {
            "media": round(float(scores.mean()), 4),
            "desvio": round(float(scores.std()), 4),
            "folds": [round(float(s), 4) for s in scores],
        }

    # Fit on the full dataset for the persisted artifact
    pipeline.fit(X, y)
    return pipeline, metricas


def salvar_dataset_csv(X, y):
    """Save the training dataset for reproducibility / audit."""
    with open(DATASET_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(FEATURE_NAMES + ["rotulo"])
        for linha, rotulo in zip(X, y):
            writer.writerow(list(linha) + [rotulo])


def main():
    print("=" * 64)
    print("SecuraPy ML - Module C: training, evaluation and persistence")
    print("=" * 64)

    # 1-3. Real data -> features -> ground truth
    eventos = carregar_todos_os_logs(LOGS_DIR)
    blacklist = carregar_blacklist(os.path.join(CONFIG_DIR, "blacklist.json"))
    padroes = load_suspicious_patterns(os.path.join(CONFIG_DIR, "regras.json"))
    X, y, features_por_ip, rotulos_reais = construir_dataset(eventos, blacklist, padroes)

    print(f"\n[dataset] real IPs: {len(rotulos_reais)} "
          f"(ataque={sum(1 for v in rotulos_reais.values() if v == 'ataque')}, "
          f"normal={sum(1 for v in rotulos_reais.values() if v == 'normal')})")
    print(f"[dataset] total samples (real + synthetic): {len(y)}")

    # 4-6. Train + cross-validate + report (C1)
    pipeline, metricas = treinar_e_avaliar(X, y)
    print("\n[C1] Cross-validation report (StratifiedKFold, k=5):")
    for nome in ("precision", "recall", "f1"):
        m = metricas[nome]
        print(f"  {nome:<9}: {m['media']:.4f} (+/- {m['desvio']:.4f})")

    # Sanity check on the REAL IPs (the deployment ground truth)
    matriz_real, ips_reais = feature_matrix(features_por_ip)
    previsoes = pipeline.predict(np.array(matriz_real, dtype=float))
    acertos = sum(1 for ip, prev in zip(ips_reais, previsoes)
                  if rotulos_reais[ip] == prev)
    print(f"\n[sanity] real IPs correctly classified: {acertos}/{len(ips_reais)}")
    for ip, prev in zip(ips_reais, previsoes):
        esperado = rotulos_reais[ip]
        marca = "OK " if esperado == prev else "ERR"
        print(f"  [{marca}] {ip:<18} esperado={esperado:<7} previsto={prev}")

    # 7. Persist the model and its SHA-256 integrity hash
    joblib.dump(pipeline, MODEL_PATH)
    hash_hex = sha256_do_arquivo(MODEL_PATH)
    with open(HASH_PATH, "w", encoding="utf-8") as f:
        f.write(hash_hex)

    # 8. Metrics report (deliverable #5) + dataset CSV
    salvar_dataset_csv(X, y)
    relatorio = {
        "modelo": "Pipeline(StandardScaler, LogisticRegression)",
        "features": FEATURE_NAMES,
        "n_amostras_treino": int(len(y)),
        "n_ips_reais": len(ips_reais),
        "validacao_cruzada": metricas,
        "avaliacao_ips_reais": {"acertos": acertos, "total": len(ips_reais)},
        "arquivo_modelo": os.path.relpath(MODEL_PATH, PROJECT_ROOT),
        "hash_sha256": hash_hex,
        "hash_arquivo": os.path.relpath(HASH_PATH, PROJECT_ROOT),
        "gerado_em": datetime.now(timezone.utc).isoformat(),
    }
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(relatorio, f, indent=2, ensure_ascii=False)

    print(f"\n[persist] model saved   -> {os.path.relpath(MODEL_PATH, PROJECT_ROOT)}")
    print(f"[persist] SHA-256 hash  -> {os.path.relpath(HASH_PATH, PROJECT_ROOT)}")
    print(f"[persist] hash value    -> {hash_hex}")
    print(f"[persist] metrics report-> {os.path.relpath(REPORT_PATH, PROJECT_ROOT)}")
    print("[C4] integrity registered: classificar.py verifies this hash on load")
    print("=" * 64)


if __name__ == "__main__":
    main()
