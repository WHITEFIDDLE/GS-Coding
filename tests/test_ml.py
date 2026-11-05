"""
Module C test scenarios (GS section 3, Módulo C):
    C1 - train and evaluate: precision / recall / F1 printed
    C2 - classify 185.220.101.1 (10+ FAILs + port scan + blacklist) -> HIGH risk / "ataque"
    C3 - classify 192.168.1.10 (normal internal traffic) -> "normal"
    C4 - model integrity: hash matches; if altered -> alert
"""

import os
import shutil

import pytest

from ml.classificar import ModelIntegrityError, verificar_integridade
from ml.treinar import construir_dataset, treinar_e_avaliar

PROJETO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# --------------------------------------------------------------------------- #
# C1
# --------------------------------------------------------------------------- #
def test_c1_treinar_e_avaliar_reporta_metricas():
    from core.coletor import carregar_todos_os_logs
    from core.detector import carregar_blacklist
    from ml.features import load_suspicious_patterns

    eventos = carregar_todos_os_logs(os.path.join(PROJETO, "logs"))
    blacklist = carregar_blacklist(os.path.join(PROJETO, "config", "blacklist.txt"))
    padroes = load_suspicious_patterns(os.path.join(PROJETO, "config", "regras.json"))

    X, y, _, _ = construir_dataset(eventos, blacklist, padroes)
    pipeline, metricas = treinar_e_avaliar(X, y)

    # Report with the three required metrics, each cross-validated
    assert set(metricas) == {"precision", "recall", "f1"}
    for nome, valores in metricas.items():
        assert valores["media"] >= 0.90, f"{nome} below 0.90: {valores}"
        assert len(valores["folds"]) == 5     # StratifiedKFold k=5
    assert pipeline is not None


# --------------------------------------------------------------------------- #
# C2 / C3
# --------------------------------------------------------------------------- #
def test_c2_ip_ataque_obtem_score_alto_e_rotulo_ataque(features_e_scores):
    _, scores = features_e_scores
    info = scores["185.220.101.1"]
    assert info["rotulo"] == "ataque"
    assert info["nivel"] == "ALTO"
    assert info["score"] >= 0.75
    assert info["features"]["auth_fails"] >= 10


def test_c3_ip_normal_obtem_rotulo_normal(features_e_scores):
    _, scores = features_e_scores
    info = scores["192.168.1.10"]
    assert info["rotulo"] == "normal"
    assert info["score"] < 0.5
    assert info["nivel"] == "BAIXO"


# --------------------------------------------------------------------------- #
# C4
# --------------------------------------------------------------------------- #
def test_c4_integridade_hash_confere(tmp_path):
    # 1) Hash of the real model file matches the registered one
    hash_atual = verificar_integridade()
    with open(os.path.join(PROJETO, "ml", "modelo.sha256"), encoding="utf-8") as f:
        assert hash_atual == f.read().strip()

    # 2) A TAMPERED copy must be REFUSED (fail closed)
    copia = tmp_path / "ml"
    copia.mkdir()
    shutil.copy(os.path.join(PROJETO, "ml", "modelo.pkl"), copia / "modelo.pkl")
    shutil.copy(os.path.join(PROJETO, "ml", "modelo.sha256"), copia / "modelo.sha256")

    # flip one byte of the pickled model -> different SHA-256
    with open(copia / "modelo.pkl", "r+b") as f:
        f.seek(100)
        original = f.read(1)
        f.seek(100)
        f.write(bytes([original[0] ^ 0xFF]))

    with pytest.raises(ModelIntegrityError) as exc:
        verificar_integridade(diretorio_ml=str(copia))
    assert "INTEGRITY" in str(exc.value)


# --------------------------------------------------------------------------- #
# Bonus - Isolation Forest
# --------------------------------------------------------------------------- #
def test_bonus_anomalias_marca_ips_atacantes(features_e_scores):
    from ml.anomalias import detectar_anomalias

    features, _ = features_e_scores
    resultados = detectar_anomalias(features)
    assert resultados["185.220.101.1"]["anomalia"] is True
    assert resultados["192.168.1.10"]["anomalia"] is False


# --------------------------------------------------------------------------- #
# Alert prioritization helper
# --------------------------------------------------------------------------- #
def test_alertas_ordenados_por_risco(pipeline_nucleo, features_e_scores):
    from ml.classificar import ordenar_alertas_por_risco

    _, scores = features_e_scores
    _, alertas, _ = pipeline_nucleo

    ordenados = ordenar_alertas_por_risco(alertas, scores)
    assert len(ordenados) == len(alertas)
    # first alert must belong to a top-risk IP
    primeiro_ip = ordenados[0]["ip"]
    assert scores[primeiro_ip]["rotulo"] == "ataque"
