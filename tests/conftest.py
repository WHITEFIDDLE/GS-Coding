"""
Shared pytest fixtures for the SecuraPy Platform tests (C/E/G scenarios).

Run from the project root:
    python -m pytest tests/ -v
"""

import os
import subprocess
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

MODEL_PATH = os.path.join(PROJECT_ROOT, "ml", "modelo.pkl")


@pytest.fixture(scope="session")
def modelo():
    """Ensure the model exists (training it once if missing) and load it hash-verified."""
    if not os.path.exists(MODEL_PATH):
        subprocess.run([sys.executable, os.path.join(PROJECT_ROOT, "ml", "treinar.py")],
                       check=True, cwd=PROJECT_ROOT, capture_output=True)
    from ml.classificar import carregar_modelo
    return carregar_modelo()


@pytest.fixture(scope="session")
def pipeline_nucleo():
    """(eventos, alertas, ameacas) from the 1st-semester core pipeline."""
    from core.detector import executar_pipeline_deteccao
    return executar_pipeline_deteccao(
        os.path.join(PROJECT_ROOT, "logs"),
        os.path.join(PROJECT_ROOT, "config", "regras.json"),
        os.path.join(PROJECT_ROOT, "config", "blacklist.txt"),
    )


@pytest.fixture(scope="session")
def features_e_scores(pipeline_nucleo, modelo):
    """Feature dict + ML risk scores for every IP in the logs."""
    from core.detector import carregar_blacklist
    from ml.classificar import pontuar_ips
    from ml.features import extract_features_by_ip, load_suspicious_patterns

    eventos, _, _ = pipeline_nucleo
    blacklist = carregar_blacklist(os.path.join(PROJECT_ROOT, "config", "blacklist.txt"))
    padroes = load_suspicious_patterns(os.path.join(PROJECT_ROOT, "config", "regras.json"))
    features = extract_features_by_ip(eventos, blacklist, padroes)
    scores = pontuar_ips(features, modelo)
    return features, scores


@pytest.fixture(scope="session")
def app(tmp_path_factory):
    """Flask app with the default provider and a session-scoped access log file."""
    from web.dashboard import criar_app

    caminho_log = str(tmp_path_factory.mktemp("logs_web") / "access.log")
    application = criar_app(caminho_log_acesso=caminho_log)
    application.config["TESTING"] = True
    application._caminho_log_acesso_teste = caminho_log
    return application


@pytest.fixture()
def cliente(app):
    """Unauthenticated Flask test client."""
    return app.test_client()


@pytest.fixture()
def cliente_logado(app):
    """Flask test client with an authenticated operator session."""
    client = app.test_client()
    with client.session_transaction() as sessao:
        sessao["usuario"] = "admin"
        sessao["nome"] = "Operador Administrador"
        sessao["nivel_acesso"] = 5
        sessao["csrf_token"] = "token-teste-csrf"
    return client
