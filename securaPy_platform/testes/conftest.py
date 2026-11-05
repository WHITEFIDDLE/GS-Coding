import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def pytest_addoption(parser):
    parser.addoption('--integracao', action='store_true', help='Inclui testes contra bancos reais')


def pytest_collection_modifyitems(config, items):
    if config.getoption('--integracao'):
        return
    for item in items:
        if 'integracao' in item.keywords:
            item.add_marker(pytest.mark.skip(reason='Use --integracao com os bancos locais em execução'))


# --------------------------------------------------------------------------- #
# Fixtures dos módulos C, E e G (ML, dashboard e assistente)
# --------------------------------------------------------------------------- #
PROJECT_ROOT = str(Path(__file__).resolve().parents[1])
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
    from servicos.analise import analisar_pasta
    analise = analisar_pasta(
        os.path.join(PROJECT_ROOT, "logs"),
        os.path.join(PROJECT_ROOT, "config", "regras.json"),
        os.path.join(PROJECT_ROOT, "config", "blacklist.json"),
    )
    return analise["eventos"], analise["alertas"], analise["ameacas"]


@pytest.fixture(scope="session")
def features_e_scores(pipeline_nucleo, modelo):
    """Feature dict + ML risk scores for every IP in the logs."""
    from servicos.analise import carregar_blacklist
    from ml.classificar import pontuar_ips
    from ml.features import extract_features_by_ip, load_suspicious_patterns

    eventos, _, _ = pipeline_nucleo
    blacklist = carregar_blacklist(os.path.join(PROJECT_ROOT, "config", "blacklist.json"))
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
