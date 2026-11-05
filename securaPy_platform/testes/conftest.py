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
