from unittest.mock import Mock

import requests

from core.enriquecimento import consultar_ip


def test_privado_nao_consulta_rede(monkeypatch):
    consultar = Mock(side_effect=AssertionError('Não deveria consultar'))
    monkeypatch.setattr(requests, 'get', consultar)
    assert consultar_ip('192.168.1.10', {})['privado'] is True
    consultar.assert_not_called()


def test_falha_externa_e_cache(monkeypatch):
    consultar = Mock(side_effect=requests.Timeout)
    monkeypatch.setattr(requests, 'get', consultar)
    cache = {}
    primeiro = consultar_ip('185.220.101.1', cache)
    assert primeiro['cidade'] == 'Desconhecido'
    assert consultar_ip('185.220.101.1', cache) == primeiro
    assert consultar.call_count == 1
