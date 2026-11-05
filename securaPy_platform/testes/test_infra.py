from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from docker.errors import DockerException
from infra.verificar_containers import verificar, main


def container(servico, status='running', saude='healthy'):
    return SimpleNamespace(name='projeto-' + servico, reload=Mock(), attrs={
        'Config': {'Labels': {'com.docker.compose.service': servico}},
        'State': {'Status': status, 'Health': {'Status': saude}}})


def test_sdk_todos_saudaveis_e_filtro():
    cliente = Mock()
    cliente.containers.list.return_value = [container(s) for s in ('api', 'mongo', 'mysql')]
    assert verificar(cliente, 'securapy-df')['ok']
    cliente.containers.list.assert_called_once_with(all=True, filters={'label': [
        'com.docker.compose.project=securapy-df', 'com.docker.compose.oneoff=False']})


@pytest.mark.parametrize('status,saude', [('exited', 'healthy'), ('running', 'unhealthy'), ('running', 'starting'), ('running', 'sem-healthcheck')])
def test_sdk_container_com_problema(status, saude):
    cliente = Mock()
    cliente.containers.list.return_value = [container('api', status, saude), container('mongo'), container('mysql')]
    assert not verificar(cliente, 'securapy-df')['ok']


def test_sdk_servico_ausente():
    cliente = Mock(); cliente.containers.list.return_value = [container('api')]
    resposta = verificar(cliente, 'securapy-df')
    assert not resposta['ok'] and not resposta['servicos']['mysql']['ok']


def test_sdk_daemon_indisponivel(monkeypatch, capsys):
    monkeypatch.setattr('infra.verificar_containers.docker.from_env', Mock(side_effect=DockerException('segredo')))
    assert main([]) == 2
    assert 'segredo' not in capsys.readouterr().err


def test_sdk_fecha_cliente(monkeypatch):
    cliente = Mock(); cliente.containers.list.return_value = []
    monkeypatch.setattr('infra.verificar_containers.docker.from_env', lambda **kwargs: cliente)
    assert main([]) == 1
    cliente.close.assert_called_once()
