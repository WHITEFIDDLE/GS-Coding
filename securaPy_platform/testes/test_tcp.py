import json
import socket
import threading

import pytest

from alertas.publicador import publicar_criticos
from alertas.servidor_alertas import ServidorAlertas, enviar_json


@pytest.fixture
def servidor():
    servidor = ServidorAlertas('token-de-teste-com-32-caracteres-abc', porta=0)
    thread = threading.Thread(target=servidor.servir, daemon=True)
    thread.start()
    yield servidor
    servidor.fechar()
    thread.join(timeout=3)
    assert not thread.is_alive()


def alerta():
    return {'timestamp':'2025-02-20 08:15:01', 'severidade':'CRITICA',
            'ip':'185.220.101.1', 'regra_nome':'Teste', 'descricao':'Teste de broadcast'}


def ler(entrada):
    return json.loads(entrada.readline())


def test_broadcast_para_dois_consoles_e_historico(servidor):
    with socket.create_connection(servidor.endereco, timeout=3) as a, \
         socket.create_connection(servidor.endereco, timeout=3) as b:
        with a.makefile('rb') as entrada_a, b.makefile('rb') as entrada_b:
            for con, entrada in [(a,entrada_a), (b,entrada_b)]:
                enviar_json(con, {'acao':'assinar'})
                assert ler(entrada)['tipo'] == 'conectado'
            assert publicar_criticos([alerta()], servidor.token, *servidor.endereco) == 1
            assert ler(entrada_a)['alerta'] == alerta()
            assert ler(entrada_b)['alerta'] == alerta()
            enviar_json(a, {'acao':'status'})
            status = ler(entrada_a)
            assert status['clientes'] == 2 and status['alertas'] == 1
            enviar_json(a, {'acao':'historico'})
            assert ler(entrada_a)['alertas'] == [alerta()]


def test_publicacao_sem_token_recusada(servidor):
    with pytest.raises(ValueError, match='recusou'):
        publicar_criticos([alerta()], 'invalido', *servidor.endereco)
    assert servidor.total_alertas == 0


def test_tcp_fragmentado_e_multiplas_mensagens(servidor):
    with socket.create_connection(servidor.endereco, timeout=3) as con:
        with con.makefile('rb') as entrada:
            con.sendall(b'{"acao":"assi')
            con.sendall(b'nar"}\n{"acao":"status"}\n')
            assert ler(entrada)['tipo'] == 'conectado'
            assert ler(entrada)['tipo'] == 'status'
