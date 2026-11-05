import json
from collections import Counter

import pytest

from configuracao import PASTA_PROJETO
from core.coletor import carregar_log, carregar_todos_os_logs, parsear_linha_auth, parsear_linha_firewall, parsear_linha_web
from core.detector import detectar_brute_force, detectar_port_scan, verificar_blacklist
from core.regras import carregar_regras, classificar_severidade
from servicos.analise import analisar_pasta


def test_logs_originais_e_deteccoes():
    eventos = carregar_todos_os_logs(PASTA_PROJETO / 'logs')
    assert Counter(evento['fonte'] for evento in eventos) == {'auth': 23, 'firewall': 17, 'web': 18}
    brute = detectar_brute_force(eventos)
    assert brute['185.220.101.1']['tentativas'] == 11
    assert brute['185.220.101.1']['severidade'] == 'ALTA'
    scan = detectar_port_scan(eventos)
    assert scan['185.220.101.1']['quantidade'] == 7
    assert scan['185.220.101.1']['severidade'] == 'ALTA'
    blacklist = {'185.220.101.1', '91.240.118.172', '45.33.32.156'}
    encontrados, contagem = verificar_blacklist(eventos, blacklist)
    assert encontrados == blacklist
    assert contagem['185.220.101.1'] == 25


@pytest.mark.parametrize('parser,linha', [
    (parsear_linha_auth, '2025-02-20 08:15:01 FAIL usuario=admin ip=999.1.1.1'),
    (parsear_linha_auth, '2025-02-30 08:15:01 FAIL usuario=admin ip=10.0.0.1'),
    (parsear_linha_auth, '2025-02-20 08:15:01 FAIL usuario=admin ip=10.0.0.1 ip=10.0.0.2'),
    (parsear_linha_firewall, '2025-02-20 08:15:01 BLOCK proto=TCP src=10.0.0.1 dst=10.0.0.2 dport=99999'),
    (parsear_linha_web, '2025-02-20 08:15:01 GET url=/ ip=10.0.0.1 status=999'),
])
def test_linhas_invalidas(parser, linha):
    assert parser(linha) is None


def test_log_inexistente_e_linha_ruim_nao_interrompem(tmp_path, caplog):
    assert carregar_log(tmp_path / 'inexistente.log', 'auth') == []
    arquivo = tmp_path / 'auth.log'
    arquivo.write_text('\nlinha quebrada\n2025-02-20 08:15:01 FAIL usuario=admin ip=10.0.0.1\n', encoding='utf-8')
    assert len(carregar_log(arquivo, 'auth')) == 1
    assert 'linha 2' in caplog.text


def test_regra_json_ruim_e_inativa(tmp_path):
    arquivo = tmp_path / 'regras.json'
    arquivo.write_text('{quebrado', encoding='utf-8')
    assert carregar_regras(arquivo) == []
    arquivo.write_text(json.dumps({'regras': [{'ativa': False}]}), encoding='utf-8')
    assert carregar_regras(arquivo) == []


@pytest.mark.parametrize('pontos,esperado', [(0,'INFO'), (3,'BAIXA'), (5,'MEDIA'), (7,'ALTA'), (9,'CRITICA')])
def test_severidade(pontos, esperado):
    assert classificar_severidade(pontos) == esperado


def test_analise_regras_e_correlacao():
    analise = analisar_pasta(PASTA_PROJETO / 'logs', PASTA_PROJETO / 'config/regras.json', PASTA_PROJETO / 'config/blacklist.json')
    assert len(analise['eventos']) == 58
    primeira = analise['ameacas'][0]
    assert primeira['ip'] == '185.220.101.1'
    assert primeira['pontuacao'] == 15
    assert primeira['deteccoes'] == ['brute_force', 'port_scan', 'blacklist']
    ids = {alerta['regra_id'] for alerta in analise['alertas']}
    assert ids == {'R001', 'R002', 'R003', 'R004', 'R005', 'CORRELACAO'}
    json.dumps(analise)  # sets internos viram listas no contrato de saída.


def test_porta_repetida_nao_vira_novo_scan():
    linha = '2025-02-20 08:15:01 BLOCK proto=TCP src=10.0.0.1 dst=10.0.0.2 dport=22'
    evento = parsear_linha_firewall(linha)
    assert detectar_port_scan([evento] * 20) == {}


@pytest.mark.parametrize('total,severidade', [(5,'BAIXA'), (6,'MEDIA'), (10,'MEDIA'), (11,'ALTA'), (21,'CRITICA')])
def test_limites_originais_brute_force(total, severidade):
    evento = parsear_linha_auth('2025-02-20 08:15:01 FAIL usuario=admin ip=10.0.0.1')
    assert detectar_brute_force([evento] * total)['10.0.0.1']['severidade'] == severidade
