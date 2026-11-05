"""Orquestra o módulo A sem depender dos bancos, da API ou do ML."""
import json
from ipaddress import ip_address
from pathlib import Path

from core.coletor import carregar_todos_os_logs
from core.detector import detectar_brute_force, detectar_port_scan, verificar_blacklist, gerar_resumo_ameacas
from core.regras import aplicar_regras, carregar_regras


def carregar_blacklist(caminho):
    dados = json.loads(Path(caminho).read_text(encoding='utf-8-sig'))
    if not isinstance(dados, list):
        raise ValueError('Blacklist precisa ser uma lista de IPs')
    return {str(ip_address(ip)) for ip in dados}


def analisar_eventos(eventos, regras, blacklist):
    eventos = list(eventos)
    brute_force = detectar_brute_force(eventos)
    port_scan = detectar_port_scan(eventos)
    encontrados = verificar_blacklist(eventos, blacklist)
    ameacas = gerar_resumo_ameacas(brute_force, port_scan, encontrados)
    alertas = aplicar_regras(eventos, regras)
    for ameaca in ameacas:
        timestamp = max(evento['timestamp'] for evento in eventos if evento['ip'] == ameaca['ip'])
        alertas.append({
            'timestamp': timestamp, 'ip': ameaca['ip'], 'fonte': 'correlacao',
            'regra_id': 'CORRELACAO', 'regra_nome': 'Correlação de ameaças',
            'severidade': ameaca['severidade'], 'origem': 'detector',
            'descricao': 'Detecções: ' + ', '.join(ameaca['deteccoes']),
            'detalhes': ameaca['detalhes'], 'pontuacao_regras': ameaca['pontuacao'],
        })
    return {'eventos': eventos, 'alertas': alertas, 'ameacas': ameacas}


def analisar_pasta(pasta_logs, caminho_regras, caminho_blacklist):
    regras = carregar_regras(caminho_regras)
    if not regras:
        raise ValueError('Nenhuma regra ativa válida. Confira a configuração antes de analisar.')
    return analisar_eventos(carregar_todos_os_logs(pasta_logs), regras, carregar_blacklist(caminho_blacklist))
