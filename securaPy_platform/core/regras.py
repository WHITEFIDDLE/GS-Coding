"""Regras de um evento: usuário privilegiado, porta sensível e URLs suspeitas."""
import json
import logging
from pathlib import Path
from urllib.parse import unquote

from core.coletor import atributos_do_evento

logger = logging.getLogger(__name__)
CONDICOES = {'usuario_privilegiado', 'porta_critica', 'path_traversal', 'xss', 'reconhecimento'}


def carregar_regras(caminho_config):
    try:
        documento = json.loads(Path(caminho_config).read_text(encoding='utf-8-sig'))
        regras = documento['regras']
        if not isinstance(regras, list):
            raise ValueError('A chave regras precisa ser uma lista')
        ativas = []
        for regra in regras:
            if not isinstance(regra, dict):
                raise ValueError('Regra inválida')
            if not regra.get('ativa', False):
                continue
            for chave in ('id', 'nome', 'descricao', 'fonte', 'condicao', 'severidade_base'):
                if chave not in regra:
                    raise ValueError('Regra incompleta')
            if regra['fonte'] not in {'auth', 'firewall', 'web'} or regra['condicao'] not in CONDICOES:
                raise ValueError('Fonte ou condição desconhecida')
            float(regra['severidade_base'])
            chave_alvos = {'usuario_privilegiado': 'usuarios_alvo', 'porta_critica': 'portas_criticas',
                           'reconhecimento': 'urls_suspeitas'}.get(regra['condicao'], 'padroes')
            if not isinstance(regra.get(chave_alvos), list):
                raise ValueError('Lista de alvos inválida')
            ativas.append(regra)
        return ativas
    except (OSError, UnicodeError, ValueError, KeyError, TypeError):
        logger.warning('Configuração de regras inválida ou indisponível')
        return []


def classificar_severidade(pontuacao):
    if pontuacao >= 9:
        return 'CRITICA'
    if pontuacao >= 7:
        return 'ALTA'
    if pontuacao >= 5:
        return 'MEDIA'
    if pontuacao >= 3:
        return 'BAIXA'
    return 'INFO'


def avaliar_regra(regra, evento):
    if evento['fonte'] != regra['fonte']:
        return None
    campos = atributos_do_evento(evento)
    condicao = regra['condicao']
    violou = False
    if condicao == 'usuario_privilegiado':
        violou = campos.get('usuario') in regra['usuarios_alvo']
    elif condicao == 'porta_critica':
        violou = evento['tipo'] == 'BLOCK' and int(campos['dport']) in regra['portas_criticas']
    else:
        url = unquote(str(campos.get('url', ''))).lower()
        if condicao == 'reconhecimento':
            padroes = regra.get('urls_suspeitas', [])
        else:
            padroes = regra.get('padroes', [])
        violou = any(str(padrao).lower() in url for padrao in padroes)
    if not violou:
        return None
    return {
        'timestamp': evento['timestamp'], 'fonte': evento['fonte'], 'ip': evento['ip'],
        'regra_id': regra['id'], 'regra_nome': regra['nome'],
        'severidade': classificar_severidade(float(regra['severidade_base'])),
        'descricao': regra['descricao'], 'origem': 'regra',
    }


def aplicar_regras(eventos, regras):
    alertas = []
    for evento in eventos:
        for regra in regras:
            alerta = avaliar_regra(regra, evento)
            if alerta is not None:
                alertas.append(alerta)
    return alertas
