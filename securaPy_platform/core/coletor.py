"""Converte as três fontes de log para o mesmo formato de evento.

Mantém os campos propostos no esqueleto do professor. O campo adicional
`atributos` guarda os valores estruturados para evitar novos splits no ML.
"""
import logging
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path

logger = logging.getLogger(__name__)
ARQUIVOS = {'auth.log': 'auth', 'firewall.log': 'firewall', 'web_access.log': 'web'}


def _separar_campos(linha):
    partes = linha.strip().split()
    if len(partes) < 4:
        raise ValueError('Linha incompleta')
    timestamp = partes[0] + ' ' + partes[1]
    datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
    campos = {}
    for parte in partes[3:]:
        chave, valor = parte.split('=', 1)
        if not chave or not valor or chave in campos:
            raise ValueError('Campo vazio ou repetido')
        campos[chave] = valor
    return timestamp, partes[2], campos


def _parsear(linha, fonte):
    try:
        timestamp, tipo, campos = _separar_campos(linha)
        if fonte == 'auth':
            if tipo not in {'FAIL', 'OK'}:
                raise ValueError('Tipo de autenticação inválido')
            ip = str(ip_address(campos['ip']))
            atributos = {'usuario': campos['usuario']}
        elif fonte == 'firewall':
            if tipo not in {'BLOCK', 'ALLOW'} or campos['proto'] not in {'TCP', 'UDP', 'ICMP'}:
                raise ValueError('Tipo ou protocolo inválido')
            ip = str(ip_address(campos['src']))
            porta = int(campos['dport'])
            if not 1 <= porta <= 65535:
                raise ValueError('Porta fora do intervalo')
            atributos = {'proto': campos['proto'], 'dst': str(ip_address(campos['dst'])), 'dport': porta}
        else:
            if tipo not in {'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'}:
                raise ValueError('Método HTTP inválido')
            ip = str(ip_address(campos['ip']))
            status = int(campos['status'])
            if not 100 <= status <= 599:
                raise ValueError('Status HTTP inválido')
            atributos = {'url': campos['url'], 'status': status}
        detalhes = ' '.join(f'{chave}={valor}' for chave, valor in atributos.items())
        return {
            'timestamp': timestamp, 'fonte': fonte, 'tipo': tipo, 'ip': ip,
            'detalhes': detalhes, 'atributos': atributos, 'linha_original': linha.strip(),
        }
    except (ValueError, KeyError):
        return None


def parsear_linha_auth(linha):
    return _parsear(linha, 'auth')


def parsear_linha_firewall(linha):
    return _parsear(linha, 'firewall')


def parsear_linha_web(linha):
    return _parsear(linha, 'web')


def carregar_log(caminho_arquivo, fonte):
    parsers = {'auth': parsear_linha_auth, 'firewall': parsear_linha_firewall, 'web': parsear_linha_web}
    if fonte not in parsers:
        raise ValueError('Fonte desconhecida')
    eventos = []
    try:
        with Path(caminho_arquivo).open(encoding='utf-8-sig') as arquivo:
            for numero, linha in enumerate(arquivo, 1):
                if not linha.strip():
                    continue
                evento = parsers[fonte](linha)
                if evento is None:
                    # Não registrar a linha crua: ela pode conter dados sensíveis.
                    logger.warning('Linha inválida ignorada: %s, linha %d', Path(caminho_arquivo).name, numero)
                else:
                    eventos.append(evento)
    except (OSError, UnicodeError):
        logger.warning('Não foi possível ler o log %s', Path(caminho_arquivo).name)
    return eventos


def carregar_todos_os_logs(pasta_logs):
    eventos = []
    for nome, fonte in ARQUIVOS.items():
        lote = carregar_log(Path(pasta_logs) / nome, fonte)
        logger.info('%s: %d eventos válidos', nome, len(lote))
        eventos.extend(lote)
    return eventos


def atributos_do_evento(evento):
    """Aceita também o formato antigo, que só tinha `detalhes` como texto."""
    if isinstance(evento.get('atributos'), dict):
        return evento['atributos']
    return dict(parte.split('=', 1) for parte in evento.get('detalhes', '').split() if '=' in parte)
