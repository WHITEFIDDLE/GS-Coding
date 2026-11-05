"""Orquestração ponta a ponta usada pela API e pelo dashboard (seção 4 da GS).

Ordem do fluxo:
1. coletor (módulo A) -> 2. regras -> 3. detector -> 4. score de ML (módulo C)
-> 5. persistência no MongoDB (módulo B) -> 6. alertas críticos via TCP.
O score é calculado antes de gravar para que cada alerta já seja salvo com o
risco do seu IP; nenhuma etapa reimplementa a lógica de outro módulo.
"""
import logging
import time
from collections import Counter
from pathlib import Path

from core.coletor import parsear_linha_auth, parsear_linha_firewall, parsear_linha_web
from ml.classificar import carregar_modelo, pontuar_ips
from ml.features import FEATURE_NAMES, extract_features_by_ip, load_suspicious_patterns
from servicos.analise import analisar_eventos, carregar_blacklist
from core.regras import carregar_regras

logger = logging.getLogger(__name__)
PARSERS = {'auth': parsear_linha_auth, 'firewall': parsear_linha_firewall, 'web': parsear_linha_web}
LIMITE_LOTE = 5000
ORDEM_SEVERIDADE = {'CRITICA': 0, 'ALTA': 1, 'MEDIA': 2, 'BAIXA': 3, 'INFO': 4}


class Contexto:
    """Regras, blacklist, padrões e modelo carregados uma única vez."""

    def __init__(self, pasta_projeto, modelo=None):
        pasta = Path(pasta_projeto)
        self.pasta_logs = (pasta / 'logs').resolve()
        self.regras = carregar_regras(pasta / 'config' / 'regras.json')
        if not self.regras:
            raise ValueError('Nenhuma regra ativa válida. Confira config/regras.json.')
        self.blacklist = carregar_blacklist(pasta / 'config' / 'blacklist.json')
        self.padroes = load_suspicious_patterns(str(pasta / 'config' / 'regras.json'))
        # carregar_modelo verifica o SHA-256 antes de desserializar (cenário C4).
        self.modelo = modelo if modelo is not None else carregar_modelo()


def eventos_do_lote(lote):
    """Valida um lote [{fonte, linha}] com os mesmos parsers do núcleo."""
    if not isinstance(lote, list) or not 1 <= len(lote) <= LIMITE_LOTE:
        raise ValueError(f'"eventos" deve ser uma lista com 1 a {LIMITE_LOTE} itens')
    eventos = []
    for posicao, item in enumerate(lote, 1):
        if not isinstance(item, dict) or item.get('fonte') not in PARSERS:
            raise ValueError(f'Item {posicao}: "fonte" deve ser auth, firewall ou web')
        linha = item.get('linha')
        if not isinstance(linha, str) or not 1 <= len(linha) <= 2000:
            raise ValueError(f'Item {posicao}: "linha" deve ser texto de até 2000 caracteres')
        evento = PARSERS[item['fonte']](linha)
        if evento is None:
            raise ValueError(f'Item {posicao}: linha fora do formato do log {item["fonte"]}')
        eventos.append(evento)
    return eventos


def pasta_de_logs_permitida(contexto, relativo):
    """Resolve uma pasta dentro de logs/; recusa caminho absoluto e '..' (path traversal)."""
    if not isinstance(relativo, str) or len(relativo) > 200:
        raise ValueError('"caminho" deve ser texto')
    destino = (contexto.pasta_logs / relativo).resolve()
    if destino != contexto.pasta_logs and contexto.pasta_logs not in destino.parents:
        raise ValueError('"caminho" deve ficar dentro da pasta logs/')
    if not destino.is_dir():
        raise ValueError('Pasta de logs inexistente')
    return destino


def pontuar(eventos, contexto):
    """{ip: {score, rotulo, nivel, features}} a partir de qualquer lista de eventos."""
    features = extract_features_by_ip(eventos, contexto.blacklist, contexto.padroes)
    return pontuar_ips(features, contexto.modelo) if features else {}


def score_vazio(ip):
    return {'ip': ip, 'score': 0.0, 'rotulo': 'normal', 'nivel': 'BAIXO',
            'features': {nome: 0 for nome in FEATURE_NAMES}}


def analisar_e_persistir(eventos, contexto, repositorio, publicar=None):
    """Executa o fluxo completo e devolve um resumo serializável."""
    analise = analisar_eventos(eventos, contexto.regras, contexto.blacklist)
    scores = pontuar(analise['eventos'], contexto)
    for alerta in analise['alertas']:
        info = scores.get(alerta['ip'])
        if info:
            alerta['score_ml'] = info['score']
            alerta['nivel_ml'] = info['nivel']
    for ameaca in analise['ameacas']:
        ameaca['score_ml'] = scores.get(ameaca['ip'], score_vazio(ameaca['ip']))['score']

    persistencia = {
        'eventos': repositorio.salvar_eventos(analise['eventos']),
        'alertas': repositorio.salvar_alertas(analise['alertas']),
    }
    resumo = {
        'total_eventos': len(analise['eventos']),
        'total_alertas': len(analise['alertas']),
        'eventos_por_fonte': dict(Counter(e['fonte'] for e in analise['eventos'])),
        'alertas_por_severidade': dict(Counter(a['severidade'] for a in analise['alertas'])),
        'ameacas': sorted(analise['ameacas'], key=lambda a: (-a['score_ml'], a['ip'])),
        'persistencia': persistencia,
        'publicados_tcp': 0,
    }
    if publicar is not None:
        try:
            resumo['publicados_tcp'] = publicar(analise['alertas'])
        except (OSError, ValueError):
            # Os dados já estão no banco; a falha do canal TCP não desfaz a análise.
            logger.warning('Servidor de alertas TCP indisponível')
            resumo['aviso_tcp'] = 'Dados persistidos, mas os alertas críticos não foram publicados no TCP.'
    return resumo


def todos_os_eventos(repositorio, limite=10000, **filtros):
    """Percorre a paginação do repositório (máx. 100 por página)."""
    eventos, pagina = [], 1
    while len(eventos) < limite:
        lote = repositorio.buscar_eventos(pagina=pagina, tamanho=100, **filtros)
        eventos.extend(lote['itens'])
        if pagina * 100 >= lote['total'] or not lote['itens']:
            break
        pagina += 1
    return eventos[:limite]


def todos_os_alertas(repositorio, limite=2000, **filtros):
    alertas, pagina = [], 1
    while len(alertas) < limite:
        lote = repositorio.buscar_alertas(pagina=pagina, tamanho=100, **filtros)
        alertas.extend(lote['itens'])
        if pagina * 100 >= lote['total'] or not lote['itens']:
            break
        pagina += 1
    return alertas[:limite]


def alerta_mais_grave(alertas):
    if not alertas:
        return None
    return min(alertas, key=lambda a: ORDEM_SEVERIDADE.get(a.get('severidade'), 9))


def geolocalizador(consultar_ip, segundos_falha=60):
    """Usa o cache do módulo A, mas não guarda para sempre uma consulta que falhou.

    `consultar_ip` grava no cache também o resultado padrão de quando o
    ipinfo.io não responde; aqui essa falha expira e a consulta é refeita.
    """
    cache, falhas = {}, {}

    def geolocalizar(ip):
        if ip in falhas and time.monotonic() - falhas[ip] >= segundos_falha:
            cache.pop(ip, None)
            falhas.pop(ip, None)
        resultado = consultar_ip(ip, cache)
        if not resultado.get('consultado') and not resultado.get('privado'):
            falhas.setdefault(ip, time.monotonic())
        return resultado
    return geolocalizar
