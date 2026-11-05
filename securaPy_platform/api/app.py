"""API REST do SecuraPy Platform (módulo D — Aulas 6, 7 e 10).

As rotas só validam a entrada, chamam os serviços/repositórios dos outros
módulos e convertem o resultado em JSON. Nenhuma regra de detecção, SQL ou
consulta MongoDB é reescrita aqui.
"""
import logging
import time
from datetime import datetime, timezone
from ipaddress import ip_address

from flask import Blueprint, Flask, g, jsonify, request
from werkzeug.exceptions import HTTPException

from api.auth import exigir_token, gerar_token, validar_segredo
from db.erros import ErroPersistencia
from servicos import plataforma

logger = logging.getLogger('securaPy.api')
SEVERIDADES = ('CRITICA', 'ALTA', 'MEDIA', 'BAIXA', 'INFO')
CAMPOS_ALERTA = {'ip', 'severidade', 'descricao', 'regra_nome'}
HEADERS_API = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
    'Cache-Control': 'no-store',
    'Referrer-Policy': 'no-referrer',
}


class ErroEntrada(ValueError):
    """Entrada inválida do cliente: vira 400 com mensagem amigável."""


def _inteiro(nome, padrao, minimo, maximo):
    valor = request.args.get(nome)
    if valor is None:
        return padrao
    if not valor.isdigit() or not minimo <= int(valor) <= maximo:
        raise ErroEntrada(f'"{nome}" deve ser um inteiro entre {minimo} e {maximo}')
    return int(valor)


def _filtros(permitidos):
    return {nome: request.args[nome] for nome in permitidos if request.args.get(nome)}


def _ip_valido(texto):
    try:
        return str(ip_address(texto))
    except ValueError:
        raise ErroEntrada('IP inválido. Exemplo: 185.220.101.1') from None


def _corpo_json():
    dados = request.get_json(silent=True)
    if not isinstance(dados, dict):
        raise ErroEntrada('Envie um objeto JSON com Content-Type: application/json')
    return dados


def _validar_alerta(dados):
    extras = set(dados) - CAMPOS_ALERTA
    if extras:
        raise ErroEntrada('Campos não permitidos: ' + ', '.join(sorted(extras)))
    severidade = dados.get('severidade')
    if not isinstance(severidade, str) or severidade.upper() not in SEVERIDADES:
        raise ErroEntrada('"severidade" deve ser: ' + ', '.join(SEVERIDADES))
    descricao = dados.get('descricao')
    if not isinstance(descricao, str) or not 1 <= len(descricao.strip()) <= 500:
        raise ErroEntrada('"descricao" deve ter de 1 a 500 caracteres')
    regra_nome = dados.get('regra_nome', 'Alerta manual via API')
    if not isinstance(regra_nome, str) or not 1 <= len(regra_nome.strip()) <= 100:
        raise ErroEntrada('"regra_nome" deve ter de 1 a 100 caracteres')
    if not isinstance(dados.get('ip'), str):
        raise ErroEntrada('"ip" é obrigatório')
    return {
        'timestamp': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'ip': _ip_valido(dados['ip']),
        'fonte': 'manual', 'origem': 'api',
        'regra_id': 'MANUAL', 'regra_nome': regra_nome.strip(),
        'severidade': severidade.upper(),
        # Texto guardado como dado; o dashboard escapa na exibição (cenário E1).
        'descricao': descricao.strip(),
    }


def criar_api(repositorio, usuarios, contexto, segredo_jwt, assistente=None,
              geolocalizar=None, publicar=None, prefixo='/api', minutos_token=30):
    """Fábrica da aplicação. Dependências injetadas facilitam os testes sem bancos."""
    app = Flask(__name__)
    app.config.update(API_JWT_SECRET=validar_segredo(segredo_jwt), MAX_CONTENT_LENGTH=2 * 1024 * 1024,
                      JSON_SORT_KEYS=False)
    app.json.ensure_ascii = False
    rotas = Blueprint('api', __name__)

    @app.before_request
    def _inicio():
        g.inicio = time.perf_counter()

    @app.after_request
    def _cabecalhos_e_log(resposta):
        for nome, valor in HEADERS_API.items():
            resposta.headers[nome] = valor
        operador = getattr(g, 'operador', {}).get('email', '-')
        duracao = (time.perf_counter() - getattr(g, 'inicio', time.perf_counter())) * 1000
        logger.info('%s "%s %s" %s operador=%s %.1fms', request.remote_addr, request.method,
                    request.script_root + request.path, resposta.status_code, operador, duracao)
        return resposta

    # ------------------------------------------------------------------ #
    @rotas.get('/saude')
    def saude():
        try:
            repositorio.contar_por_fonte()
            return jsonify({'status': 'ok', 'mongodb': 'ok'})
        except ErroPersistencia:
            return jsonify({'status': 'degradado', 'mongodb': 'indisponivel'}), 503

    @rotas.post('/auth/token')
    def emitir_token():
        dados = _corpo_json()
        usuario = usuarios.autenticar(dados.get('email'), dados.get('senha'))
        if usuario is None:
            # Mesma resposta para e-mail inexistente e senha errada (anti-enumeração).
            return jsonify({'erro': 'Credenciais inválidas.'}), 401
        token = gerar_token(usuario, app.config['API_JWT_SECRET'], minutos_token)
        return jsonify({'token': token, 'tipo': 'Bearer', 'expira_em_minutos': minutos_token})

    @rotas.get('/eventos')
    def listar_eventos():
        filtros = _filtros(('fonte', 'tipo', 'ip', 'inicio', 'fim'))
        if 'ip' in filtros:
            filtros['ip'] = _ip_valido(filtros['ip'])
        return jsonify(repositorio.buscar_eventos(
            pagina=_inteiro('pagina', 1, 1, 100000), tamanho=_inteiro('tamanho', 20, 1, 100), **filtros))

    @rotas.get('/alertas')
    def listar_alertas():
        filtros = _filtros(('severidade', 'ip', 'fonte', 'inicio', 'fim'))
        if 'ip' in filtros:
            filtros['ip'] = _ip_valido(filtros['ip'])
        if 'fonte' in filtros:
            # Alertas também têm as fontes "correlacao" e "manual"; o filtro do
            # repositório de eventos só aceita as três fontes de log.
            fonte = filtros.pop('fonte')
            if fonte not in {'auth', 'firewall', 'web', 'correlacao', 'manual'}:
                raise ErroEntrada('"fonte" inválida')
            itens = [a for a in plataforma.todos_os_alertas(repositorio, **filtros) if a.get('fonte') == fonte]
            pagina, tamanho = _inteiro('pagina', 1, 1, 100000), _inteiro('tamanho', 20, 1, 100)
            inicio = (pagina - 1) * tamanho
            return jsonify({'itens': itens[inicio:inicio + tamanho], 'total': len(itens),
                            'pagina': pagina, 'tamanho': tamanho})
        return jsonify(repositorio.buscar_alertas(
            pagina=_inteiro('pagina', 1, 1, 100000), tamanho=_inteiro('tamanho', 20, 1, 100), **filtros))

    @rotas.get('/alertas/<alerta_id>')
    def obter_alerta(alerta_id):
        try:
            alerta = repositorio.buscar_alerta(alerta_id)
        except ValueError:
            raise ErroEntrada('Identificador de alerta inválido') from None
        if alerta is None:
            return jsonify({'erro': 'Alerta não encontrado.'}), 404
        return jsonify(alerta)

    @rotas.post('/alertas')
    @exigir_token(nivel_minimo=2)
    def criar_alerta():
        alerta = _validar_alerta(_corpo_json())
        alerta['criado_por'] = g.operador['email']
        return jsonify(repositorio.registrar_alerta(alerta)), 201

    @rotas.post('/analisar')
    @exigir_token(nivel_minimo=3)
    def analisar():
        dados = _corpo_json()
        if 'eventos' in dados and 'caminho' in dados:
            raise ErroEntrada('Envie "caminho" ou "eventos", não os dois')
        if 'eventos' in dados:
            eventos = plataforma.eventos_do_lote(dados['eventos'])
        else:
            from core.coletor import carregar_todos_os_logs
            pasta = plataforma.pasta_de_logs_permitida(contexto, dados.get('caminho', '.'))
            eventos = carregar_todos_os_logs(pasta)
            if not eventos:
                raise ErroEntrada('Nenhum evento válido encontrado nessa pasta')
        return jsonify(plataforma.analisar_e_persistir(eventos, contexto, repositorio, publicar))

    @rotas.get('/ip/<ip>')
    def detalhar_ip(ip):
        ip = _ip_valido(ip)
        eventos = plataforma.todos_os_eventos(repositorio, ip=ip)
        alertas = plataforma.todos_os_alertas(repositorio, ip=ip)
        score = plataforma.pontuar(eventos, contexto).get(ip) or plataforma.score_vazio(ip)
        score.pop('ip', None)
        alvo = plataforma.alerta_mais_grave(alertas) or (eventos[0] if eventos else None)
        return jsonify({
            'ip': ip,
            'total_eventos': len(eventos), 'eventos': eventos,
            'total_alertas': len(alertas), 'alertas': alertas,
            'geolocalizacao': geolocalizar(ip) if geolocalizar else None,
            'ml': score,
            'assistente': assistente.analisar_alerta(alvo) if assistente and alvo else None,
        })

    @rotas.get('/resumo')
    def resumo():
        return jsonify({'eventos_por_fonte': repositorio.contar_por_fonte(),
                        'alertas_por_severidade': repositorio.contar_por_severidade(),
                        'top_ips': repositorio.top_ips(_inteiro('limite', 5, 1, 100))})

    app.register_blueprint(rotas, url_prefix=prefixo or None)

    # ------------------------------------------------------------------ #
    # Erros: JSON, status correto e nenhum detalhe interno na resposta.
    @app.errorhandler(ErroEntrada)
    def _entrada(erro):
        return jsonify({'erro': str(erro)}), 400

    @app.errorhandler(ValueError)
    def _valor(erro):
        # ValueError vem das validações dos repositórios/serviços (mensagens nossas).
        return jsonify({'erro': str(erro) or 'Requisição inválida.'}), 400

    @app.errorhandler(ErroPersistencia)
    def _banco(_erro):
        logger.warning('Banco de dados indisponível em %s', request.path)
        return jsonify({'erro': 'Serviço de dados indisponível. Tente novamente.'}), 503

    @app.errorhandler(HTTPException)
    def _http(erro):
        return jsonify({'erro': erro.description if erro.code < 500 else 'Erro interno.'}), erro.code

    @app.errorhandler(Exception)
    def _inesperado(_erro):
        logger.exception('Erro inesperado em %s', request.path)
        return jsonify({'erro': 'Erro interno do servidor.'}), 500

    return app
