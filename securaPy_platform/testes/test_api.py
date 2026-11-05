"""Módulo D (API) e integração com B, C, E e G, sem bancos reais.

Os repositórios falsos usam a mesma preparação de documentos do módulo B
(preparar_documento/para_json), inclusive a chave que evita duplicatas.
D1  GET /api/alertas?severidade=critica&pagina=1&tamanho=5 -> críticos paginados
D2  GET /api/ip/185.220.101.1 -> eventos + alertas + geo + score
D3  POST /api/alertas sem token -> 401
D4  POST /api/alertas com corpo inválido -> 400
D5  GET /api/ip/<malformado> -> 400 amigável
"""
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from bson import ObjectId

from api.app import criar_api
from api.auth import gerar_token
from configuracao import PASTA_PROJETO
from db.documentos import para_json, preparar_documento
from db.erros import ErroPersistencia
from ia.assistente import AssistenteLLM
from servicos.plataforma import Contexto

SEGREDO = 'segredo-de-teste-com-mais-de-32-caracteres!'
OUTRO_SEGREDO = 'outro-segredo-de-teste-com-mais-de-32-caracteres'


class MongoFalso:
    """Imita o RepositorioMongo: deduplica por chave, filtra e pagina."""

    def __init__(self):
        self.colecoes = {'evento': {}, 'alerta': {}}
        self.falhar = None

    def _checar(self):
        if self.falhar:
            raise self.falhar

    def _salvar(self, documentos, tipo):
        self._checar()
        inseridos = 0
        for documento in documentos:
            novo = preparar_documento(documento, tipo, 'America/Sao_Paulo')
            if novo['chave_' + tipo] not in self.colecoes[tipo]:
                novo['_id'] = ObjectId()
                self.colecoes[tipo][novo['chave_' + tipo]] = novo
                inseridos += 1
        return {'recebidos': len(documentos), 'inseridos': inseridos, 'existentes': len(documentos) - inseridos}

    def salvar_eventos(self, eventos):
        return self._salvar(list(eventos), 'evento')

    def salvar_alertas(self, alertas):
        return self._salvar(list(alertas), 'alerta')

    def registrar_alerta(self, alerta):
        self._salvar([alerta], 'alerta')
        chave = preparar_documento(alerta, 'alerta', 'America/Sao_Paulo')['chave_alerta']
        return para_json(self.colecoes['alerta'][chave])

    def _buscar(self, tipo, pagina, tamanho, filtros):
        self._checar()
        if not 1 <= tamanho <= 100 or pagina < 1:
            raise ValueError('Paginação inválida')
        if filtros.get('fonte') and filtros['fonte'] not in {'auth', 'firewall', 'web'}:
            raise ValueError('Fonte inválida')  # mesma regra de RepositorioMongo._filtro
        itens = list(self.colecoes[tipo].values())
        for campo in ('fonte', 'tipo', 'ip'):
            if filtros.get(campo):
                itens = [d for d in itens if d.get(campo) == filtros[campo]]
        if filtros.get('severidade'):
            severidade = filtros['severidade'].upper()
            if severidade not in {'INFO', 'BAIXA', 'MEDIA', 'ALTA', 'CRITICA'}:
                raise ValueError('Severidade inválida')
            itens = [d for d in itens if d['severidade'] == severidade]
        itens.sort(key=lambda d: d['timestamp'], reverse=True)
        inicio = (pagina - 1) * tamanho
        return {'itens': para_json(itens[inicio:inicio + tamanho]), 'total': len(itens),
                'pagina': pagina, 'tamanho': tamanho}

    def buscar_eventos(self, pagina=1, tamanho=20, **filtros):
        return self._buscar('evento', pagina, tamanho, filtros)

    def buscar_alertas(self, pagina=1, tamanho=20, **filtros):
        return self._buscar('alerta', pagina, tamanho, filtros)

    def buscar_alerta(self, alerta_id):
        if not ObjectId.is_valid(alerta_id):
            raise ValueError('Identificador de alerta inválido')
        for documento in self.colecoes['alerta'].values():
            if documento['_id'] == ObjectId(alerta_id):
                return para_json(documento)
        return None

    def contar_por_fonte(self):
        self._checar()
        total = {}
        for d in self.colecoes['evento'].values():
            total[d['fonte']] = total.get(d['fonte'], 0) + 1
        return [{'fonte': f, 't': 0, 'total': n} for f, n in sorted(total.items())]

    def contar_por_severidade(self):
        total = {}
        for d in self.colecoes['alerta'].values():
            total[d['severidade']] = total.get(d['severidade'], 0) + 1
        return [{'severidade': s, 'total': n} for s, n in sorted(total.items())]

    def top_ips(self, limite=5):
        total = {}
        for d in self.colecoes['evento'].values():
            total[d['ip']] = total.get(d['ip'], 0) + 1
        return [{'ip': ip, 'total': n} for ip, n in sorted(total.items(), key=lambda x: (-x[1], x[0]))][:limite]


class UsuariosFalsos:
    CONTAS = {
        'admin@securapy.test': ('SenhaCorreta!2025', {'id': 1, 'nome': 'Admin', 'nivel_acesso': 5}),
        'leitor@securapy.test': ('SenhaDoLeitor!2025', {'id': 2, 'nome': 'Leitor', 'nivel_acesso': 1}),
    }

    def autenticar(self, email, senha):
        conta = self.CONTAS.get(email)
        if not conta or conta[0] != senha:
            return None
        return {**conta[1], 'email': email}


@pytest.fixture(scope='module')
def contexto():
    return Contexto(PASTA_PROJETO)


@pytest.fixture
def repo():
    return MongoFalso()


@pytest.fixture
def publicados():
    return []


@pytest.fixture
def api(repo, contexto, publicados):
    def publicar(alertas):
        criticos = [a for a in alertas if a['severidade'] == 'CRITICA']
        publicados.extend(criticos)
        return len(criticos)

    app = criar_api(repo, UsuariosFalsos(), contexto, SEGREDO, assistente=AssistenteLLM(api_key=None),
                    geolocalizar=lambda ip: {'ip': ip, 'pais': 'DE', 'cidade': 'Frankfurt', 'org': 'AS Teste'},
                    publicar=publicar)
    app.config['TESTING'] = True
    return app.test_client()


def _token(cliente, email='admin@securapy.test', senha='SenhaCorreta!2025'):
    resposta = cliente.post('/api/auth/token', json={'email': email, 'senha': senha})
    assert resposta.status_code == 200
    return {'Authorization': 'Bearer ' + resposta.get_json()['token']}


@pytest.fixture
def analisado(api):
    resposta = api.post('/api/analisar', json={}, headers=_token(api))
    assert resposta.status_code == 200, resposta.get_json()
    return resposta.get_json()


# --------------------------------------------------------------------------- #
# Autenticação
# --------------------------------------------------------------------------- #
def test_token_com_credencial_errada_e_usuario_inexistente_mesma_resposta(api):
    errada = api.post('/api/auth/token', json={'email': 'admin@securapy.test', 'senha': 'errada'})
    inexistente = api.post('/api/auth/token', json={'email': 'ninguem@x.test', 'senha': 'errada'})
    assert errada.status_code == inexistente.status_code == 401
    assert errada.get_json() == inexistente.get_json()


def test_d3_post_alerta_sem_token_401(api):
    resposta = api.post('/api/alertas', json={'ip': '1.2.3.4', 'severidade': 'ALTA', 'descricao': 'x'})
    assert resposta.status_code == 401
    assert resposta.headers['WWW-Authenticate'] == 'Bearer'


@pytest.mark.parametrize('cabecalho', [
    'Bearer token-qualquer',
    'Basic YWRtaW46c2VuaGE=',
    'Bearer ' + jwt.encode({'sub': '1', 'nivel': 5}, None, algorithm='none'),
])
def test_token_invalido_ou_alg_none_401(api, cabecalho):
    resposta = api.post('/api/alertas', json={}, headers={'Authorization': cabecalho})
    assert resposta.status_code == 401


def test_token_expirado_ou_de_outra_chave_401(api):
    usuario = {'id': 1, 'email': 'admin@securapy.test', 'nivel_acesso': 5}
    expirado = gerar_token(usuario, SEGREDO, minutos=-1)
    forjado = gerar_token(usuario, OUTRO_SEGREDO)
    for token in (expirado, forjado):
        resposta = api.post('/api/alertas', json={}, headers={'Authorization': 'Bearer ' + token})
        assert resposta.status_code == 401


def test_nivel_insuficiente_403(api):
    cabecalho = _token(api, 'leitor@securapy.test', 'SenhaDoLeitor!2025')
    resposta = api.post('/api/alertas', json={'ip': '1.2.3.4', 'severidade': 'ALTA', 'descricao': 'x'},
                        headers=cabecalho)
    assert resposta.status_code == 403


# --------------------------------------------------------------------------- #
# Análise ponta a ponta pela API (A + B + C + TCP)
# --------------------------------------------------------------------------- #
def test_analisar_persiste_58_eventos_e_publica_criticos(analisado, publicados):
    assert analisado['total_eventos'] == 58
    assert analisado['eventos_por_fonte'] == {'auth': 23, 'firewall': 17, 'web': 18}
    assert analisado['persistencia']['eventos']['inseridos'] == 58
    assert analisado['publicados_tcp'] == len(publicados) > 0
    primeira = analisado['ameacas'][0]
    assert primeira['ip'] == '185.220.101.1' and primeira['score_ml'] >= 0.75


def test_analisar_de_novo_nao_duplica(api, analisado):
    segunda = api.post('/api/analisar', json={}, headers=_token(api)).get_json()
    assert segunda['persistencia']['eventos']['inseridos'] == 0
    assert segunda['persistencia']['alertas']['inseridos'] == 0


def test_analisar_lote_de_eventos(api):
    lote = [{'fonte': 'web', 'linha': '2025-02-20 10:00:00 GET ip=203.0.113.9 url=/../../etc/passwd status=404'},
            {'fonte': 'auth', 'linha': '2025-02-20 10:00:01 FAIL usuario=root ip=203.0.113.9'}]
    resposta = api.post('/api/analisar', json={'eventos': lote}, headers=_token(api))
    assert resposta.status_code == 200
    assert resposta.get_json()['total_eventos'] == 2
    assert resposta.get_json()['alertas_por_severidade'].get('CRITICA', 0) >= 1


@pytest.mark.parametrize('corpo', [
    {'caminho': '..'}, {'caminho': '../../'}, {'caminho': 'C:/Windows'}, {'caminho': 'nao_existe'},
    {'eventos': []}, {'eventos': [{'fonte': 'auth', 'linha': 'linha quebrada'}]},
    {'eventos': [{'fonte': 'outra', 'linha': 'x'}]}, {'caminho': '.', 'eventos': []},
])
def test_analisar_entrada_invalida_400(api, corpo):
    resposta = api.post('/api/analisar', json=corpo, headers=_token(api))
    assert resposta.status_code == 400
    assert 'erro' in resposta.get_json()


def test_falha_no_tcp_nao_derruba_a_analise(repo, contexto):
    def publicar(_alertas):
        raise OSError('conexão recusada')

    app = criar_api(repo, UsuariosFalsos(), contexto, SEGREDO, publicar=publicar).test_client()
    resposta = app.post('/api/analisar', json={}, headers=_token(app))
    assert resposta.status_code == 200
    assert 'aviso_tcp' in resposta.get_json()


# --------------------------------------------------------------------------- #
# Consultas (D1, D2, D5)
# --------------------------------------------------------------------------- #
def test_d1_alertas_criticos_paginados(api, analisado):
    resposta = api.get('/api/alertas?severidade=critica&pagina=1&tamanho=5')
    corpo = resposta.get_json()
    assert resposta.status_code == 200
    assert 0 < len(corpo['itens']) <= 5 and corpo['pagina'] == 1 and corpo['tamanho'] == 5
    assert all(item['severidade'] == 'CRITICA' for item in corpo['itens'])
    assert corpo['total'] >= len(corpo['itens'])


def test_eventos_com_filtros(api, analisado):
    corpo = api.get('/api/eventos?fonte=auth&tipo=FAIL&ip=185.220.101.1&tamanho=100').get_json()
    assert corpo['total'] == 11
    assert all(e['fonte'] == 'auth' and e['tipo'] == 'FAIL' for e in corpo['itens'])


@pytest.mark.parametrize('consulta', ['tamanho=0', 'tamanho=101', 'pagina=0', 'pagina=abc',
                                      'severidade=urgente', 'fonte=dns', 'ip=999.1.1.1'])
def test_parametros_invalidos_400(api, consulta):
    rota = '/api/eventos?' if consulta.startswith('fonte') else '/api/alertas?'
    assert api.get(rota + consulta).status_code == 400


def test_d2_detalhe_do_ip(api, analisado):
    corpo = api.get('/api/ip/185.220.101.1').get_json()
    assert corpo['total_eventos'] > 0 and corpo['total_alertas'] > 0
    assert corpo['geolocalizacao']['pais'] == 'DE'
    assert corpo['ml']['nivel'] == 'ALTO' and corpo['ml']['rotulo'] == 'ataque'
    assert corpo['assistente']['classificacao'] == 'CRÍTICO'


def test_ip_interno_normal(api, analisado):
    corpo = api.get('/api/ip/192.168.1.10').get_json()
    assert corpo['ml']['rotulo'] == 'normal'


@pytest.mark.parametrize('ip', ['abc', '999.999.1.1', '1.2.3', "1.1.1.1' OR '1'='1"])
def test_d5_ip_malformado_400(api, ip):
    resposta = api.get('/api/ip/' + ip)
    assert resposta.status_code == 400
    assert 'IP inválido' in resposta.get_json()['erro']


def test_alerta_por_id(api, analisado):
    item = api.get('/api/alertas?tamanho=1').get_json()['itens'][0]
    assert api.get('/api/alertas/' + item['id']).get_json()['id'] == item['id']
    assert api.get('/api/alertas/nao-e-objectid').status_code == 400
    assert api.get('/api/alertas/' + str(ObjectId())).status_code == 404


def test_resumo(api, analisado):
    corpo = api.get('/api/resumo').get_json()
    assert corpo['top_ips'][0]['ip'] == '185.220.101.1'


# --------------------------------------------------------------------------- #
# Escrita (D4) e XSS (E1 pela API)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize('corpo', [
    {}, {'ip': '1.2.3.4', 'severidade': 'URGENTE', 'descricao': 'x'},
    {'ip': 'abc', 'severidade': 'ALTA', 'descricao': 'x'},
    {'ip': '1.2.3.4', 'severidade': 'ALTA', 'descricao': ''},
    {'ip': '1.2.3.4', 'severidade': 'ALTA', 'descricao': 'x' * 501},
    {'ip': '1.2.3.4', 'severidade': 'ALTA', 'descricao': 'x', 'admin': True},
    {'ip': ['1.2.3.4'], 'severidade': 'ALTA', 'descricao': 'x'},
])
def test_d4_corpo_invalido_400(api, corpo):
    resposta = api.post('/api/alertas', json=corpo, headers=_token(api))
    assert resposta.status_code == 400


def test_d4_corpo_que_nao_e_json_400(api):
    resposta = api.post('/api/alertas', data='ip=1.2.3.4', headers=_token(api),
                        content_type='application/x-www-form-urlencoded')
    assert resposta.status_code == 400


def test_criar_alerta_201_e_xss_guardado_como_dado(api):
    resposta = api.post('/api/alertas', headers=_token(api), json={
        'ip': '203.0.113.77', 'severidade': 'alta', 'descricao': '<script>alert(1)</script>'})
    assert resposta.status_code == 201
    corpo = resposta.get_json()
    assert corpo['id'] and corpo['severidade'] == 'ALTA' and corpo['criado_por'] == 'admin@securapy.test'
    assert resposta.headers['Content-Type'].startswith('application/json')
    assert resposta.headers['X-Content-Type-Options'] == 'nosniff'


# --------------------------------------------------------------------------- #
# Erros sem vazamento
# --------------------------------------------------------------------------- #
def test_headers_de_seguranca_em_toda_resposta(api):
    for rota in ('/api/saude', '/api/eventos', '/api/inexistente'):
        resposta = api.get(rota)
        for nome in ('X-Content-Type-Options', 'X-Frame-Options', 'Content-Security-Policy'):
            assert nome in resposta.headers


def test_404_e_405_em_json(api):
    assert api.get('/api/inexistente').status_code == 404
    assert api.delete('/api/alertas').status_code == 405
    assert 'erro' in api.get('/api/inexistente').get_json()


def test_banco_fora_do_ar_503_sem_detalhes(api, repo):
    repo.falhar = ErroPersistencia('Não foi possível concluir a operação no MongoDB.')
    resposta = api.get('/api/eventos')
    assert resposta.status_code == 503
    assert 'Mongo' not in resposta.get_data(as_text=True)
    assert api.get('/api/saude').status_code == 503


def test_erro_inesperado_500_sem_traceback(api, repo):
    repo.falhar = RuntimeError('mongodb://usuario:senha-secreta@host interno')
    resposta = api.get('/api/eventos')
    texto = resposta.get_data(as_text=True)
    assert resposta.status_code == 500
    assert 'senha-secreta' not in texto and 'Traceback' not in texto


def test_segredo_jwt_curto_e_recusado(repo, contexto):
    with pytest.raises(ValueError):
        criar_api(repo, UsuariosFalsos(), contexto, 'curto')


# --------------------------------------------------------------------------- #
# Integração com o dashboard (E) usando os mesmos dados do MongoDB
# --------------------------------------------------------------------------- #
def test_dashboard_le_o_que_a_api_gravou_e_escapa_xss(api, repo, contexto, tmp_path):
    from web.dashboard import criar_app
    from web.providers import RepositorioDataProvider
    from web.usuarios import MySQLUserStore

    api.post('/api/analisar', json={}, headers=_token(api))
    api.post('/api/alertas', headers=_token(api), json={
        'ip': '203.0.113.77', 'severidade': 'ALTA', 'descricao': '<script>alert(1)</script>'})

    class RepoUsuariosMySQL:  # mesmo contrato de db/mysql_repo.RepositorioUsuarios.autenticar
        def autenticar(self, email, senha):
            return UsuariosFalsos().autenticar(email, senha)

    painel = criar_app(data_provider=RepositorioDataProvider(repo, contexto),
                       user_store=MySQLUserStore(RepoUsuariosMySQL()),
                       assistente=AssistenteLLM(api_key=None),
                       caminho_log_acesso=str(tmp_path / 'access.log')).test_client()
    assert painel.post('/login', data={'login': 'admin@securapy.test', 'senha': 'errada'}).status_code == 401
    login = painel.post('/login', data={'login': 'admin@securapy.test', 'senha': 'SenhaCorreta!2025'})
    assert login.status_code == 302

    inicio = painel.get('/').get_data(as_text=True)
    assert '185.220.101.1' in inicio
    alertas = painel.get('/alertas').get_data(as_text=True)
    assert '&lt;script&gt;alert(1)&lt;/script&gt;' in alertas and '<script>alert(1)' not in alertas
    busca = painel.get('/busca?ip=185.220.101.1').get_data(as_text=True)
    assert 'CRÍTICO' in busca


def test_geolocalizacao_que_falhou_e_refeita_depois(monkeypatch):
    from servicos.plataforma import geolocalizador
    chamadas = []

    def consultar_ip(ip, cache):
        if ip in cache:
            return dict(cache[ip])
        chamadas.append(ip)
        cache[ip] = {'ip': ip, 'privado': False, 'consultado': len(chamadas) > 1, 'pais': 'DE'}
        return dict(cache[ip])

    geolocalizar = geolocalizador(consultar_ip, segundos_falha=0)
    assert geolocalizar('185.220.101.1')['consultado'] is False
    assert geolocalizar('185.220.101.1')['consultado'] is True   # falha expirou e foi refeita
    assert geolocalizar('185.220.101.1')['consultado'] is True   # sucesso fica no cache
    assert len(chamadas) == 2
