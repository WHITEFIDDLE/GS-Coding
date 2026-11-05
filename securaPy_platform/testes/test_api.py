"""Contrato HTTP e autorização, sem exigir serviços externos."""
from unittest.mock import create_autospec

import pytest
from itsdangerous import TimestampSigner

from api import criar_app
from db.erros import ErroPersistencia, UsuarioDuplicado
from db.mongo_repo import RepositorioMongo
from db.mysql_repo import RepositorioUsuarios


@pytest.fixture()
def api():
    mongo = create_autospec(RepositorioMongo, instance=True)
    mongo.fuso_logs = 'America/Sao_Paulo'
    validador = object.__new__(RepositorioMongo)
    validador.fuso_logs = mongo.fuso_logs
    mongo._filtro.side_effect = validador._filtro
    mongo.buscar_eventos.return_value = {'itens': [], 'total': 0, 'pagina': 1, 'tamanho': 20}
    mongo.buscar_alertas.return_value = {'itens': [], 'total': 0, 'pagina': 1, 'tamanho': 20}
    mongo.buscar_alerta.return_value = None
    mongo.salvar_alertas.return_value = {'recebidos': 1, 'inseridos': 1, 'existentes': 0}
    mongo.top_ips.return_value = []
    mongo.contar_por_fonte.return_value = []
    mongo.contar_por_severidade.return_value = []
    usuarios = create_autospec(RepositorioUsuarios, instance=True)
    admin = {'id': 1, 'nome': 'Pedro', 'email': 'pedro@example.test', 'nivel_acesso': 5}
    usuarios.autenticar.return_value = admin.copy()
    usuarios.buscar_usuario.return_value = admin.copy()
    usuarios.listar_usuarios.return_value = [admin.copy()]
    app = criar_app({'TESTING': True, 'SECRET_KEY': 'a' * 64, 'TOKEN_TTL': 60}, mongo=mongo, usuarios=usuarios)
    return app, app.test_client(), mongo, usuarios


def token(cliente):
    resposta = cliente.post('/api/login', json={'email': 'pedro@example.test', 'senha': 'senha-teste-segura'})
    assert resposta.status_code == 200
    return {'Authorization': 'Bearer ' + resposta.json['access_token']}


def test_config_sem_chave():
    with pytest.raises(ValueError):
        criar_app({'SECRET_KEY': ''})


@pytest.mark.parametrize('rota', ['/api/me', '/api/eventos', '/api/alertas', '/api/resumo', '/api/usuarios'])
def test_token_obrigatorio(api, rota):
    _, cliente, _, _ = api
    resposta = cliente.get(rota)
    assert resposta.status_code == 401
    assert resposta.headers['WWW-Authenticate'] == 'Bearer'


def test_login_e_token_adulterado(api):
    _, cliente, _, _ = api
    headers = token(cliente)
    assert cliente.get('/api/me', headers=headers).json['id'] == 1
    headers['Authorization'] += 'alteracao'
    assert cliente.get('/api/me', headers=headers).status_code == 401


def test_token_expirado(api, monkeypatch):
    _, cliente, _, _ = api
    monkeypatch.setattr(TimestampSigner, 'get_timestamp', lambda self: 1000)
    headers = token(cliente)
    monkeypatch.setattr(TimestampSigner, 'get_timestamp', lambda self: 1061)
    assert cliente.get('/api/me', headers=headers).status_code == 401


def test_remocao_e_rebaixamento_imediatos(api):
    _, cliente, _, usuarios = api
    headers = token(cliente)
    usuarios.buscar_usuario.return_value['nivel_acesso'] = 1
    assert cliente.get('/api/usuarios', headers=headers).status_code == 403
    assert cliente.get('/api/eventos', headers=headers).status_code == 200
    usuarios.buscar_usuario.return_value = None
    assert cliente.get('/api/me', headers=headers).status_code == 401


def test_falha_login_generica(api):
    _, cliente, _, usuarios = api
    usuarios.autenticar.return_value = None
    resposta = cliente.post('/api/login', json={'email': 'ausente@example.test', 'senha': 'incorreta'})
    assert resposta.status_code == 401
    assert 'ausente' not in resposta.get_data(as_text=True)


@pytest.mark.parametrize('dados', [None, [], {}, {'email': {}, 'senha': 'ok'},
                                    {'email': 'a', 'senha': 'b', 'nivel_acesso': 5}])
def test_json_invalido(api, dados):
    _, cliente, _, _ = api
    resposta = cliente.post('/api/login', json=dados)
    assert resposta.status_code in (400, 415)


def test_json_quebrado_tamanho_e_tipo(api):
    _, cliente, _, _ = api
    assert cliente.post('/api/login', data='{', content_type='application/json').status_code == 400
    assert cliente.post('/api/login', data='texto').status_code == 415
    assert cliente.post('/api/login', data='x' * 65537, content_type='application/json').status_code == 413


@pytest.mark.parametrize('query', ['pagina=0', 'pagina=abc', 'tamanho=101', 'tamanho=-1',
    'pagina=1&pagina=2', 'ip=nao-e-ip', 'fonte=outra', 'inicio=ontem',
    'inicio=2026-02-02&fim=2026-01-01', '$where=1', 'severidade=ALTA'])
def test_filtros_invalidos(api, query):
    _, cliente, mongo, _ = api
    resposta = cliente.get('/api/eventos?' + query, headers=token(cliente))
    assert resposta.status_code == 400
    mongo.buscar_eventos.assert_not_called()


def test_paginacao_e_filtros_encaminhados(api):
    _, cliente, mongo, _ = api
    resposta = cliente.get('/api/eventos?pagina=2&tamanho=5&ip=185.220.101.1', headers=token(cliente))
    assert resposta.status_code == 200
    mongo.buscar_eventos.assert_called_once_with(pagina=2, tamanho=5, ip='185.220.101.1')


def test_alerta_ausente(api):
    _, cliente, _, _ = api
    assert cliente.get('/api/alertas/0123456789abcdef01234567', headers=token(cliente)).status_code == 404


def test_alerta_id_malformado(api):
    _, cliente, mongo, _ = api
    mongo.buscar_alerta.side_effect = ValueError('Identificador inválido')
    assert cliente.get('/api/alertas/abc', headers=token(cliente)).status_code == 400


def alerta():
    return {'timestamp': '2026-11-05T12:00:00Z', 'ip': '192.168.1.10', 'regra_id': 'MANUAL',
            'regra_nome': 'Teste', 'severidade': 'ALTA', 'descricao': '<script>alert(1)</script>'}


def test_alerta_manual_deduplicacao_e_permissao(api):
    _, cliente, mongo, usuarios = api
    headers = token(cliente)
    resposta = cliente.post('/api/alertas', json=alerta(), headers=headers)
    assert resposta.status_code == 201
    salvo = mongo.salvar_alertas.call_args.args[0][0]
    assert salvo['origem'] == 'api' and salvo['fonte'] == 'manual'
    assert salvo['descricao'] == alerta()['descricao']  # evidência preservada como dado JSON
    mongo.salvar_alertas.return_value = {'recebidos': 1, 'inseridos': 0, 'existentes': 1}
    assert cliente.post('/api/alertas', json=alerta(), headers=headers).status_code == 200
    usuarios.buscar_usuario.return_value['nivel_acesso'] = 2
    assert cliente.post('/api/alertas', json=alerta(), headers=headers).status_code == 403


@pytest.mark.parametrize('campo,valor', [('ip', 123), ('severidade', 'URGENTE'), ('timestamp', 'ontem'), ('descricao', None)])
def test_validacao_alerta(api, campo, valor):
    _, cliente, mongo, _ = api
    dados = alerta(); dados[campo] = valor
    assert cliente.post('/api/alertas', json=dados, headers=token(cliente)).status_code == 400
    mongo.salvar_alertas.assert_not_called()


def test_crud_usuarios(api):
    _, cliente, _, usuarios = api
    headers = token(cliente)
    novo = {'id': 2, 'nome': 'Operador', 'email': 'op@example.test', 'nivel_acesso': 1}
    usuarios.criar_usuario.return_value = novo
    resposta = cliente.post('/api/usuarios', json={k: v for k, v in dict(novo, senha='senha-segura-123').items() if k != 'id'}, headers=headers)
    assert resposta.status_code == 201 and resposta.headers['Location'] == '/api/usuarios/2'
    assert 'senha' not in resposta.json
    usuarios.atualizar_usuario.return_value = dict(novo, nome='Novo')
    assert cliente.patch('/api/usuarios/2', json={'nome': 'Novo'}, headers=headers).json['nome'] == 'Novo'
    usuarios.atualizar_usuario.assert_called_once_with(2, nome='Novo')
    usuarios.remover_usuario.return_value = True
    assert cliente.delete('/api/usuarios/2', headers=headers).status_code == 204


@pytest.mark.parametrize('dados', [{}, {'senha': 'curta'}, {'nivel_acesso': True}, {'nivel_acesso': 6}, {'email': None}, {'senha_hash': 'qualquer'}])
def test_usuario_campos_invalidos(api, dados):
    _, cliente, _, usuarios = api
    assert cliente.patch('/api/usuarios/2', json=dados, headers=token(cliente)).status_code == 400
    usuarios.atualizar_usuario.assert_not_called()


def test_duplicidade_e_falhas_sem_detalhes(api):
    _, cliente, mongo, usuarios = api
    headers = token(cliente)
    usuarios.criar_usuario.side_effect = UsuarioDuplicado('SQL segredo')
    dados = {'nome': 'Teste', 'email': 'a@example.test', 'senha': 'senha-segura-123'}
    assert cliente.post('/api/usuarios', json=dados, headers=headers).status_code == 409
    for erro, status in [(ErroPersistencia('senha-do-banco'), 503), (RuntimeError('segredo'), 500)]:
        mongo.buscar_eventos.side_effect = erro
        resposta = cliente.get('/api/eventos', headers=headers)
        assert resposta.status_code == status
        assert 'segredo' not in resposta.get_data(as_text=True)
        assert 'senha-do-banco' not in resposta.get_data(as_text=True)


def test_health_ready_e_headers(api):
    _, cliente, mongo, _ = api
    for rota, status in [('/health', 200), ('/ready', 200), ('/ausente', 404), ('/api/me', 401)]:
        resposta = cliente.get(rota)
        assert resposta.status_code == status
        assert resposta.is_json
        assert resposta.headers['X-Content-Type-Options'] == 'nosniff'
        assert resposta.headers['Cache-Control'] == 'no-store'
    mongo.buscar_eventos.side_effect = ErroPersistencia('offline')
    assert cliente.get('/ready').status_code == 503
    assert cliente.get('/health').status_code == 200


def test_metodo_invalido_preserva_allow(api):
    _, cliente, _, _ = api
    resposta = cliente.get('/api/login')
    assert resposta.status_code == 405 and 'POST' in resposta.headers['Allow']
