from uuid import uuid4

import mysql.connector
import pytest

from configuracao import PASTA_PROJETO, configuracao_mongo, configuracao_mysql
from db.erros import ErroPersistencia, UsuarioDuplicado
from db.mongo_repo import RepositorioMongo
from db.mysql_repo import RepositorioUsuarios
from servicos.analise import analisar_pasta
from servicos.ingestao import persistir_analise

pytestmark = pytest.mark.integracao


@pytest.fixture
def mongo():
    config = configuracao_mongo()
    config['banco'] = 'teste_ab_' + uuid4().hex
    with RepositorioMongo(**config) as repo:
        repo.preparar()
        yield repo
        # Apenas este banco temporário, criado pelo teste, é removido.
        repo.cliente.drop_database(config['banco'])


@pytest.fixture
def usuarios():
    repo = RepositorioUsuarios(configuracao_mysql())
    repo.preparar()
    criados = []
    yield repo, criados
    for usuario_id in criados:
        repo.remover_usuario(usuario_id)


def test_ingestao_idempotente_filtros_indices_e_agregacao(mongo):
    analise = analisar_pasta(PASTA_PROJETO / 'logs', PASTA_PROJETO / 'config/regras.json', PASTA_PROJETO / 'config/blacklist.json')
    primeira = persistir_analise(analise, mongo)
    segunda = persistir_analise(analise, mongo)
    assert primeira['eventos']['inseridos'] == 58
    assert segunda['eventos']['inseridos'] == 0
    assert segunda['alertas']['inseridos'] == 0
    assert mongo.buscar_eventos()['total'] == 58
    falhas = mongo.buscar_eventos(fonte='auth', tipo='FAIL', ip='185.220.101.1', tamanho=5)
    assert falhas['total'] == 11 and len(falhas['itens']) == 5
    assert len(mongo.buscar_eventos(fonte='auth', tipo='FAIL', ip='185.220.101.1', pagina=3, tamanho=5)['itens']) == 1
    assert mongo.buscar_eventos(inicio='2025-02-20T11:15:01Z', fim='2025-02-20T11:15:01Z')['total'] == 1
    assert mongo.top_ips()[0] == {'ip':'185.220.101.1', 'total':25}
    assert sum(item['total'] for item in mongo.contar_por_fonte()) == 58
    assert sum(item['total'] for item in mongo.contar_por_severidade()) == len(analise['alertas'])
    for colecao in (mongo.banco.eventos, mongo.banco.alertas):
        assert 'ip_1' in colecao.index_information()
        assert 'timestamp_1' in colecao.index_information()
    item = mongo.buscar_alertas(severidade='critica')['itens'][0]
    assert mongo.buscar_alerta(item['id'])['severidade'] == 'CRITICA'
    assert mongo.buscar_alerta('000000000000000000000000') is None


def test_validacao_mongo_antes_da_gravacao(mongo):
    with pytest.raises(ValueError):
        mongo.salvar_eventos([{}])
    assert mongo.buscar_eventos()['total'] == 0
    with pytest.raises(ValueError):
        mongo.buscar_eventos(ip={'$ne': None})
    with pytest.raises(ValueError):
        mongo.buscar_eventos(inicio='2025-02-21', fim='2025-02-20')
    with pytest.raises(ValueError):
        mongo.buscar_alerta('id-invalido')
    with pytest.raises(ValueError):
        mongo.buscar_eventos(tamanho=101)


def test_crud_usuario_hash_e_autenticacao(usuarios):
    repo, criados = usuarios
    email = f'teste-{uuid4().hex}@example.test'
    senha = 'Senha-de-teste-123!'
    usuario = repo.criar_usuario('Operador de teste', email, senha, 2)
    criados.append(usuario['id'])
    assert 'senha_hash' not in usuario and 'senha' not in usuario
    assert repo.buscar_usuario(usuario['id']) == usuario
    assert repo.autenticar(email, senha) == usuario
    assert repo.autenticar(email, 'senha-incorreta') is None
    assert repo.autenticar('nao-existe-' + email, senha) is None
    assert repo.autenticar("' OR '1'='1", senha) is None
    with mysql.connector.connect(**configuracao_mysql()) as con:
        with con.cursor() as cur:
            cur.execute('SELECT senha_hash FROM usuarios WHERE id=%s', (usuario['id'],))
            hash_salvo = cur.fetchone()[0]
            assert hash_salvo != senha and hash_salvo.startswith('scrypt:')
    with pytest.raises(UsuarioDuplicado):
        repo.criar_usuario('Duplicado', email.upper(), senha)
    # A duplicata não deixa a conexão ou transação inutilizável.
    alterado = repo.atualizar_usuario(usuario['id'], nivel_acesso=4, senha='Nova-senha-de-teste-123!')
    assert alterado['nivel_acesso'] == 4
    assert repo.autenticar(email, senha) is None
    assert repo.autenticar(email, 'Nova-senha-de-teste-123!') is not None
    assert any(item['id'] == usuario['id'] for item in repo.listar_usuarios(tamanho=100))
    assert repo.remover_usuario(usuario['id']) is True
    assert repo.remover_usuario(usuario['id']) is False


def test_limites_de_usuario_e_nivel_no_banco(usuarios):
    repo, criados = usuarios
    for nivel in (0, 6, True):
        with pytest.raises(ValueError):
            repo.criar_usuario('Teste', 'teste@example.test', 'Senha-de-teste-123!', nivel)
    with pytest.raises(ValueError):
        repo.criar_usuario('Teste', 'email-ruim', 'Senha-de-teste-123!')
    with pytest.raises(ValueError):
        repo.criar_usuario('Teste', 'teste@example.test', 'curta')
    # Conferir a restrição no próprio MySQL, sem depender só do Python.
    with mysql.connector.connect(**configuracao_mysql()) as con:
        with con.cursor() as cur:
            with pytest.raises(mysql.connector.Error):
                cur.execute('INSERT INTO usuarios(nome,email,senha_hash,nivel_acesso) VALUES(%s,%s,%s,%s)',
                            ('Invalido', f'{uuid4().hex}@example.test', 'hash-nao-utilizavel', 6))
        con.rollback()


def test_conexao_mysql_indisponivel_sem_vazar_credenciais():
    config = configuracao_mysql()
    config.update(port=1, connection_timeout=1)
    repo = RepositorioUsuarios(config)
    with pytest.raises(ErroPersistencia) as erro:
        repo.listar_usuarios()
    assert config['password'] not in str(erro.value)


def test_conexao_mongo_indisponivel_sem_vazar_detalhes():
    with RepositorioMongo('mongodb://127.0.0.1:1/', 'teste_offline') as repo:
        with pytest.raises(ErroPersistencia, match='MongoDB'):
            repo.preparar()
