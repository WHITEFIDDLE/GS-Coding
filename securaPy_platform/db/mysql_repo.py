"""Usuários e credenciais no MySQL. Nenhuma senha ou hash sai do repositório."""
import re
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path

import mysql.connector
from mysql.connector import Error, IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

from db.erros import ErroPersistencia, UsuarioDuplicado

COLUNAS_PUBLICAS = 'id, nome, email, nivel_acesso'


@lru_cache(maxsize=1)
def _hash_ficticio():
    # Mesmo trabalho de hash quando o e-mail não existe; não elimina todo canal temporal.
    return generate_password_hash('credencial-ficticia-nao-utilizavel', method='scrypt')


def _validar_id(usuario_id):
    if type(usuario_id) is not int or usuario_id < 1:
        raise ValueError('ID de usuário inválido')


def _validar_nome(nome):
    if not isinstance(nome, str) or not 1 <= len(nome.strip()) <= 100:
        raise ValueError('Nome precisa ter de 1 a 100 caracteres')
    return nome.strip()


def _validar_email(email):
    if not isinstance(email, str):
        raise ValueError('E-mail inválido')
    email = email.strip().lower()
    if len(email) > 254 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email):
        raise ValueError('E-mail inválido')
    return email


def _validar_nivel(nivel):
    if type(nivel) is not int or not 1 <= nivel <= 5:
        raise ValueError('Nível de acesso precisa estar entre 1 e 5')
    return nivel


def _hash_senha(senha):
    if not isinstance(senha, str) or not 10 <= len(senha) <= 128:
        raise ValueError('Senha precisa ter de 10 a 128 caracteres')
    return generate_password_hash(senha, method='scrypt')


class RepositorioUsuarios:
    def __init__(self, configuracao):
        self.configuracao = dict(configuracao)
        _hash_ficticio()

    @contextmanager
    def _cursor(self, escrita=False):
        conexao = None
        try:
            conexao = mysql.connector.connect(**self.configuracao)
            with conexao.cursor(dictionary=True) as cursor:
                yield cursor
            if escrita:
                conexao.commit()
        except IntegrityError as erro:
            if conexao:
                conexao.rollback()
            if erro.errno == 1062:
                raise UsuarioDuplicado('Já existe um usuário com esse e-mail.') from None
            raise ErroPersistencia('Os dados violam uma restrição do MySQL.') from None
        except Error:
            if conexao:
                try:
                    conexao.rollback()
                except Error:
                    pass
            raise ErroPersistencia('Não foi possível concluir a operação no MySQL.') from None
        finally:
            if conexao:
                conexao.close()

    def preparar(self):
        sql = (Path(__file__).resolve().parents[1] / 'sql' / '001_usuarios.sql').read_text(encoding='utf-8')
        with self._cursor(escrita=True) as cursor:
            cursor.execute(sql)

    def criar_usuario(self, nome, email, senha, nivel_acesso=1):
        valores = (_validar_nome(nome), _validar_email(email), _hash_senha(senha), _validar_nivel(nivel_acesso))
        with self._cursor(escrita=True) as cursor:
            cursor.execute('INSERT INTO usuarios (nome,email,senha_hash,nivel_acesso) VALUES (%s,%s,%s,%s)', valores)
            usuario_id = cursor.lastrowid
        return self.buscar_usuario(usuario_id)

    def buscar_usuario(self, usuario_id):
        _validar_id(usuario_id)
        with self._cursor() as cursor:
            cursor.execute(f'SELECT {COLUNAS_PUBLICAS} FROM usuarios WHERE id=%s', (usuario_id,))
            return cursor.fetchone()

    def listar_usuarios(self, pagina=1, tamanho=20):
        if type(pagina) is not int or pagina < 1 or type(tamanho) is not int or not 1 <= tamanho <= 100:
            raise ValueError('Paginação inválida')
        with self._cursor() as cursor:
            cursor.execute(f'SELECT {COLUNAS_PUBLICAS} FROM usuarios ORDER BY id LIMIT %s OFFSET %s',
                           (tamanho, (pagina - 1) * tamanho))
            return cursor.fetchall()

    def atualizar_usuario(self, usuario_id, *, nome=None, email=None, senha=None, nivel_acesso=None):
        _validar_id(usuario_id)
        campos = {}
        if nome is not None:
            campos['nome'] = _validar_nome(nome)
        if email is not None:
            campos['email'] = _validar_email(email)
        if senha is not None:
            campos['senha_hash'] = _hash_senha(senha)
        if nivel_acesso is not None:
            campos['nivel_acesso'] = _validar_nivel(nivel_acesso)
        if not campos:
            raise ValueError('Informe ao menos um campo para atualizar')
        # Só nomes de coluna definidos acima entram na SQL; valores vão em parâmetros.
        atribuicoes = ', '.join(f'{campo}=%s' for campo in campos)
        with self._cursor(escrita=True) as cursor:
            cursor.execute(f'UPDATE usuarios SET {atribuicoes} WHERE id=%s', (*campos.values(), usuario_id))
        return self.buscar_usuario(usuario_id)

    def remover_usuario(self, usuario_id):
        _validar_id(usuario_id)
        with self._cursor(escrita=True) as cursor:
            cursor.execute('DELETE FROM usuarios WHERE id=%s', (usuario_id,))
            return cursor.rowcount == 1

    def autenticar(self, email, senha):
        # Falha de credencial é None nos dois casos; indisponibilidade é outro erro.
        if not isinstance(email, str) or not isinstance(senha, str) or len(email) > 254 or len(senha) > 128:
            return None
        with self._cursor() as cursor:
            cursor.execute('SELECT id,nome,email,nivel_acesso,senha_hash FROM usuarios WHERE email=%s',
                           (email.strip().lower(),))
            usuario = cursor.fetchone()
        hash_armazenado = usuario['senha_hash'] if usuario else _hash_ficticio()
        confere = check_password_hash(hash_armazenado, senha)
        if not usuario or not confere:
            return None
        return {campo: valor for campo, valor in usuario.items() if campo != 'senha_hash'}
