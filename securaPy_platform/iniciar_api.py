"""Inicialização do contêiner da API (módulo F).

1. Espera MySQL e MongoDB aceitarem conexões e cria tabela/índices
   (mesmas funções do comando `main.py preparar-bancos`, sem apagar dados).
2. Cria o administrador inicial a partir de ADMIN_EMAIL/ADMIN_PASSWORD,
   se ainda não existir (a senha vai para o MySQL só como hash).
3. Substitui este processo pelo gunicorn, servindo wsgi:application.
"""
import logging
import os
import sys
import time

from configuracao import configuracao_mongo, configuracao_mysql
from db.erros import ErroPersistencia, UsuarioDuplicado
from db.mongo_repo import RepositorioMongo
from db.mysql_repo import RepositorioUsuarios

logger = logging.getLogger('iniciar_api')


def preparar_bancos(tentativas=30, espera=2):
    for tentativa in range(1, tentativas + 1):
        try:
            RepositorioUsuarios(configuracao_mysql()).preparar()
            with RepositorioMongo(**configuracao_mongo()) as repo:
                repo.preparar()
            logger.info('Bancos prontos (tentativa %d).', tentativa)
            return
        except ErroPersistencia:
            logger.info('Bancos ainda indisponíveis (tentativa %d/%d).', tentativa, tentativas)
            time.sleep(espera)
    raise SystemExit('Não foi possível conectar aos bancos.')


def criar_admin_inicial():
    email, senha = os.getenv('ADMIN_EMAIL'), os.getenv('ADMIN_PASSWORD')
    if not email or not senha:
        logger.info('ADMIN_EMAIL/ADMIN_PASSWORD não definidos; nenhum usuário inicial criado.')
        return
    try:
        RepositorioUsuarios(configuracao_mysql()).criar_usuario('Administrador', email, senha, 5)
        logger.info('Administrador inicial criado.')
    except UsuarioDuplicado:
        logger.info('Administrador inicial já existe.')


def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    preparar_bancos()
    criar_admin_inicial()
    sys.stdout.flush()
    os.execvp('gunicorn', ['gunicorn', '--bind', '0.0.0.0:5000', '--workers', os.getenv('API_WORKERS', '2'),
                           '--access-logfile', '-', 'wsgi:application'])


if __name__ == '__main__':
    main()
