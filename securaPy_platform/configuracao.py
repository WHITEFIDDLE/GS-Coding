"""Configuração central. Nenhuma conexão é aberta durante o import."""
import os
from pathlib import Path

from dotenv import load_dotenv

PASTA_PROJETO = Path(__file__).resolve().parent
load_dotenv(PASTA_PROJETO / '.env', override=False)


def configuracao_mysql():
    senha = os.getenv('MYSQL_PASSWORD')
    if not senha:
        raise ValueError('Defina MYSQL_PASSWORD no arquivo .env ou no ambiente.')
    return {
        'host': os.getenv('MYSQL_HOST', '127.0.0.1'),
        'port': int(os.getenv('MYSQL_PORT', '13307')),
        'user': os.getenv('MYSQL_USER', 'operador'),
        'password': senha,
        'database': os.getenv('MYSQL_DATABASE', 'securapy_gs'),
        'connection_timeout': 5,
    }


def configuracao_mongo():
    return {
        'uri': os.getenv('MONGO_URI', 'mongodb://127.0.0.1:27019/'),
        'banco': os.getenv('MONGO_DATABASE', 'securapy_gs'),
        'fuso_logs': os.getenv('LOG_TIMEZONE', 'America/Sao_Paulo'),
    }
