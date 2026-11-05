"""Ponto de entrada da plataforma integrada (usado pelo gunicorn no Docker).

/        -> dashboard do analista (módulo E), lendo o MongoDB e logando no MySQL
/api/... -> API REST (módulo D)

Os dois usam os mesmos repositórios (módulo B), o mesmo núcleo (módulo A),
o mesmo modelo verificado por hash (módulo C) e o mesmo assistente (módulo G).
Execução local: python wsgi.py   (http://127.0.0.1:5000)
"""
import logging
import os

from werkzeug.middleware.dispatcher import DispatcherMiddleware

from configuracao import PASTA_PROJETO, configuracao_mongo, configuracao_mysql


def _ligado(nome, padrao='0'):
    return os.getenv(nome, padrao).strip().lower() in {'1', 'true', 'sim', 'yes'}


def criar_plataforma():
    from api.app import criar_api
    from core.enriquecimento import consultar_ip
    from db.mongo_repo import RepositorioMongo
    from db.mysql_repo import RepositorioUsuarios
    from ia.assistente import obter_assistente
    from servicos.plataforma import Contexto, geolocalizador
    from web.dashboard import criar_app
    from web.providers import RepositorioDataProvider
    from web.usuarios import MySQLUserStore

    repositorio = RepositorioMongo(**configuracao_mongo())
    usuarios = RepositorioUsuarios(configuracao_mysql())
    contexto = Contexto(PASTA_PROJETO)
    assistente = obter_assistente()

    geolocalizar = None
    if _ligado('ENRIQUECER_IP'):
        geolocalizar = geolocalizador(consultar_ip)

    publicar = None
    if _ligado('PUBLICAR_ALERTAS'):
        from alertas.publicador import publicar_criticos
        host, porta = os.getenv('ALERTAS_HOST', '127.0.0.1'), int(os.getenv('ALERTAS_PORT', '9999'))
        token = os.getenv('ALERTAS_TOKEN', '')
        publicar = lambda alertas: publicar_criticos(alertas, token, host, porta)  # noqa: E731

    api = criar_api(repositorio, usuarios, contexto, os.getenv('API_JWT_SECRET', ''),
                    assistente=assistente, geolocalizar=geolocalizar, publicar=publicar, prefixo='')
    painel = criar_app(data_provider=RepositorioDataProvider(repositorio, contexto, geolocalizar),
                       user_store=MySQLUserStore(usuarios), assistente=assistente)
    painel.wsgi_app = DispatcherMiddleware(painel.wsgi_app, {'/api': api})
    return painel


logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
application = criar_plataforma()

if __name__ == '__main__':
    # debug=False: o depurador do Werkzeug executaria código remoto (OWASP A05).
    application.run(host=os.getenv('API_HOST', '127.0.0.1'), port=int(os.getenv('API_PORT', '5000')), debug=False)
