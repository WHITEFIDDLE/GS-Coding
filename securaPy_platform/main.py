"""Entrada de demonstração dos módulos A e B; a API será feita por outro integrante."""
import argparse
import getpass
import json
import logging
import os
from pathlib import Path

from configuracao import PASTA_PROJETO, configuracao_mongo, configuracao_mysql
from core.enriquecimento import enriquecer_alertas
from db.documentos import para_json
from db.erros import ErroPersistencia, UsuarioDuplicado
from db.mongo_repo import RepositorioMongo
from db.mysql_repo import RepositorioUsuarios
from servicos.analise import analisar_pasta
from servicos.ingestao import persistir_analise


def exibir(documento):
    print(json.dumps(para_json(documento), indent=2, ensure_ascii=False))


def montar_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    comandos = parser.add_subparsers(dest='comando', required=True)
    comandos.add_parser('preparar-bancos', help='Cria índices e tabela, sem apagar dados')
    for nome in ('analisar', 'ingerir'):
        comando = comandos.add_parser(nome)
        comando.add_argument('--logs', type=Path, default=PASTA_PROJETO / 'logs')
        comando.add_argument('--saida', type=Path, help='Exporta JSON da análise')
        comando.add_argument('--enriquecer', action='store_true', help='Consulta ipinfo para IPs públicos')
        if nome == 'ingerir':
            comando.add_argument('--publicar', action='store_true', help='Publica críticos no servidor TCP')
    consulta = comandos.add_parser('consultar')
    consulta.add_argument('--colecao', choices=['eventos', 'alertas'], default='eventos')
    consulta.add_argument('--ip')
    consulta.add_argument('--fonte', choices=['auth', 'firewall', 'web'])
    consulta.add_argument('--tipo')
    consulta.add_argument('--inicio', help='Data ISO; sem fuso usa LOG_TIMEZONE')
    consulta.add_argument('--fim')
    consulta.add_argument('--severidade')
    consulta.add_argument('--pagina', type=int, default=1)
    consulta.add_argument('--tamanho', type=int, default=20)
    comandos.add_parser('resumo-banco')
    criar = comandos.add_parser('criar-usuario')
    criar.add_argument('--nome', required=True)
    criar.add_argument('--email', required=True)
    criar.add_argument('--nivel', type=int, choices=range(1, 6), default=1)
    comandos.add_parser('listar-usuarios')
    login = comandos.add_parser('autenticar')
    login.add_argument('--email', required=True)
    servidor = comandos.add_parser('servidor-alertas')
    servidor.add_argument('--host', default=os.getenv('ALERTAS_HOST', '127.0.0.1'))
    servidor.add_argument('--porta', type=int, default=int(os.getenv('ALERTAS_PORT', '9999')))
    cliente = comandos.add_parser('cliente-alertas')
    cliente.add_argument('--host', default=os.getenv('ALERTAS_HOST', '127.0.0.1'))
    cliente.add_argument('--porta', type=int, default=int(os.getenv('ALERTAS_PORT', '9999')))
    return parser


def executar(args):
    if args.comando == 'servidor-alertas':
        from alertas.servidor_alertas import ServidorAlertas
        servidor = ServidorAlertas(os.getenv('ALERTAS_TOKEN', ''), args.host, args.porta)
        print(f'Servidor TCP ouvindo em {servidor.endereco}', flush=True)
        try:
            servidor.servir()
        finally:
            servidor.fechar()
    elif args.comando == 'cliente-alertas':
        from alertas.cliente_alertas import conectar_servidor
        conectar_servidor(args.host, args.porta)
    elif args.comando == 'preparar-bancos':
        RepositorioUsuarios(configuracao_mysql()).preparar()
        with RepositorioMongo(**configuracao_mongo()) as repo:
            repo.preparar()
        print('Tabela e índices preparados; dados existentes preservados.')
    elif args.comando in {'analisar', 'ingerir'}:
        analise = analisar_pasta(args.logs, PASTA_PROJETO / 'config/regras.json', PASTA_PROJETO / 'config/blacklist.json')
        if args.enriquecer:
            analise['alertas'] = enriquecer_alertas(analise['alertas'], {})
        if args.comando == 'ingerir':
            with RepositorioMongo(**configuracao_mongo()) as repo:
                repo.preparar()
                analise['persistencia'] = persistir_analise(analise, repo)
            if args.publicar:
                from alertas.publicador import publicar_criticos
                try:
                    analise['publicados'] = publicar_criticos(analise['alertas'], os.getenv('ALERTAS_TOKEN', ''),
                        os.getenv('ALERTAS_HOST', '127.0.0.1'), int(os.getenv('ALERTAS_PORT', '9999')))
                except (OSError, ValueError):
                    analise['aviso_tcp'] = 'Dados persistidos, mas os alertas não foram confirmados no TCP.'
        if args.saida:
            args.saida.parent.mkdir(parents=True, exist_ok=True)
            args.saida.write_text(json.dumps(para_json(analise), indent=2, ensure_ascii=False), encoding='utf-8')
        exibir({'total_eventos': len(analise['eventos']), 'total_alertas': len(analise['alertas']),
                'ameacas': analise['ameacas'], 'persistencia': analise.get('persistencia'),
                'publicados': analise.get('publicados'), 'aviso_tcp': analise.get('aviso_tcp')})
    elif args.comando == 'consultar':
        filtros = {nome: getattr(args, nome) for nome in ('ip', 'fonte', 'tipo', 'inicio', 'fim', 'severidade')
                   if getattr(args, nome) is not None}
        if args.colecao == 'eventos' and 'severidade' in filtros:
            raise ValueError('Severidade é um filtro de alertas')
        with RepositorioMongo(**configuracao_mongo()) as repo:
            buscar = repo.buscar_eventos if args.colecao == 'eventos' else repo.buscar_alertas
            exibir(buscar(pagina=args.pagina, tamanho=args.tamanho, **filtros))
    elif args.comando == 'resumo-banco':
        with RepositorioMongo(**configuracao_mongo()) as repo:
            exibir({'top_ips': repo.top_ips(), 'por_fonte': repo.contar_por_fonte(),
                    'por_severidade': repo.contar_por_severidade()})
    else:
        usuarios = RepositorioUsuarios(configuracao_mysql())
        if args.comando == 'criar-usuario':
            senha = getpass.getpass('Senha (10 a 128 caracteres): ')
            if senha != getpass.getpass('Confirme a senha: '):
                raise ValueError('As senhas não conferem')
            exibir(usuarios.criar_usuario(args.nome, args.email, senha, args.nivel))
        elif args.comando == 'listar-usuarios':
            exibir(usuarios.listar_usuarios())
        elif args.comando == 'autenticar':
            usuario = usuarios.autenticar(args.email, getpass.getpass('Senha: '))
            if usuario is None:
                raise ValueError('Credenciais inválidas')
            exibir(usuario)


def main():
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    parser = montar_parser()
    args = parser.parse_args()
    try:
        executar(args)
    except (ErroPersistencia, UsuarioDuplicado, ValueError, OSError) as erro:
        if isinstance(erro, OSError):
            parser.exit(1, 'Não foi possível acessar arquivo, diretório ou serviço de rede.\n')
        parser.exit(1, f'{erro}\n')
    except KeyboardInterrupt:
        print('\nEncerrado.')


if __name__ == '__main__':
    main()
