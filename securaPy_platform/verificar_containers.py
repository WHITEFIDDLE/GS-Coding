"""Verifica pelo SDK do Docker (docker-py) se a plataforma está no ar (cenários F2 e F3).

Uso (no host, com o compose em execução):
    python verificar_containers.py
Lista os contêineres do projeto Compose "securapy", exige que api, mongo e
mysql estejam "running" (e saudáveis, quando têm healthcheck) e chama
GET /api/saude, que precisa responder 200. Código de saída 0 = tudo OK.
"""
import argparse
import sys
import urllib.error
import urllib.request

import docker
from docker.errors import DockerException

OBRIGATORIOS = ('api', 'mongo', 'mysql')


def listar_servicos(cliente, projeto):
    filtro = {'label': f'com.docker.compose.project={projeto}'}
    servicos = {}
    for conteiner in cliente.containers.list(all=True, filters=filtro):
        servico = conteiner.labels.get('com.docker.compose.service', conteiner.name)
        saude = conteiner.attrs.get('State', {}).get('Health', {}).get('Status', 'sem healthcheck')
        servicos[servico] = {'nome': conteiner.name, 'status': conteiner.status, 'saude': saude,
                             'imagem': conteiner.image.tags[0] if conteiner.image.tags else conteiner.image.short_id}
    return servicos


def verificar_api(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as resposta:
            return resposta.status
    except urllib.error.HTTPError as erro:
        return erro.code
    except (urllib.error.URLError, OSError):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--projeto', default='securapy')
    parser.add_argument('--url', default='http://127.0.0.1:5000/api/saude')
    args = parser.parse_args()
    try:
        cliente = docker.from_env()
        cliente.ping()
    except DockerException:
        print('Não foi possível falar com o Docker. O Docker Desktop está em execução?')
        return 2

    servicos = listar_servicos(cliente, args.projeto)
    print(f'{"SERVIÇO":<10} {"CONTÊINER":<22} {"STATUS":<10} {"SAÚDE":<16} IMAGEM')
    for servico, info in sorted(servicos.items()):
        print(f'{servico:<10} {info["nome"]:<22} {info["status"]:<10} {info["saude"]:<16} {info["imagem"]}')

    problemas = []
    for servico in OBRIGATORIOS:
        info = servicos.get(servico)
        if info is None:
            problemas.append(f'{servico}: contêiner não encontrado')
        elif info['status'] != 'running':
            problemas.append(f'{servico}: status {info["status"]}')
        elif info['saude'] not in {'healthy', 'sem healthcheck'}:
            problemas.append(f'{servico}: saúde {info["saude"]}')

    status_api = verificar_api(args.url)
    print(f'\nGET {args.url} -> {status_api or "sem resposta"}')
    if status_api != 200:
        problemas.append('API não respondeu 200')

    if problemas:
        print('\nFALHOU:\n  - ' + '\n  - '.join(problemas))
        return 1
    print(f'\nOK: {", ".join(OBRIGATORIOS)} em "running" e a API respondeu 200.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
