"""Contexto do IP; opcional na CLI e disponível para a futura consulta por IP."""
from ipaddress import ip_address

import requests


def eh_ip_privado(ip):
    endereco = ip_address(ip)
    return endereco.is_private or endereco.is_loopback


def consultar_ip(ip, cache):
    ip = str(ip_address(ip))
    if ip in cache:
        return dict(cache[ip])
    publico = ip_address(ip).is_global
    padrao = 'Desconhecido' if publico else 'Rede Interna / não pública'
    resultado = {'ip': ip, 'privado': eh_ip_privado(ip), 'consultado': False,
                 **{campo: padrao for campo in ('cidade', 'regiao', 'pais', 'org', 'hostname')}}
    if publico:
        try:
            resposta = requests.get(f'https://ipinfo.io/{ip}/json', timeout=5)
            resposta.raise_for_status()
            dados = resposta.json()
            if not isinstance(dados, dict) or dados.get('bogon'):
                raise ValueError('Resposta inválida')
            mapa = {'cidade': 'city', 'regiao': 'region', 'pais': 'country', 'org': 'org', 'hostname': 'hostname'}
            for destino, origem in mapa.items():
                valor = dados.get(origem)
                if isinstance(valor, str):
                    resultado[destino] = valor[:300]
            resultado['consultado'] = True
        except (requests.RequestException, ValueError):
            # A indisponibilidade de uma API externa não deve interromper a análise.
            pass
    cache[ip] = resultado
    return dict(resultado)


def enriquecer_alertas(alertas, cache):
    return [{**alerta, 'geolocalizacao': consultar_ip(alerta['ip'], cache)} for alerta in alertas]
