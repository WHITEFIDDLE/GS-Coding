"""Detecções que precisam olhar vários eventos, com dicts e sets."""
from collections import Counter

from core.coletor import atributos_do_evento
from core.regras import classificar_severidade


def detectar_brute_force(eventos, threshold=5):
    if threshold < 1:
        raise ValueError('O limite deve ser positivo')
    por_ip = {}
    for evento in eventos:
        if evento['fonte'] != 'auth' or evento['tipo'] != 'FAIL':
            continue
        dados = por_ip.setdefault(evento['ip'], {'tentativas': 0, 'usuarios': set()})
        dados['tentativas'] += 1
        dados['usuarios'].add(atributos_do_evento(evento)['usuario'])
    resultado = {}
    for ip, dados in por_ip.items():
        total = dados['tentativas']
        if total < threshold:
            continue
        # Limites copiados do contrato do detector original (>20, >10, >5).
        if total > 20:
            severidade = 'CRITICA'
        elif total > 10:
            severidade = 'ALTA'
        elif total > 5:
            severidade = 'MEDIA'
        else:
            severidade = 'BAIXA'
        resultado[ip] = {'tentativas': total, 'usuarios': sorted(dados['usuarios']), 'severidade': severidade}
    return resultado


def detectar_port_scan(eventos, threshold=3):
    if threshold < 1:
        raise ValueError('O limite deve ser positivo')
    portas_por_ip = {}
    for evento in eventos:
        if evento['fonte'] == 'firewall' and evento['tipo'] == 'BLOCK':
            portas_por_ip.setdefault(evento['ip'], set()).add(int(atributos_do_evento(evento)['dport']))
    resultado = {}
    for ip, portas in portas_por_ip.items():
        quantidade = len(portas)
        if quantidade >= threshold:
            if quantidade > 10:
                severidade = 'CRITICA'
            elif quantidade > 5:
                severidade = 'ALTA'
            else:
                severidade = 'MEDIA'
            resultado[ip] = {'portas': portas, 'quantidade': quantidade, 'severidade': severidade}
    return resultado


def verificar_blacklist(eventos, blacklist):
    encontrados = {evento['ip'] for evento in eventos} & set(blacklist)
    contagem = Counter(evento['ip'] for evento in eventos if evento['ip'] in encontrados)
    return encontrados, dict(contagem)


def gerar_resumo_ameacas(brute_force, port_scan, blacklist_resultado):
    ips_blacklist, contagem = blacklist_resultado
    todos_ips = set(brute_force) | set(port_scan) | ips_blacklist
    ameacas = []
    for ip in todos_ips:
        deteccoes, detalhes = [], {}
        if ip in brute_force:
            deteccoes.append('brute_force')
            detalhes['brute_force'] = brute_force[ip]
        if ip in port_scan:
            deteccoes.append('port_scan')
            dados = port_scan[ip]
            detalhes['port_scan'] = {**dados, 'portas': sorted(dados['portas'])}
        if ip in ips_blacklist:
            deteccoes.append('blacklist')
            detalhes['blacklist'] = {'eventos': contagem[ip]}
        pontuacao = 5 * len(deteccoes)
        ameacas.append({'ip': ip, 'deteccoes': deteccoes, 'pontuacao': pontuacao,
                        'severidade': classificar_severidade(pontuacao), 'detalhes': detalhes})
    return sorted(ameacas, key=lambda ameaca: (-ameaca['pontuacao'], ameaca['ip']))
