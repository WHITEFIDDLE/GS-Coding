"""Baixa os três logs didáticos originais sem substituir arquivos existentes."""
from pathlib import Path
from urllib.request import urlopen

BASE = 'https://raw.githubusercontent.com/fabioBaraDev/coding_for_security/main/GS_1Semestre/securaPy/logs/'


def baixar_logs():
    pasta = Path(__file__).resolve().parent / 'logs'
    pasta.mkdir(exist_ok=True)
    for nome in ('auth.log', 'firewall.log', 'web_access.log'):
        destino = pasta / nome
        if destino.exists():
            print(f'{nome}: já existe, preservado.')
            continue
        with urlopen(BASE + nome, timeout=20) as resposta:
            dados = resposta.read()
        dados.decode('utf-8-sig')
        with destino.open('xb') as arquivo:
            arquivo.write(dados)
        print(f'{nome}: baixado.')


if __name__ == '__main__':
    baixar_logs()
