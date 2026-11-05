"""Console simples para demonstração em dois terminais."""
import socket
import threading

from alertas.servidor_alertas import enviar_json, receber_mensagens, formatar_alerta


def receber_alertas(conexao, parada):
    try:
        for mensagem in receber_mensagens(conexao, parada):
            if mensagem['tipo'] == 'alerta':
                print('\n' + formatar_alerta(mensagem['alerta']))
            elif mensagem['tipo'] == 'historico':
                for alerta in mensagem['alertas']:
                    print(formatar_alerta(alerta))
            else:
                print(mensagem)
    except (OSError, ValueError):
        print('Conexão de monitoramento encerrada.')
    finally:
        parada.set()


def conectar_servidor(host='127.0.0.1', porta=9999):
    parada = threading.Event()
    with socket.create_connection((host, porta), timeout=3) as conexao:
        conexao.settimeout(.5)
        enviar_json(conexao, {'acao': 'assinar'})
        threading.Thread(target=receber_alertas, args=(conexao, parada), daemon=True).start()
        print('Comandos: /status, /historico, /sair')
        while not parada.is_set():
            try:
                comando = input().strip().lstrip('/')
            except (EOFError, KeyboardInterrupt):
                comando = 'sair'
            if comando not in {'status', 'historico', 'sair'}:
                print('Use /status, /historico ou /sair')
                continue
            enviar_json(conexao, {'acao': comando})
            if comando == 'sair':
                break
        parada.set()
