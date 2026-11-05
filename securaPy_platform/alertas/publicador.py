"""Ponte entre a ingestão e o processo que mantém os consoles TCP conectados."""
import json
import socket

from alertas.servidor_alertas import enviar_json, LIMITE_MENSAGEM


def publicar_criticos(alertas, token, host='127.0.0.1', porta=9999):
    criticos = [alerta for alerta in alertas if alerta['severidade'] == 'CRITICA']
    if not criticos:
        return 0
    with socket.create_connection((host, porta), timeout=3) as conexao:
        with conexao.makefile('rb') as entrada:
            for alerta in criticos:
                enviar_json(conexao, {'acao': 'publicar', 'token': token, 'alerta': alerta})
                resposta = entrada.readline(LIMITE_MENSAGEM + 1)
                if not resposta.endswith(b'\n') or len(resposta) > LIMITE_MENSAGEM:
                    raise ValueError('Resposta TCP inválida')
                if json.loads(resposta).get('tipo') != 'publicado':
                    raise ValueError('Servidor recusou a publicação')
    return len(criticos)
