"""Broadcast TCP com mensagens JSON delimitadas por quebra de linha (JSONL).

Um socket entrega bytes, não mensagens. O delimitador evita misturar dois
alertas ou interpretar um alerta recebido pela metade.
"""
import hmac
import json
import logging
import socket
import threading
from collections import deque

logger = logging.getLogger(__name__)
LIMITE_MENSAGEM = 65536


def enviar_json(conexao, documento):
    pacote = json.dumps(documento, ensure_ascii=False).encode('utf-8') + b'\n'
    if len(pacote) > LIMITE_MENSAGEM:
        raise ValueError('Mensagem TCP muito grande')
    conexao.sendall(pacote)


def receber_mensagens(conexao, parada):
    buffer = b''
    while not parada.is_set():
        try:
            dados = conexao.recv(4096)
        except socket.timeout:
            continue
        if not dados:
            return
        buffer += dados
        while b'\n' in buffer:
            linha, buffer = buffer.split(b'\n', 1)
            if len(linha) > LIMITE_MENSAGEM:
                raise ValueError('Mensagem TCP muito grande')
            yield json.loads(linha.decode('utf-8'))
        if len(buffer) > LIMITE_MENSAGEM:
            raise ValueError('Mensagem TCP muito grande')


def formatar_alerta(alerta):
    return (f"[{alerta['timestamp']}] [{alerta['severidade']}] "
            f"{alerta['regra_nome']} - {alerta['ip']} - {alerta['descricao']}")


class ServidorAlertas:
    def __init__(self, token_publicacao, host='127.0.0.1', porta=9999, max_clientes=10):
        if not token_publicacao or len(token_publicacao) < 24:
            raise ValueError('Configure ALERTAS_TOKEN com pelo menos 24 caracteres')
        self.token = token_publicacao
        self.max_clientes = max_clientes
        self.clientes = {}
        self.lock = threading.Lock()
        self.historico = deque(maxlen=10)
        self.total_alertas = 0
        self.parada = threading.Event()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.socket.bind((host, porta))
            self.socket.listen(max_clientes)
            self.socket.settimeout(.5)
        except OSError:
            self.socket.close()
            raise
        self.endereco = self.socket.getsockname()

    def servir(self):
        while not self.parada.is_set():
            try:
                conexao, _ = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                if self.parada.is_set():
                    break
                raise
            conexao.settimeout(2)
            with self.lock:
                if len(self.clientes) >= self.max_clientes:
                    conexao.close()
                    continue
                # O lock individual impede duas threads de misturarem envios.
                self.clientes[conexao] = {'assinado': False, 'envio': threading.Lock()}
            threading.Thread(target=self._tratar, args=(conexao,), daemon=True).start()

    def _enviar(self, conexao, documento):
        with self.lock:
            cliente = self.clientes.get(conexao)
        if cliente is None:
            return
        with cliente['envio']:
            enviar_json(conexao, documento)

    def remover_cliente(self, conexao):
        with self.lock:
            self.clientes.pop(conexao, None)
        try:
            conexao.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        conexao.close()

    def broadcast_alerta(self, alerta):
        for campo in ('timestamp', 'severidade', 'regra_nome', 'ip', 'descricao'):
            if not isinstance(alerta.get(campo), str) or len(alerta[campo]) > 2000:
                raise ValueError('Alerta inválido')
        if alerta['severidade'] != 'CRITICA':
            raise ValueError('O canal publica apenas alertas críticos')
        mensagem = {'tipo': 'alerta', 'alerta': alerta}
        # Validar tamanho antes de registrar no histórico.
        if len(json.dumps(mensagem, ensure_ascii=False).encode('utf-8')) + 1 > LIMITE_MENSAGEM:
            raise ValueError('Alerta muito grande')
        with self.lock:
            self.historico.append(alerta)
            self.total_alertas += 1
            assinantes = [con for con, dados in self.clientes.items() if dados['assinado']]
        for conexao in assinantes:
            try:
                self._enviar(conexao, mensagem)
            except OSError:
                self.remover_cliente(conexao)

    def _tratar(self, conexao):
        try:
            for mensagem in receber_mensagens(conexao, self.parada):
                if not isinstance(mensagem, dict):
                    raise ValueError('Objeto JSON esperado')
                acao = mensagem.get('acao')
                if acao == 'assinar':
                    with self.lock:
                        self.clientes[conexao]['assinado'] = True
                    self._enviar(conexao, {'tipo': 'conectado', 'mensagem': 'Monitor de alertas conectado'})
                elif acao == 'publicar':
                    token = mensagem.get('token', '')
                    if not isinstance(token, str) or not hmac.compare_digest(token, self.token):
                        self._enviar(conexao, {'tipo': 'erro', 'mensagem': 'Publicação não autorizada'})
                        return
                    alerta = mensagem.get('alerta')
                    if not isinstance(alerta, dict):
                        raise ValueError('Alerta inválido')
                    self.broadcast_alerta(alerta)
                    self._enviar(conexao, {'tipo': 'publicado'})
                elif acao == 'status':
                    with self.lock:
                        status = {'tipo': 'status', 'clientes': sum(c['assinado'] for c in self.clientes.values()),
                                  'alertas': self.total_alertas}
                    self._enviar(conexao, status)
                elif acao == 'historico':
                    with self.lock:
                        historico = list(self.historico)
                    self._enviar(conexao, {'tipo': 'historico', 'alertas': historico})
                elif acao == 'sair':
                    return
                else:
                    self._enviar(conexao, {'tipo': 'erro', 'mensagem': 'Comando desconhecido'})
        except (OSError, ValueError, UnicodeError, KeyError, TypeError):
            logger.info('Conexão de monitoramento encerrada ou mensagem inválida')
        finally:
            self.remover_cliente(conexao)

    def fechar(self):
        self.parada.set()
        self.socket.close()
        with self.lock:
            conexoes = list(self.clientes)
        for conexao in conexoes:
            self.remover_cliente(conexao)
