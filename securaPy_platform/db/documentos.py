"""Conversão de datas e documentos para o MongoDB e para JSON."""
import hashlib
import json
from datetime import datetime, timezone
from ipaddress import ip_address
from zoneinfo import ZoneInfo

from bson import ObjectId


def data_utc(valor, fuso_logs='America/Sao_Paulo'):
    if isinstance(valor, str):
        valor = datetime.fromisoformat(valor.replace('Z', '+00:00'))
    if not isinstance(valor, datetime):
        raise ValueError('Data precisa ser datetime ou texto ISO 8601')
    if valor.tzinfo is None:
        valor = valor.replace(tzinfo=ZoneInfo(fuso_logs))
    return valor.astimezone(timezone.utc)


def para_json(valor):
    if isinstance(valor, dict):
        return {('id' if chave == '_id' else chave): para_json(item) for chave, item in valor.items()}
    if isinstance(valor, (list, tuple, set)):
        return [para_json(item) for item in valor]
    if isinstance(valor, datetime):
        return valor.isoformat()
    if isinstance(valor, ObjectId):
        return str(valor)
    return valor


def preparar_documento(documento, tipo, fuso_logs):
    if not isinstance(documento, dict):
        raise ValueError('Documento precisa ser um dicionário')
    campos = ['timestamp', 'ip', 'fonte', 'tipo'] if tipo == 'evento' else [
        'timestamp', 'ip', 'regra_id', 'regra_nome', 'severidade', 'descricao']
    for campo in campos:
        if not documento.get(campo):
            raise ValueError(f'Campo obrigatório ausente: {campo}')
    novo = {chave: valor for chave, valor in documento.items() if chave not in {'_id', 'id', 'chave_evento', 'chave_alerta'}}
    novo['ip'] = str(ip_address(novo['ip']))
    novo['timestamp'] = data_utc(novo['timestamp'], fuso_logs)
    if tipo == 'evento' and novo['fonte'] not in {'auth', 'firewall', 'web'}:
        raise ValueError('Fonte inválida')
    if tipo == 'alerta':
        novo['severidade'] = str(novo['severidade']).upper()
        if novo['severidade'] not in {'INFO', 'BAIXA', 'MEDIA', 'ALTA', 'CRITICA'}:
            raise ValueError('Severidade inválida')
        identidade = {chave: novo[chave] for chave in campos}
    else:
        identidade = novo
    texto = json.dumps(para_json(identidade), sort_keys=True, ensure_ascii=False, separators=(',', ':'))
    novo['chave_' + tipo] = hashlib.sha256(texto.encode('utf-8')).hexdigest()
    return novo
