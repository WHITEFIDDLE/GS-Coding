"""Autenticação por token (módulo D): JWT HS256 com expiração.

O token é emitido em POST /api/auth/token depois de o operador ser validado
pelo MySQL (db/mysql_repo.py). Rotas de escrita exigem o cabeçalho
`Authorization: Bearer <token>`; sem token válido a resposta é 401, e com
nível de acesso insuficiente é 403.
"""
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import current_app, g, jsonify

ALGORITMO = 'HS256'
EMISSOR = 'securapy-platform'


def validar_segredo(segredo):
    if not isinstance(segredo, str) or len(segredo) < 32:
        raise ValueError('Defina API_JWT_SECRET com pelo menos 32 caracteres')
    return segredo


def gerar_token(usuario, segredo, minutos=30):
    agora = datetime.now(timezone.utc)
    claims = {
        'sub': str(usuario['id']),
        'email': usuario['email'],
        'nivel': int(usuario['nivel_acesso']),
        'iss': EMISSOR,
        'iat': agora,
        'exp': agora + timedelta(minutes=minutos),
    }
    return jwt.encode(claims, segredo, algorithm=ALGORITMO)


def verificar_token(token, segredo):
    """Devolve as claims ou lança jwt.InvalidTokenError (assinatura, expiração, emissor)."""
    # `algorithms` fixo impede o ataque de trocar o algoritmo para "none".
    return jwt.decode(token, segredo, algorithms=[ALGORITMO], issuer=EMISSOR,
                      options={'require': ['sub', 'exp', 'iat', 'iss']})


def _erro(status, mensagem):
    resposta = jsonify({'erro': mensagem})
    resposta.status_code = status
    if status == 401:
        resposta.headers['WWW-Authenticate'] = 'Bearer'
    return resposta


def exigir_token(nivel_minimo=1):
    def decorador(funcao):
        @wraps(funcao)
        def executar(*args, **kwargs):
            from flask import request
            cabecalho = request.headers.get('Authorization', '')
            tipo, _, token = cabecalho.partition(' ')
            if tipo != 'Bearer' or not token:
                return _erro(401, 'Token ausente. Use Authorization: Bearer <token>.')
            try:
                claims = verificar_token(token.strip(), current_app.config['API_JWT_SECRET'])
            except jwt.InvalidTokenError:
                return _erro(401, 'Token inválido ou expirado.')
            if int(claims.get('nivel', 0)) < nivel_minimo:
                return _erro(403, 'Nível de acesso insuficiente para esta operação.')
            g.operador = claims
            return funcao(*args, **kwargs)
        return executar
    return decorador
