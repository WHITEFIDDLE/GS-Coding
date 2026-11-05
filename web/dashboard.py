"""
Web Module E - Secure Analyst Dashboard (GS Aula 8, OWASP Top 10).

Security controls implemented (each mapped to a GS test scenario):

    E1  XSS DEFENSE       Jinja2 autoescape forced ON for every template and
                          never using the |safe filter -> all data rendered
                          is HTML-escaped; plus a strict CSP that blocks any
                          inline/remote script even if escaping failed.
    E2  SECURITY HEADERS  after_request hook injects, on EVERY response:
                          X-Content-Type-Options, X-Frame-Options,
                          Content-Security-Policy (+ Referrer-Policy extra).
    E3  HARDENED LOGIN    PBKDF2 hashed passwords (web/usuarios.py), constant
                          time compare, timing-equalized unknown-login path
                          and ONE generic error message for both cases
                          ("anti user enumeration").
    E4  ACCESS LOGGING    every request logged (method, path, IP, status,
                          authenticated user, duration) to logs/access.log -
                          OWASP A09: Security Logging and Monitoring Failure.

Extra hardening: session cookie HttpOnly + SameSite=Lax, secret key from
env, CSRF token on the alert-registration form, generic error handlers that
never leak tracebacks, input validation (IP via ipaddress, severity from a
fixed set).

Run (from the project root, after 'python ml/treinar.py'):
    python web/dashboard.py                # http://127.0.0.1:5000
"""

import ipaddress
import logging
import os
import secrets
import sys
import time
from datetime import datetime, timedelta

from flask import (Flask, flash, g, redirect, render_template, request,
                   session, url_for)
from functools import wraps

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ia.assistente import obter_assistente                     # noqa: E402
from web.providers import InMemoryDataProvider                  # noqa: E402
from web.usuarios import UserStore                              # noqa: E402

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Fixed severity set for form validation (E1 write path)
SEVERIDADES_VALIDAS = ("CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO")

HEADERS_SEGURANCA = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    ),
    "Referrer-Policy": "same-origin",
}


# --------------------------------------------------------------------------- #
# Access logging (OWASP A09)
# --------------------------------------------------------------------------- #
def criar_logger_acesso(caminho_log):
    logger = logging.getLogger("securaPy.acesso")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if logger.handlers:            # avoid duplicated handlers across reloads
        return logger
    os.makedirs(os.path.dirname(caminho_log), exist_ok=True)
    handler = logging.FileHandler(caminho_log, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(message)s",
                                           datefmt="%Y-%m-%d %H:%M:%S"))
    logger.addHandler(handler)
    return logger


def _ip_cliente():
    """Client IP of the request (no proxy chain handling in the lab scope)."""
    return request.remote_addr or "-"


# --------------------------------------------------------------------------- #
# Default provider wiring (core -> ML -> assistant), used when nothing is injected
# --------------------------------------------------------------------------- #
def construir_provider_padrao(assistente=None):
    from core.detector import carregar_blacklist, executar_pipeline_deteccao
    from ml.anomalias import detectar_anomalias
    from ml.classificar import carregar_modelo, pontuar_ips
    from ml.features import (extract_features_by_ip, load_suspicious_patterns)

    eventos, alertas, ameacas = executar_pipeline_deteccao(
        os.path.join(PROJECT_ROOT, "logs"),
        os.path.join(PROJECT_ROOT, "config", "regras.json"),
        os.path.join(PROJECT_ROOT, "config", "blacklist.txt"),
    )
    blacklist = carregar_blacklist(os.path.join(PROJECT_ROOT, "config", "blacklist.txt"))
    padroes = load_suspicious_patterns(os.path.join(PROJECT_ROOT, "config", "regras.json"))

    features_por_ip = extract_features_by_ip(eventos, blacklist, padroes)
    modelo = carregar_modelo()                    # hash-verified load (C4)
    scores_por_ip = pontuar_ips(features_por_ip, modelo)
    anomalias_por_ip = detectar_anomalias(features_por_ip)   # bonus Isolation Forest

    return InMemoryDataProvider(eventos, alertas, scores_por_ip,
                                anomalias_por_ip, ameacas)


# --------------------------------------------------------------------------- #
# App factory
# --------------------------------------------------------------------------- #
def criar_app(data_provider=None, user_store=None, assistente=None,
              caminho_log_acesso=None):
    app = Flask(__name__, template_folder="templates", static_folder="static")

    # SECRET: environment first; dev fallback is random per process (never
    # hardcoded - secrets in env is a GS code-quality criterion).
    app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
    if not os.environ.get("SECRET_KEY"):
        app.logger.warning("SECRET_KEY not set - using a random per-process key "
                           "(sessions reset on restart; set SECRET_KEY in production).")

    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,       # JS cannot read the cookie
        SESSION_COOKIE_SAMESITE="Lax",      # CSRF mitigation for cookies
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        MAX_CONTENT_LENGTH=64 * 1024,       # request size limit
    )

    # XSS defense: force autoescape ON globally (Flask already autoescapes
    # .html; making it explicit documents the E1 defense for the review).
    app.jinja_options = dict(app.jinja_options, autoescape=True)

    user_store = user_store or UserStore()
    assistente = assistente or obter_assistente()
    data_provider = data_provider or construir_provider_padrao(assistente)

    caminho_log = (caminho_log_acesso
                   or os.environ.get("SECURAPY_ACCESS_LOG")
                   or os.path.join(PROJECT_ROOT, "logs", "access.log"))
    logger_acesso = criar_logger_acesso(caminho_log)

    # ------------------------------------------------------------------ #
    # Hooks: access logging (E4) + security headers (E2)
    # ------------------------------------------------------------------ #
    @app.before_request
    def _iniciar_cronometro():
        g.inicio_requisicao = time.perf_counter()

    @app.after_request
    def _registrar_e_proteger(resposta):
        duracao_ms = (time.perf_counter() - getattr(g, "inicio_requisicao",
                                                    time.perf_counter())) * 1000
        usuario = session.get("usuario", "-")
        # One line per request (scenario E4) - OWASP A09 audit trail
        logger_acesso.info(
            '%s - "%s %s" - %s - usuario=%s - %.1fms - %dB',
            _ip_cliente(), request.method, request.path, resposta.status_code,
            usuario, duracao_ms, resposta.calculate_content_length() or 0,
        )
        # Security headers on EVERY response (scenario E2)
        for cabecalho, valor in HEADERS_SEGURANCA.items():
            resposta.headers[cabecalho] = valor
        return resposta

    # ------------------------------------------------------------------ #
    # Auth helpers
    # ------------------------------------------------------------------ #
    def login_required(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if "usuario" not in session:
                return redirect(url_for("login", next=request.path))
            return f(*args, **kwargs)
        return wrapper

    def _token_csrf():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(16)
        return session["csrf_token"]

    def _csrf_valido():
        token = request.form.get("csrf_token", "")
        return token and secrets.compare_digest(token, session.get("csrf_token", ""))

    app.jinja_env.globals["csrf_token"] = _token_csrf
    app.jinja_env.globals["now"] = datetime.now

    # ------------------------------------------------------------------ #
    # Login / logout (scenario E3)
    # ------------------------------------------------------------------ #
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            login_digitado = request.form.get("login", "")
            senha = request.form.get("senha", "")
            usuario = user_store.autenticar(login_digitado, senha)

            if usuario is None:
                # ANTI-ENUMERATION: identical message + 401 for wrong
                # password AND unknown user (same generic wording).
                logger_acesso.warning(
                    '%s - LOGIN FALHOU - login=%s - "%s"',
                    _ip_cliente(), login_digitado[:50], request.path,
                )
                return render_template("login.html",
                                       erro="Credenciais inválidas."), 401

            session["usuario"] = usuario["login"]
            session["nome"] = usuario["nome"]
            session["nivel_acesso"] = usuario["nivel_acesso"]
            session.permanent = True
            logger_acesso.warning(
                '%s - LOGIN OK - login=%s - "%s"',
                _ip_cliente(), usuario["login"], request.path,
            )
            destino = request.args.get("next") or url_for("dashboard")
            # open-redirect protection: only relative paths allowed
            if not destino.startswith("/") or destino.startswith("//"):
                destino = url_for("dashboard")
            return redirect(destino)

        return render_template("login.html", erro=None)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # ------------------------------------------------------------------ #
    # Dashboard home (E-requirement 1: summary views)
    # ------------------------------------------------------------------ #
    @app.route("/")
    @login_required
    def dashboard():
        resumo_fontes = data_provider.resumo_eventos_por_fonte()
        total_eventos = sum(resumo_fontes.values())
        por_severidade = data_provider.contagem_alertas_por_severidade()
        total_alertas = sum(por_severidade.values())
        top_ips = data_provider.top_ips_suspeitos(limite=10)
        return render_template(
            "dashboard.html",
            resumo_fontes=resumo_fontes,
            total_eventos=total_eventos,
            por_severidade=por_severidade,
            total_alertas=total_alertas,
            top_ips=top_ips,
            consulta_ip="",
        )

    # ------------------------------------------------------------------ #
    # IP search (events + alerts + ML score + LLM explanation)
    # ------------------------------------------------------------------ #
    @app.route("/busca")
    @login_required
    def busca():
        ip = (request.args.get("ip") or "").strip()
        contexto = {"consulta_ip": ip, "ip_valido": False, "erro": None}

        if not ip:
            contexto["erro"] = "Informe um IP para a busca."
            return render_template("busca_ip.html", **contexto), 400

        try:
            ipaddress.ip_address(ip)     # validation: 400 on malformed input
        except ValueError:
            contexto["erro"] = ("Formato de IP inválido. Exemplo válido: "
                                "185.220.101.1")
            return render_template("busca_ip.html", **contexto), 400

        contexto.update(
            ip_valido=True,
            ip=ip,
            info_ip=data_provider.score_do_ip(ip),
            eventos=data_provider.eventos_do_ip(ip),
            alertas=data_provider.alertas_do_ip(ip),
            geo=data_provider.geo_do_ip(ip),
        )

        # Assistant explanation (Module G): explain the MOST SEVERE alert of
        # the IP (best triage value); when the IP has no alerts, explain its
        # first event.
        alvo = None
        if contexto["alertas"]:
            ordem_sev = {"CRITICA": 0, "ALTA": 1, "MEDIA": 2, "BAIXA": 3, "INFO": 4}
            alvo = min(contexto["alertas"],
                       key=lambda a: ordem_sev.get(a.get("severidade"), 9))
        elif contexto["eventos"]:
            alvo = contexto["eventos"][0]
        contexto["analise_ia"] = assistente.analisar_alerta(alvo) if alvo else None
        return render_template("busca_ip.html", **contexto)

    # ------------------------------------------------------------------ #
    # Alerts list + manual registration form (scenario E1)
    # ------------------------------------------------------------------ #
    @app.route("/alertas")
    @login_required
    def alertas():
        return render_template(
            "alertas.html",
            lista_alertas=data_provider.todos_alertas_por_risco(),
            severidades=SEVERIDADES_VALIDAS,
        )

    @app.route("/alertas/novo", methods=["POST"])
    @login_required
    def alertas_novo():
        if not _csrf_valido():
            return "Token CSRF inválido ou ausente.", 400

        ip = (request.form.get("ip") or "").strip()
        severidade = request.form.get("severidade", "")
        descricao = (request.form.get("descricao") or "").strip()

        erros = []
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            erros.append("IP inválido.")
        if severidade not in SEVERIDADES_VALIDAS:
            erros.append("Severidade inválida.")
        if not descricao or len(descricao) > 500:
            erros.append("Descrição obrigatória (máximo 500 caracteres).")
        if erros:
            flash(" ".join(erros), "erro")
            return redirect(url_for("alertas"))

        alerta = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "regra_id": "MANUAL",
            "regra_nome": "Alerta manual do operador",
            "severidade": severidade,
            "ip": ip,
            "fonte": "manual",
            "descricao": descricao,     # user input - ALWAYS escaped on render
        }
        salvo = data_provider.registrar_alerta(alerta)
        flash(f"Alerta {salvo['id']} registrado e exibido com escaping.", "sucesso")
        return redirect(url_for("alertas"))

    # ------------------------------------------------------------------ #
    # Error handlers - generic messages, no traceback leakage (GS criterion)
    # ------------------------------------------------------------------ #
    @app.errorhandler(404)
    def _nao_encontrado(_erro):
        return render_template("erro.html",
                               codigo=404, mensagem="Página não encontrada."), 404

    @app.errorhandler(400)
    def _requisicao_invalida(_erro):
        return render_template("erro.html",
                               codigo=400, mensagem="Requisição inválida."), 400

    @app.errorhandler(500)
    def _erro_interno(erro):
        # details go to the server log only - the client sees a generic page
        app.logger.exception("Internal error: %s", erro)
        return render_template("erro.html",
                               codigo=500,
                               mensagem="Erro interno do servidor."), 500

    return app


if __name__ == "__main__":
    app = criar_app()
    # debug=False in this codebase: never expose the debugger (OWASP A05)
    app.run(host="127.0.0.1", port=5000, debug=False)
