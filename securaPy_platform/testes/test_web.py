"""
Module E test scenarios (GS section 3, Módulo E):
    E1 - alert with description '<script>alert(1)</script>' rendered -> literal text, script NOT executed
    E2 - response headers include the 3 required security headers
    E3 - wrong password AND unknown user -> same generic 401 message
    E4 - any route -> one access log line registered (OWASP A09)
"""

import os

# --------------------------------------------------------------------------- #
# Access control
# --------------------------------------------------------------------------- #
def test_rotas_protegidas_redirecionam_para_login(cliente):
    resposta = cliente.get("/")
    assert resposta.status_code == 302
    assert "/login" in resposta.headers["Location"]


# --------------------------------------------------------------------------- #
# E1 - XSS
# --------------------------------------------------------------------------- #
def test_e1_xss_e_escapado_no_render(cliente_logado):
    # Register an alert whose description carries a script payload
    resposta = cliente_logado.post("/alertas/novo", data={
        "csrf_token": "token-teste-csrf",
        "ip": "203.0.113.77",
        "severidade": "ALTA",
        "descricao": "<script>alert(1)</script>",
    }, follow_redirects=True)
    assert resposta.status_code == 200

    html = resposta.get_data(as_text=True)
    # The payload must appear as ESCAPED literal text...
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    # ...and must NEVER be present as a live script element
    assert "<script>alert(1)</script>" not in html


def test_e1_tambem_sem_csrf_nao_salva(cliente_logado):
    resposta = cliente_logado.post("/alertas/novo", data={
        "ip": "203.0.113.78",
        "severidade": "ALTA",
        "descricao": "sem csrf",
    })
    assert resposta.status_code == 400


# --------------------------------------------------------------------------- #
# E2 - security headers
# --------------------------------------------------------------------------- #
def test_e2_headers_de_seguranca_presentes(cliente):
    resposta = cliente.get("/login")
    assert resposta.status_code == 200
    assert resposta.headers["X-Content-Type-Options"] == "nosniff"
    assert resposta.headers["X-Frame-Options"] == "DENY"
    csp = resposta.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp


def test_e2_headers_em_todas_as_rotas(cliente_logado):
    for caminho in ("/", "/alertas", "/busca?ip=185.220.101.1", "/inexistente"):
        resposta = cliente_logado.get(caminho)
        for cabecalho in ("X-Content-Type-Options", "X-Frame-Options",
                          "Content-Security-Policy"):
            assert cabecalho in resposta.headers, f"{cabecalho} missing on {caminho}"


# --------------------------------------------------------------------------- #
# E3 - hardened login (anti-enumeration)
# --------------------------------------------------------------------------- #
def test_e3_senha_errada_e_usuario_inexistente_geram_mesma_mensagem(cliente):
    resposta_senha_errada = cliente.post("/login", data={
        "login": "admin", "senha": "SenhaErrada!123",
    })
    resposta_usuario_inexistente = cliente.post("/login", data={
        "login": "usuario_fantasma_xyz", "senha": "QualquerSenha!123",
    })

    # Same status and SAME generic message in both cases
    assert resposta_senha_errada.status_code == 401
    assert resposta_usuario_inexistente.status_code == 401
    corpo_1 = resposta_senha_errada.get_data(as_text=True)
    corpo_2 = resposta_usuario_inexistente.get_data(as_text=True)
    assert "Credenciais inválidas." in corpo_1
    assert "Credenciais inválidas." in corpo_2


def test_e3_login_valido_entra_no_dashboard(cliente):
    resposta = cliente.post("/login", data={
        "login": "admin", "senha": "SecuraPy@2025",
    }, follow_redirects=True)
    assert resposta.status_code == 200
    assert "Visão geral" in resposta.get_data(as_text=True)


# --------------------------------------------------------------------------- #
# E4 - access logging (OWASP A09)
# --------------------------------------------------------------------------- #
def test_e4_toda_requisicao_gera_linha_de_log(app, cliente_logado):
    caminho_log = app._caminho_log_acesso_teste
    linhas_antes = 0
    if os.path.exists(caminho_log):
        with open(caminho_log, encoding="utf-8") as f:
            linhas_antes = sum(1 for _ in f)

    cliente_logado.get("/")

    assert os.path.exists(caminho_log)
    with open(caminho_log, encoding="utf-8") as f:
        linhas = f.readlines()
    assert len(linhas) > linhas_antes
    ultima = linhas[-1]
    assert '"GET /"' in ultima
    assert "usuario=" in ultima
    assert "200" in ultima


# --------------------------------------------------------------------------- #
# Input validation (GS error-handling criterion: 400, never 500)
# --------------------------------------------------------------------------- #
def test_busca_com_ip_malformado_retorna_400(cliente_logado):
    resposta = cliente_logado.get("/busca", query_string={"ip": "999.999.ip!"})
    assert resposta.status_code == 400
    assert "inválido" in resposta.get_data(as_text=True).lower()


def test_busca_ip_valido_mostra_score_e_ia(cliente_logado):
    resposta = cliente_logado.get("/busca", query_string={"ip": "185.220.101.1"})
    corpo = resposta.get_data(as_text=True)
    assert resposta.status_code == 200
    assert "CRÍTICO" in corpo          # assistant explanation present
    assert "Score de ML" in corpo


def test_erro_404_generico_sem_traceback(cliente):
    resposta = cliente.get("/rota/que/nao/existe")
    assert resposta.status_code == 404
    corpo = resposta.get_data(as_text=True)
    assert "não encontrada" in corpo.lower()
    assert "Traceback" not in corpo
