# Imagem da API + dashboard do SecuraPy Platform (módulo F — Aula 11).
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SECURAPY_ACCESS_LOG=/app/dados/access.log

WORKDIR /app

# Usuário sem privilégios: se a aplicação for comprometida, o atacante não é root.
RUN groupadd --system securapy && useradd --system --gid securapy --home-dir /app securapy

# Dependências primeiro: a camada fica em cache enquanto o requirements não muda.
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY --chown=securapy:securapy . .
RUN mkdir -p /app/dados && chown securapy:securapy /app/dados

USER securapy
EXPOSE 5000

HEALTHCHECK --interval=10s --timeout=5s --start-period=40s --retries=5 \
    CMD python -c "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/api/saude', timeout=4).status == 200 else 1)"

# Prepara os bancos (tabela e índices), cria o administrador inicial e sobe o gunicorn.
CMD ["python", "iniciar_api.py"]
