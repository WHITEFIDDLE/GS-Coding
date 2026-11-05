"""
Web Module E - Operator credential store (GS Aula 8, OWASP A07).

Security requirements implemented here:
    - Passwords are NEVER stored in plain text: PBKDF2-HMAC-SHA256 with a
      random 128-bit salt per user and 210k iterations (OWASP 2024 guidance
      for PBKDF2-SHA256). Only the hash lives in config/usuarios.json.
    - Constant-time comparison (hmac.compare_digest) on password check.
    - ANTI-ENUMERATION (scenario E3): when the login does not exist, a
      verification against a dummy hash is still executed so the response
      time does not reveal whether the account exists. The caller always
      shows the SAME generic error message for both cases.

CLI (from the project root) to add a user without exposing the password
in the shell history:
    python web/usuarios.py add
"""

import getpass
import hashlib
import hmac
import json
import os
import secrets
import sys

ITERACOES_PBKDF2 = 210_000

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAMINHO_USUARIOS_PADRAO = os.path.join(PROJECT_ROOT, "config", "usuarios.json")

# Dummy password used ONLY to equalize timing for unknown logins (anti-enumeration)
_DUMMY_SENHA = secrets.token_hex(32)


def gerar_hash_senha(senha):
    """
    Hash a password with PBKDF2-HMAC-SHA256 + random salt.
    Format: pbkdf2_sha256$<iterations>$<salt_hex>$<dk_hex>
    """
    salt = secrets.token_bytes(16)
    derivada = hashlib.pbkdf2_hmac("sha256", senha.encode("utf-8"), salt, ITERACOES_PBKDF2)
    return f"pbkdf2_sha256${ITERACOES_PBKDF2}${salt.hex()}${derivada.hex()}"


def verificar_senha(senha, hash_armazenado):
    """
    Verify a password against the stored PBKDF2 hash (constant-time compare).
    Returns True only when the password matches.
    """
    try:
        algoritmo, iteracoes, salt_hex, dk_hex = hash_armazenado.split("$")
        if algoritmo != "pbkdf2_sha256":
            return False
        derivada = hashlib.pbkdf2_hmac(
            "sha256", senha.encode("utf-8"), bytes.fromhex(salt_hex), int(iteracoes)
        )
        return hmac.compare_digest(derivada.hex(), dk_hex)
    except (ValueError, AttributeError, TypeError):
        return False


# Build the dummy hash AFTER the function definitions exist
DUMMY_HASH = gerar_hash_senha(_DUMMY_SENHA)


class UserStore:
    """
    JSON-backed operator store. In the FULL platform this role belongs to
    MySQL (Module B - mysql_repo.py with parameterized queries); this local
    store keeps Module E self-sufficient while Module B is not plugged in.
    """

    def __init__(self, caminho_usuarios=None):
        self.caminho = caminho_usuarios or CAMINHO_USUARIOS_PADRAO
        self.usuarios = {}
        self._carregar()

    def _carregar(self):
        try:
            with open(self.caminho, "r", encoding="utf-8") as f:
                dados = json.load(f)
            self.usuarios = dados.get("usuarios", {})
        except FileNotFoundError:
            print(f"[usuarios] WARNING: user file not found: {self.caminho}")
        except json.JSONDecodeError as exc:
            print(f"[usuarios] ERROR: invalid JSON in {self.caminho}: {exc}")
            self.usuarios = {}

    def autenticar(self, login, senha):
        """
        Authenticate an operator.

        ANTI-ENUMERATION: for unknown logins the password is verified against
        a dummy hash anyway (same PBKDF2 cost) and None is returned - exactly
        like a wrong password. The controller must emit the SAME generic
        message in both cases (scenario E3).
        """
        if not login or not senha:
            return None

        registro = self.usuarios.get(login)
        hash_alvo = registro.get("hash_senha") if registro else DUMMY_HASH
        senha_ok = verificar_senha(senha, hash_alvo)

        if registro and senha_ok:
            return {
                "login": login,
                "nome": registro.get("nome", login),
                "nivel_acesso": int(registro.get("nivel_acesso", 1)),
            }
        return None

    def existe(self, login):
        """Existence check - NOT used by the login flow (anti-enumeration)."""
        return login in self.usuarios

    def adicionar_usuario(self, login, senha, nome, nivel_acesso=1):
        """Add a user persisting ONLY the PBKDF2 hash (never the password)."""
        if login in self.usuarios:
            raise ValueError(f"login already exists: {login}")
        if nivel_acesso < 1 or nivel_acesso > 5:
            raise ValueError("nivel_acesso must be between 1 and 5")

        self.usuarios[login] = {
            "nome": nome,
            "nivel_acesso": int(nivel_acesso),
            "hash_senha": gerar_hash_senha(senha),
        }
        os.makedirs(os.path.dirname(self.caminho), exist_ok=True)
        with open(self.caminho, "w", encoding="utf-8") as f:
            json.dump({"usuarios": self.usuarios}, f, indent=2, ensure_ascii=False)


class MySQLUserStore:
    """
    Integração final: o login do dashboard passa a usar a tabela `usuarios`
    do MySQL (módulo B). O campo "login" do formulário é o e-mail. A
    autenticação, o hash e a anti-enumeração continuam em db/mysql_repo.py.
    """

    def __init__(self, repositorio_usuarios):
        self._repo = repositorio_usuarios

    def autenticar(self, login, senha):
        usuario = self._repo.autenticar(login, senha)
        if usuario is None:
            return None
        return {"login": usuario["email"], "nome": usuario["nome"],
                "nivel_acesso": int(usuario["nivel_acesso"])}


def _cli_interativo():
    """Interactive user creation (password typed via getpass, not argv)."""
    print("SecuraPy - create operator user")
    login = input("login: ").strip()
    nome = input("full name: ").strip() or login
    nivel = int(input("access level 1-5: ").strip() or "1")
    senha = getpass.getpass("password: ")
    senha2 = getpass.getpass("confirm password: ")
    if senha != senha2:
        print("ERROR: passwords do not match.")
        sys.exit(1)

    store = UserStore()
    try:
        store.adicionar_usuario(login, senha, nome, nivel)
        print(f"User '{login}' created in {store.caminho} (only the hash was stored).")
    except ValueError as exc:
        print(f"ERROR: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "add":
        _cli_interativo()
    else:
        print("Usage: python web/usuarios.py add")
