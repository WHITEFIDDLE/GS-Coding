"""Erros públicos, sem SQL, senha ou detalhes internos de conexão."""


class ErroPersistencia(RuntimeError):
    pass


class UsuarioDuplicado(ValueError):
    pass
