"""Liga o núcleo ao MongoDB. Não reimplementa regras dentro do banco."""


def persistir_analise(analise, repositorio):
    eventos = repositorio.salvar_eventos(analise['eventos'])
    alertas = repositorio.salvar_alertas(analise['alertas'])
    return {'eventos': eventos, 'alertas': alertas}
