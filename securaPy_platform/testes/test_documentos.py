from datetime import datetime, timezone

import pytest

from db.documentos import data_utc, preparar_documento


def test_data_local_convertida_para_utc():
    assert data_utc('2025-02-20 08:15:01') == datetime(2025, 2, 20, 11, 15, 1, tzinfo=timezone.utc)
    assert data_utc('2025-02-20T11:15:01Z') == data_utc('2025-02-20 08:15:01')


def test_identidade_estavel_e_sem_mutacao():
    evento = {'timestamp':'2025-02-20 08:15:01', 'ip':'10.0.0.1', 'fonte':'auth', 'tipo':'FAIL'}
    primeiro = preparar_documento(evento, 'evento', 'America/Sao_Paulo')
    segundo = preparar_documento(dict(reversed(list(evento.items()))), 'evento', 'America/Sao_Paulo')
    assert primeiro['chave_evento'] == segundo['chave_evento']
    assert 'chave_evento' not in evento
    with pytest.raises(ValueError):
        preparar_documento({}, 'evento', 'America/Sao_Paulo')
