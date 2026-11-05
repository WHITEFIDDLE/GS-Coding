"""MongoDB guarda eventos e alertas, sem conhecer Flask ou machine learning."""
from functools import wraps
from ipaddress import ip_address

from bson import ObjectId
from pymongo import MongoClient, UpdateOne
from pymongo.errors import PyMongoError

from db.documentos import data_utc, para_json, preparar_documento
from db.erros import ErroPersistencia


def tratar_erros_mongo(funcao):
    @wraps(funcao)
    def executar(*args, **kwargs):
        try:
            return funcao(*args, **kwargs)
        except PyMongoError:
            raise ErroPersistencia('Não foi possível concluir a operação no MongoDB.') from None
    return executar


class RepositorioMongo:
    def __init__(self, uri, banco='securapy_gs', fuso_logs='America/Sao_Paulo'):
        self.cliente = MongoClient(uri, serverSelectionTimeoutMS=5000, tz_aware=True)
        self.banco = self.cliente[banco]
        self.fuso_logs = fuso_logs

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.fechar()

    def fechar(self):
        self.cliente.close()

    @tratar_erros_mongo
    def preparar(self):
        self.cliente.admin.command('ping')
        for nome, chave in [('eventos', 'chave_evento'), ('alertas', 'chave_alerta')]:
            colecao = self.banco[nome]
            colecao.create_index('ip')
            colecao.create_index('timestamp')
            colecao.create_index(chave, unique=True)
        self.banco.alertas.create_index('severidade')

    @tratar_erros_mongo
    def _salvar(self, documentos, tipo):
        documentos = list(documentos)
        if not documentos:
            return {'recebidos': 0, 'inseridos': 0, 'existentes': 0}
        # Preparar todos antes do envio evita gravar metade por erro de validação.
        preparados = [preparar_documento(doc, tipo, self.fuso_logs) for doc in documentos]
        chave = 'chave_' + tipo
        operacoes = [UpdateOne({chave: doc[chave]}, {'$setOnInsert': doc}, upsert=True) for doc in preparados]
        colecao = self.banco.eventos if tipo == 'evento' else self.banco.alertas
        resultado = colecao.bulk_write(operacoes, ordered=True)
        return {'recebidos': len(documentos), 'inseridos': resultado.upserted_count,
                'existentes': resultado.matched_count}

    def salvar_eventos(self, eventos):
        return self._salvar(eventos, 'evento')

    def salvar_alertas(self, alertas):
        return self._salvar(alertas, 'alerta')

    @tratar_erros_mongo
    def registrar_alerta(self, alerta):
        """Salva um alerta e devolve o documento gravado, com `id` (usado pela API)."""
        documento = preparar_documento(alerta, 'alerta', self.fuso_logs)
        filtro = {'chave_alerta': documento['chave_alerta']}
        self.banco.alertas.update_one(filtro, {'$setOnInsert': documento}, upsert=True)
        return para_json(self.banco.alertas.find_one(filtro))

    def _filtro(self, fonte=None, tipo=None, ip=None, inicio=None, fim=None, severidade=None):
        filtro = {}
        if fonte is not None:
            if fonte not in {'auth', 'firewall', 'web'}:
                raise ValueError('Fonte inválida')
            filtro['fonte'] = fonte
        if tipo is not None:
            if not isinstance(tipo, str) or not 1 <= len(tipo) <= 30:
                raise ValueError('Tipo inválido')
            filtro['tipo'] = tipo
        if ip is not None:
            filtro['ip'] = str(ip_address(ip))
        datas = {}
        if inicio is not None:
            datas['$gte'] = data_utc(inicio, self.fuso_logs)
        if fim is not None:
            datas['$lte'] = data_utc(fim, self.fuso_logs)
        if inicio is not None and fim is not None and datas['$gte'] > datas['$lte']:
            raise ValueError('Início posterior ao fim')
        if datas:
            filtro['timestamp'] = datas
        if severidade is not None:
            if not isinstance(severidade, str) or severidade.upper() not in {'INFO', 'BAIXA', 'MEDIA', 'ALTA', 'CRITICA'}:
                raise ValueError('Severidade inválida')
            filtro['severidade'] = severidade.upper()
        return filtro

    @tratar_erros_mongo
    def _buscar(self, colecao, pagina, tamanho, filtros):
        if type(pagina) is not int or pagina < 1 or type(tamanho) is not int or not 1 <= tamanho <= 100:
            raise ValueError('Página deve ser positiva; tamanho deve estar entre 1 e 100')
        filtro = self._filtro(**filtros)
        cursor = colecao.find(filtro).sort([('timestamp', -1), ('_id', 1)]).skip((pagina - 1) * tamanho).limit(tamanho)
        return {'itens': para_json(list(cursor)), 'total': colecao.count_documents(filtro),
                'pagina': pagina, 'tamanho': tamanho}

    def buscar_eventos(self, pagina=1, tamanho=20, **filtros):
        return self._buscar(self.banco.eventos, pagina, tamanho, filtros)

    def buscar_alertas(self, pagina=1, tamanho=20, **filtros):
        return self._buscar(self.banco.alertas, pagina, tamanho, filtros)

    @tratar_erros_mongo
    def buscar_alerta(self, alerta_id):
        if not isinstance(alerta_id, str) or not ObjectId.is_valid(alerta_id):
            raise ValueError('Identificador de alerta inválido')
        documento = self.banco.alertas.find_one({'_id': ObjectId(alerta_id)})
        return para_json(documento) if documento else None

    @tratar_erros_mongo
    def top_ips(self, limite=5):
        if type(limite) is not int or not 1 <= limite <= 100:
            raise ValueError('Limite deve estar entre 1 e 100')
        pipeline = [{'$group': {'_id': '$ip', 'total': {'$sum': 1}}},
                    {'$sort': {'total': -1, '_id': 1}}, {'$limit': limite},
                    {'$project': {'_id': 0, 'ip': '$_id', 'total': 1}}]
        return list(self.banco.eventos.aggregate(pipeline))

    @tratar_erros_mongo
    def contar_por_severidade(self):
        return list(self.banco.alertas.aggregate([
            {'$group': {'_id': '$severidade', 'total': {'$sum': 1}}},
            {'$project': {'_id': 0, 'severidade': '$_id', 'total': 1}}, {'$sort': {'severidade': 1}}]))

    @tratar_erros_mongo
    def contar_por_fonte(self):
        return list(self.banco.eventos.aggregate([
            {'$group': {'_id': '$fonte', 'total': {'$sum': 1}}},
            {'$project': {'_id': 0, 'fonte': '$_id', 'total': 1}}, {'$sort': {'fonte': 1}}]))
