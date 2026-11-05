"""
Web Module E - Pluggable data access layer (DataProvider).

The dashboard NEVER touches the database, the core pipeline or the ML module
directly - it only talks to a DataProvider. This is what makes the module
PLUGGABLE: while Module B (MongoDB) is not ready, the InMemoryDataProvider
serves data straight from the 1st-semester pipeline + ML scoring; when
Module B lands, MongoDataProvider plugs in WITHOUT changing a single line
of the dashboard code (same interface, same routes, same templates).
"""

from collections import Counter

ORDEM_SEVERIDADE = ("CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO")


class DataProviderBase:
    """Interface contract for all data providers (integration with Module B)."""

    def resumo_eventos_por_fonte(self):
        """-> {fonte: total_eventos} (auth / firewall / web / manual)."""
        raise NotImplementedError

    def contagem_alertas_por_severidade(self):
        """-> {severidade: total_alertas}."""
        raise NotImplementedError

    def top_ips_suspeitos(self, limite=10):
        """-> [{ip, score, rotulo, nivel, num_alertas, anomalia, deteccoes}] ordered by risk."""
        raise NotImplementedError

    def todos_alertas_por_risco(self):
        """-> [alerta, ...] with each alerta enriched with 'score_ip'/'nivel_ip'."""
        raise NotImplementedError

    def eventos_do_ip(self, ip):
        """-> [evento, ...] for one IP."""
        raise NotImplementedError

    def alertas_do_ip(self, ip):
        """-> [alerta, ...] for one IP."""
        raise NotImplementedError

    def score_do_ip(self, ip):
        """-> {score, rotulo, nivel, features, anomalia, score_anomalia, deteccoes} or None."""
        raise NotImplementedError

    def registrar_alerta(self, alerta):
        """Persist one manual alert (E1 scenario) and return it with an id."""
        raise NotImplementedError

    def geo_do_ip(self, ip):
        """
        Hook for the enrichment layer (Module A - ipinfo.io + cache).
        Returns None when enrichment is not available (current scope).
        """
        return None


class InMemoryDataProvider(DataProviderBase):
    """
    Default provider: indexes the pipeline output in memory using dict/set
    structures (GS quality criterion) - O(1) lookups per IP.
    """

    def __init__(self, eventos, alertas, scores_por_ip, anomalias_por_ip=None,
                 ameacas=None):
        self._eventos = list(eventos)
        self._alertas = list(alertas)
        self._scores = dict(scores_por_ip or {})
        self._anomalias = dict(anomalias_por_ip or {})
        self._ameacas_por_ip = {a["ip"]: a for a in (ameacas or [])}

        # dict indexes per IP - the "glue" between dashboard views and data
        self._eventos_por_ip = {}
        for evento in self._eventos:
            self._eventos_por_ip.setdefault(evento.get("ip"), []).append(evento)
        self._alertas_por_ip = {}
        for alerta in self._alertas:
            self._alertas_por_ip.setdefault(alerta.get("ip"), []).append(alerta)

        self._contador_ids = 0

    # ------------------------------------------------------------------ #
    def resumo_eventos_por_fonte(self):
        return dict(Counter(ev.get("fonte", "?") for ev in self._eventos))

    def contagem_alertas_por_severidade(self):
        contagem = Counter(al.get("severidade", "INFO") for al in self._alertas)
        return {sev: contagem.get(sev, 0) for sev in ORDEM_SEVERIDADE}

    def _ip_info(self, ip):
        """Assemble the full risk picture of one IP (ML + anomaly + detections)."""
        info = self._scores.get(ip)
        anomalia = self._anomalias.get(ip)
        saida = {
            "ip": ip,
            "score": info["score"] if info else 0.0,
            "rotulo": info["rotulo"] if info else "normal",
            "nivel": info["nivel"] if info else "BAIXO",
            "num_alertas": len(self._alertas_por_ip.get(ip, [])),
            "anomalia": bool(anomalia["anomalia"]) if anomalia else False,
            "score_anomalia": anomalia["score_anomalia"] if anomalia else None,
            "deteccoes": self._ameacas_por_ip[ip]["deteccoes"] if ip in self._ameacas_por_ip else [],
            "features": info["features"] if info else {},
        }
        return saida

    def top_ips_suspeitos(self, limite=10):
        todos_ips = set(self._scores) | set(self._alertas_por_ip)
        infos = [self._ip_info(ip) for ip in todos_ips]
        infos.sort(key=lambda i: (-i["score"], -i["num_alertas"], i["ip"]))
        return infos[:limite]

    def todos_alertas_por_risco(self):
        from ml.classificar import ordenar_alertas_por_risco

        ordenados = ordenar_alertas_por_risco(self._alertas, self._scores)
        for alerta in ordenados:
            info = self._scores.get(alerta.get("ip"))
            alerta.setdefault("score_ip", info["score"] if info else None)
            alerta.setdefault("nivel_ip", info["nivel"] if info else "BAIXO")
        return ordenados

    def eventos_do_ip(self, ip):
        return list(self._eventos_por_ip.get(ip, []))

    def alertas_do_ip(self, ip):
        return list(self._alertas_por_ip.get(ip, []))

    def score_do_ip(self, ip):
        if ip not in self._scores and ip not in self._eventos_por_ip:
            return None
        return self._ip_info(ip)

    def registrar_alerta(self, alerta):
        self._contador_ids += 1
        alerta = dict(alerta)
        alerta["id"] = f"MAN-{self._contador_ids:04d}"
        self._alertas.append(alerta)
        self._alertas_por_ip.setdefault(alerta.get("ip"), []).append(alerta)
        return alerta


class MongoDataProvider(DataProviderBase):
    """
    INTEGRATION POINT with Module B (mongo_repo.py).

    Plugs the dashboard straight into MongoDB when the persistence module
    lands. Requires: pymongo installed + the events/alerts collections
    populated by the Module B ingestion. The dashboard code does NOT change
    - only the provider instance passed to web.dashboard.criar_app().

    Expected document shapes (agreed contract with Module B):
        eventos : {timestamp, fonte, tipo, ip, detalhes, linha_original}
        alertas : {timestamp, regra_id, regra_nome, severidade, ip, fonte, descricao}
    """

    def __init__(self, uri, database="securaPy", scores_por_ip=None,
                 anomalias_por_ip=None):
        try:
            from pymongo import MongoClient
        except ImportError as exc:
            raise ImportError(
                "MongoDataProvider requires pymongo (pip install pymongo) "
                "and the Module B ingestion to be executed first."
            ) from exc

        self._cliente = MongoClient(uri, serverSelectionTimeoutMS=3000)
        self._db = self._cliente[database]
        self._eventos = self._db["eventos"]
        self._alertas = self._db["alertas"]
        self._scores = dict(scores_por_ip or {})
        self._anomalias = dict(anomalias_por_ip or {})

    def resumo_eventos_por_fonte(self):
        agreg = self._eventos.aggregate([
            {"$group": {"_id": "$fonte", "total": {"$sum": 1}}}
        ])
        return {doc["_id"]: doc["total"] for doc in agreg}

    def contagem_alertas_por_severidade(self):
        agreg = self._alertas.aggregate([
            {"$group": {"_id": "$severidade", "total": {"$sum": 1}}}
        ])
        contagem = {doc["_id"]: doc["total"] for doc in agreg}
        return {sev: contagem.get(sev, 0) for sev in ORDEM_SEVERIDADE}

    def top_ips_suspeitos(self, limite=10):
        agreg = self._eventos.aggregate([
            {"$group": {"_id": "$ip", "total": {"$sum": 1}}},
            {"$sort": {"total": -1}},
            {"$limit": limite * 2},
        ])
        por_ip = {doc["_id"]: doc["total"] for doc in agreg}
        infos = []
        for ip, total in por_ip.items():
            info = self.score_do_ip(ip) or {"ip": ip, "score": 0.0, "rotulo": "normal",
                                            "nivel": "BAIXO"}
            info["num_alertas"] = self._alertas.count_documents({"ip": ip})
            infos.append(info)
        infos.sort(key=lambda i: (-i["score"], -i["num_alertas"]))
        return infos[:limite]

    def todos_alertas_por_risco(self):
        from ml.classificar import ordenar_alertas_por_risco

        alertas = list(self._alertas.find({}, {"_id": 0}).limit(2000))
        ordenados = ordenar_alertas_por_risco(alertas, self._scores)
        for alerta in ordenados:
            info = self._scores.get(alerta.get("ip"))
            alerta.setdefault("score_ip", info["score"] if info else None)
            alerta.setdefault("nivel_ip", info["nivel"] if info else "BAIXO")
        return ordenados

    def eventos_do_ip(self, ip):
        return list(self._eventos.find({"ip": ip}, {"_id": 0}).sort("timestamp", 1))

    def alertas_do_ip(self, ip):
        return list(self._alertas.find({"ip": ip}, {"_id": 0}).sort("timestamp", 1))

    def score_do_ip(self, ip):
        info = self._scores.get(ip)
        if not info:
            return None
        anomalia = self._anomalias.get(ip)
        return {
            "ip": ip,
            "score": info["score"],
            "rotulo": info["rotulo"],
            "nivel": info["nivel"],
            "features": info["features"],
            "num_alertas": self._alertas.count_documents({"ip": ip}),
            "anomalia": bool(anomalia["anomalia"]) if anomalia else False,
            "score_anomalia": anomalia["score_anomalia"] if anomalia else None,
            "deteccoes": [],
        }

    def registrar_alerta(self, alerta):
        resultado = self._alertas.insert_one(dict(alerta))
        alerta = dict(alerta, id=str(resultado.inserted_id))
        return alerta
