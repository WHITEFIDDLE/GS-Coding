"""
Web Module E - Pluggable data access layer (DataProvider).

The dashboard NEVER touches the database, the core pipeline or the ML module
directly - it only talks to a DataProvider. This is what makes the module
PLUGGABLE: while Module B (MongoDB) is not ready, the InMemoryDataProvider
serves data straight from the 1st-semester pipeline + ML scoring; when
Module B lands, RepositorioDataProvider plugs in WITHOUT changing a single line
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


class RepositorioDataProvider(DataProviderBase):
    """
    Integração final (Pessoa 2): o dashboard lê o MongoDB através do
    repositório do módulo B (db/mongo_repo.py) e calcula o score com o
    mesmo serviço usado pela API (servicos/plataforma.py). Assim, o que é
    analisado via POST /api/analisar aparece no dashboard sem duplicar código.
    """

    def __init__(self, repositorio, contexto, geolocalizar=None):
        self._repo = repositorio
        self._contexto = contexto
        self._geolocalizar = geolocalizar

    def _scores(self):
        from servicos.plataforma import pontuar, todos_os_eventos
        return pontuar(todos_os_eventos(self._repo), self._contexto)

    def resumo_eventos_por_fonte(self):
        return {item["fonte"]: item["total"] for item in self._repo.contar_por_fonte()}

    def contagem_alertas_por_severidade(self):
        contagem = {item["severidade"]: item["total"] for item in self._repo.contar_por_severidade()}
        return {sev: contagem.get(sev, 0) for sev in ORDEM_SEVERIDADE}

    def top_ips_suspeitos(self, limite=10):
        from servicos.plataforma import todos_os_alertas
        scores = self._scores()
        alertas_por_ip = Counter(a.get("ip") for a in todos_os_alertas(self._repo))
        infos = []
        for ip in set(scores) | set(alertas_por_ip):
            info = scores.get(ip, {})
            infos.append({
                "ip": ip, "score": info.get("score", 0.0), "rotulo": info.get("rotulo", "normal"),
                "nivel": info.get("nivel", "BAIXO"), "num_alertas": alertas_por_ip.get(ip, 0),
                "anomalia": False, "score_anomalia": None, "deteccoes": [],
                "features": info.get("features", {}),
            })
        infos.sort(key=lambda i: (-i["score"], -i["num_alertas"], i["ip"]))
        return infos[:limite]

    def todos_alertas_por_risco(self):
        from ml.classificar import ordenar_alertas_por_risco
        from servicos.plataforma import todos_os_alertas
        scores = self._scores()
        ordenados = ordenar_alertas_por_risco(todos_os_alertas(self._repo), scores)
        for alerta in ordenados:
            info = scores.get(alerta.get("ip"))
            alerta.setdefault("score_ip", info["score"] if info else None)
            alerta.setdefault("nivel_ip", info["nivel"] if info else "BAIXO")
        return ordenados

    def eventos_do_ip(self, ip):
        from servicos.plataforma import todos_os_eventos
        return todos_os_eventos(self._repo, ip=ip)

    def alertas_do_ip(self, ip):
        from servicos.plataforma import todos_os_alertas
        return todos_os_alertas(self._repo, ip=ip)

    def score_do_ip(self, ip):
        from ml.anomalias import detectar_anomalias
        from servicos.plataforma import pontuar
        eventos = self.eventos_do_ip(ip)
        if not eventos:
            return None
        info = pontuar(eventos, self._contexto).get(ip)
        anomalia = detectar_anomalias({ip: info["features"]}).get(ip, {}) if info else {}
        return {
            "ip": ip, "score": info["score"], "rotulo": info["rotulo"], "nivel": info["nivel"],
            "features": info["features"], "num_alertas": len(self.alertas_do_ip(ip)),
            "anomalia": bool(anomalia.get("anomalia")), "score_anomalia": anomalia.get("score_anomalia"),
            "deteccoes": [],
        }

    def registrar_alerta(self, alerta):
        return self._repo.registrar_alerta(alerta)

    def geo_do_ip(self, ip):
        if self._geolocalizar is None:
            return None
        geo = self._geolocalizar(ip)
        # Os templates usam os nomes do ipinfo; o módulo A usa nomes em português.
        return {"country": geo.get("pais"), "city": geo.get("cidade"), "org": geo.get("org")}
