import calendar
import logging
import pprint
import requests
from datetime import datetime
from collections import defaultdict
import time

logger = logging.getLogger('opensky_api')
logger.addHandler(logging.NullHandler())

# [As classes StateVector e OpenSkyStates permanecem IDÊNTICAS para garantir compatibilidade]
class StateVector(object):
    keys = ["icao24", "callsign", "origin_country", "time_position",
            "last_contact", "longitude", "latitude", "baro_altitude", "on_ground",
            "velocity", "heading", "vertical_rate", "sensors",
            "geo_altitude", "squawk", "spi", "position_source"]

    def __init__(self, arr):
        self.__dict__ = dict(zip(StateVector.keys, arr))

    def __repr__(self):
        return "StateVector(%s)" % repr(self.__dict__.values())

    def __str__(self):
        return pprint.pformat(self.__dict__, indent=4)

class OpenSkyStates(object):
    def __init__(self, j):
        self.__dict__ = j
        if self.states is not None:
            self.states = [StateVector(a) for a in self.states]
        else:
            self.states = []

    def __repr__(self):
        return "<OpenSkyStates@%s>" % str(self.__dict__)

    def __str__(self):
        return pprint.pformat(self.__dict__, indent=4)

class OpenSkyApi(object):
    """
    Main class of the OpenSky Network API. 
    Atualizada para suportar autenticação baseada em sessão conforme novas regras.
    """
    def __init__(self, username=None, password=None):
        self._api_url = "https://opensky-network.org/api"
        self._last_requests = defaultdict(lambda: 0)
        self._username = username
        self._password = password
        self._session = requests.Session() # Uso de sessão para manter cookies/tokens
        
        if username and password:
            # Tenta realizar o login inicial para obter o cookie de sessão (JSESSIONID)
            # que é o método preferencial atual em vez de Basic Auth repetitivo.
            self._login()

    def _login(self):
        """ Realiza o login para obter um token de sessão """
        try:
            # A API da OpenSky muitas vezes valida o Basic Auth na primeira requisição
            # e mantém a sessão via Cookie.
            auth = (self._username, self._password)
            r = self._session.get(f"{self._api_url}/states/own", auth=auth, timeout=10)
            if r.status_code == 200:
                logger.info("Login bem-sucedido via sessão.")
            else:
                logger.warning(f"Falha na autenticação inicial: {r.status_code}")
        except Exception as e:
            logger.error(f"Erro ao tentar autenticar: {e}")

    def _get_json(self, url_post, callee, params=None):
        # Se não houver credenciais, não envia auth (acesso anônimo)
        auth = (self._username, self._password) if self._username else None
        
        try:
            # O objeto self._session gerencia automaticamente os cookies de login
            r = self._session.get("{0:s}{1:s}".format(self._api_url, url_post),
                                 auth=auth, params=params, timeout=15.00)
            
            if r.status_code == 200:
                self._last_requests[callee] = time.time()
                return r.json()
            elif r.status_code == 401:
                logger.error("Erro 401: Não autorizado. Verifique suas credenciais.")
            elif r.status_code == 429:
                logger.warning("Erro 429: Limite de requisições excedido (Rate Limit).")
            else:
                logger.debug("Response not OK. Status {0:d} - {1:s}".format(r.status_code, r.reason))
        except requests.exceptions.RequestException as e:
            logger.error(f"Erro de conexão: {e}")
            
        return None

    def _check_rate_limit(self, time_diff_noauth, time_diff_auth, func):
        # Mantém a lógica original para não quebrar o fluxo da aplicação
        if not self._username:
            return abs(time.time() - self._last_requests[func]) >= time_diff_noauth
        else:
            return abs(time.time() - self._last_requests[func]) >= time_diff_auth

    @staticmethod
    def _check_lat(lat):
        if lat < -90 or lat > 90:
            raise ValueError("Invalid latitude {:f}! Must be in [-90, 90]".format(lat))

    @staticmethod
    def _check_lon(lon):
        if lon < -180 or lon > 180:
            raise ValueError("Invalid longitude {:f}! Must be in [-180, 180]".format(lon))

    def get_states(self, time_secs=0, icao24=None, serials=None, bbox=()):
        if not self._check_rate_limit(10, 5, self.get_states):
            logger.debug("Blocking request due to rate limit")
            return None

        t = time_secs
        if isinstance(time_secs, datetime):
            t = calendar.timegm(t.timetuple())

        params = {"time": int(t), "icao24": icao24}

        if len(bbox) == 4:
            OpenSkyApi._check_lat(bbox[0])
            OpenSkyApi._check_lat(bbox[1])
            OpenSkyApi._check_lon(bbox[2])
            OpenSkyApi._check_lon(bbox[3])
            params.update({"lamin": bbox[0], "lamax": bbox[1], "lomin": bbox[2], "lomax": bbox[3]})
        elif len(bbox) > 0:
            raise ValueError("Invalid bounding box! Must be [min_latitude, max_latitude, min_longitude, max_latitude]")

        states_json = self._get_json("/states/all", self.get_states, params=params)
        return OpenSkyStates(states_json) if states_json else None

    def get_my_states(self, time_secs=0, icao24=None, serials=None):
        if not self._username:
            raise Exception("No username and password provided for get_my_states!")
        
        if not self._check_rate_limit(0, 1, self.get_my_states):
            logger.debug("Blocking request due to rate limit")
            return None
            
        t = time_secs
        if isinstance(time_secs, datetime):
            t = calendar.timegm(t.timetuple())
            
        states_json = self._get_json("/states/own", self.get_my_states,
                                     params={"time": int(t), "icao24": icao24, "serials": serials})
        return OpenSkyStates(states_json) if states_json else None
