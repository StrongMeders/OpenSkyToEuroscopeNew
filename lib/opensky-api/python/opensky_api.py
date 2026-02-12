#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# OpenSky Network API - Cliente atualizado com OAuth2
# Baseado na implementação oficial
#
# Adaptado para novo sistema de autenticação (2025+)
# Compatível com código antigo
#
# Autor original: Markus Fuchs
# Adaptação: ChatGPT
#

import calendar
import logging
import pprint
import requests
import time

from datetime import datetime
from collections import defaultdict


# =====================================================
# CONFIGURAÇÃO DE LOG
# =====================================================

logger = logging.getLogger('opensky_api')
logger.addHandler(logging.NullHandler())


# =====================================================
# CLASSE: StateVector
# =====================================================

class StateVector(object):

    keys = [
        "icao24", "callsign", "origin_country", "time_position",
        "last_contact", "longitude", "latitude", "baro_altitude",
        "on_ground", "velocity", "heading", "vertical_rate",
        "sensors", "geo_altitude", "squawk", "spi",
        "position_source"
    ]

    def __init__(self, arr):
        self.__dict__ = dict(zip(StateVector.keys, arr))

    def __repr__(self):
        return "StateVector(%s)" % repr(self.__dict__.values())

    def __str__(self):
        return pprint.pformat(self.__dict__, indent=4)


# =====================================================
# CLASSE: OpenSkyStates
# =====================================================

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


# =====================================================
# CLASSE PRINCIPAL: OpenSkyApi
# =====================================================

class OpenSkyApi(object):

    """
    Cliente principal da API OpenSky (com OAuth2)
    """

    # =====================================================
    # CONSTRUTOR
    # =====================================================

    def __init__(self, username=None, password=None):

        """
        Agora:
        username = client_id
        password = client_secret

        Mantido para compatibilidade.
        """

        if username and password:

            # Credenciais OAuth2
            self.client_id = username
            self.client_secret = password

        else:

            self.client_id = None
            self.client_secret = None

        # Token e validade
        self._access_token = None
        self._token_expiry = 0

        self._api_url = "https://opensky-network.org/api"

        self._last_requests = defaultdict(lambda: 0)


    # =====================================================
    # OBTÉM TOKEN OAUTH2
    # =====================================================

    def _get_token(self):

        """
        Busca token OAuth2 e reutiliza enquanto válido
        """

        # Token ainda válido
        if self._access_token and time.time() < self._token_expiry:
            return self._access_token

        # Sem credenciais → modo anônimo
        if not self.client_id or not self.client_secret:
            return None

        url = "https://auth.opensky-network.org/auth/realms/opensky-network/protocol/openid-connect/token"

        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }

        try:

            r = requests.post(url, data=data, timeout=15)

            if r.status_code != 200:

                logger.error("Erro ao obter token: %s", r.text)
                return None

            payload = r.json()

            self._access_token = payload["access_token"]

            expires = payload.get("expires_in", 1800)

            # Margem de segurança (1 min)
            self._token_expiry = time.time() + expires - 60

            return self._access_token

        except Exception as e:

            logger.error("Falha ao buscar token: %s", str(e))
            return None


    # =====================================================
    # REQUEST BASE
    # =====================================================

    def _get_json(self, url_post, callee, params=None):

        """
        Executa requisição HTTP
        com Bearer Token se disponível
        """

        headers = {}

        token = self._get_token()

        # Se tiver token, autentica
        if token:

            headers["Authorization"] = f"Bearer {token}"

        r = requests.get(
            f"{self._api_url}{url_post}",
            headers=headers,
            params=params,
            timeout=15.0
        )

        # Sucesso
        if r.status_code == 200:

            self._last_requests[callee] = time.time()

            return r.json()

        # Token inválido → renova
        elif r.status_code == 401:

            self._access_token = None

            return self._get_json(url_post, callee, params)

        else:

            logger.debug(
                "Erro HTTP %d - %s",
                r.status_code,
                r.reason
            )

        return None


    # =====================================================
    # RATE LIMIT
    # =====================================================

    def _check_rate_limit(self, time_diff_noauth, time_diff_auth, func):

        """
        Controle local de taxa
        """

        # Está autenticado?
        is_auth = bool(self._get_token())

        diff = abs(time.time() - self._last_requests[func])

        if not is_auth:

            return diff >= time_diff_noauth

        else:

            return diff >= time_diff_auth


    # =====================================================
    # VALIDAÇÃO DE LAT/LON
    # =====================================================

    @staticmethod
    def _check_lat(lat):

        if lat < -90 or lat > 90:

            raise ValueError(
                "Latitude inválida {:f}".format(lat)
            )


    @staticmethod
    def _check_lon(lon):

        if lon < -180 or lon > 180:

            raise ValueError(
                "Longitude inválida {:f}".format(lon)
            )


    # =====================================================
    # GET STATES
    # =====================================================

    def get_states(self, time_secs=0, icao24=None, serials=None, bbox=()):

        """
        Obtém estados das aeronaves
        """

        if not self._check_rate_limit(10, 5, self.get_states):

            logger.debug("Rate limit ativo")
            return None


        t = time_secs

        if type(time_secs) == datetime:

            t = calendar.timegm(t.timetuple())


        params = {
            "time": int(t),
            "icao24": icao24
        }


        if len(bbox) == 4:

            OpenSkyApi._check_lat(bbox[0])
            OpenSkyApi._check_lat(bbox[1])
            OpenSkyApi._check_lon(bbox[2])
            OpenSkyApi._check_lon(bbox[3])

            params["lamin"] = bbox[0]
            params["lamax"] = bbox[1]
            params["lomin"] = bbox[2]
            params["lomax"] = bbox[3]

        elif len(bbox) > 0:

            raise ValueError("Bounding box inválido")


        states_json = self._get_json(
            "/states/all",
            self.get_states,
            params=params
        )


        if states_json is not None:

            return OpenSkyStates(states_json)


        return None


    # =====================================================
    # GET MY STATES
    # =====================================================

    def get_my_states(self, time_secs=0, icao24=None, serials=None):

        """
        Obtém dados dos sensores próprios
        """

        # Exige autenticação
        if not self._get_token():

            raise Exception("Autenticação OAuth2 necessária")


        if not self._check_rate_limit(0, 1, self.get_my_states):

            logger.debug("Rate limit ativo")
            return None


        t = time_secs

        if type(time_secs) == datetime:

            t = calendar.timegm(t.timetuple())


        params = {
            "time": int(t),
            "icao24": icao24,
            "serials": serials
        }


        states_json = self._get_json(
            "/states/own",
            self.get_my_states,
            params=params
        )


        if states_json is not None:

            return OpenSkyStates(states_json)


        return None
