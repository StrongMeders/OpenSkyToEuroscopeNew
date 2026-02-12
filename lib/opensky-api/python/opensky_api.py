#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Official OpenSky Network API client implementation
#
# Author: Markus Fuchs <fuchs@opensky-network.org>
# URL:    http://github.com/openskynetwork/opensky-api
#
# Dependencies: requests (http://docs.python-requests.org/)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
import calendar
import logging
import pprint
import requests

from datetime import datetime
from collections import defaultdict
import time

logger = logging.getLogger('opensky_api')
logger.addHandler(logging.NullHandler())


class StateVector(object):
    """ Represents the state of a vehicle at a particular time. It has the following fields:

      |  **icao24** - ICAO24 address of the transmitter in hex string representation.
      |  **callsign** - callsign of the vehicle. Can be None if no callsign has been received.
      |  **origin_country** - inferred through the ICAO24 address
      |  **time_position** - seconds since epoch of last position report. Can be None if there was no position report received by OpenSky within 15s before.
      |  **last_contact** - seconds since epoch of last received message from this transponder
      |  **longitude** - in ellipsoidal coordinates (WGS-84) and degrees. Can be None
      |  **latitude** - in ellipsoidal coordinates (WGS-84) and degrees. Can be None
      |  **geo_altitude** - geometric altitude in meters. Can be None
      |  **on_ground** - true if aircraft is on ground (sends ADS-B surface position reports).
      |  **velocity** - over ground in m/s. Can be None if information not present
      |  **heading** - in decimal degrees (0 is north). Can be None if information not present.
      |  **vertical_rate** - in m/s, incline is positive, decline negative. Can be None if information not present.
      |  **sensors** - serial numbers of sensors which received messages from the vehicle within the validity period of this state vector. Can be None if no filtering for sensor has been requested.
      |  **baro_altitude** - barometric altitude in meters. Can be None
      |  **squawk** - transponder code aka Squawk. Can be None
      |  **spi** - special purpose indicator
      |  **position_source** - origin of this state's position: 0 = ADS-B, 1 = ASTERIX, 2 = MLAT, 3 = FLARM
    """
    keys = ["icao24", "callsign", "origin_country", "time_position",
            "last_contact", "longitude", "latitude", "baro_altitude", "on_ground",
            "velocity", "heading", "vertical_rate", "sensors",
            "geo_altitude", "squawk", "spi", "position_source"]

    # We are not using namedtuple here as state vectors from the server might be extended; zip() will ignore additional
    #  entries in this case
    def __init__(self, arr):
        """ arr is the array representation of a state vector as received by the API """
        self.__dict__ = dict(zip(StateVector.keys, arr))

    def __repr__(self):
        return "StateVector(%s)" % repr(self.__dict__.values())

    def __str__(self):
        return pprint.pformat(self.__dict__, indent=4)


class OpenSkyApi(object):
    """
    Classe principal da API OpenSky (versão atualizada com OAuth2)
    """

    def __init__(self, username=None, password=None):
        """
        Agora username = client_id
             password = client_secret

        Mantido para compatibilidade com código antigo.
        """

        # Guarda as credenciais OAuth2
        if username and password:
            self.client_id = username
            self.client_secret = password
        else:
            self.client_id = None
            self.client_secret = None

        # Token OAuth
        self._access_token = None
        self._token_expiry = 0  # timestamp de expiração

        self._api_url = "https://opensky-network.org/api"

        # Armazena último request por função
        self._last_requests = defaultdict(lambda: 0)

    # =====================================================
    # BUSCA E CONTROLE DE TOKEN
    # =====================================================

    def _get_token(self):
        """
        Obtém um token OAuth2 válido.
        Reutiliza se ainda não expirou.
        """

        # Se já existe token válido, reutiliza
        if self._access_token and time.time() < self._token_expiry:
            return self._access_token

        # Se não tem credenciais, não pode autenticar
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

            # Tempo de expiração (geralmente 1800s)
            expires = payload.get("expires_in", 1800)

            # Renova 1 min antes de expirar (margem de segurança)
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
        Executa requisição HTTP com OAuth2 automaticamente.
        """

        headers = {}

        # Se houver token, usa autenticação
        token = self._get_token()

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

        # Token expirou → força renovar
        elif r.status_code == 401:

            self._access_token = None

            # Tenta novamente uma vez
            return self._get_json(url_post, callee, params)

        else:
            logger.debug(
                "Response not OK. Status %d - %s",
                r.status_code,
                r.reason
            )

        return None

    # =====================================================
    # RATE LIMIT
    # =====================================================

    def _check_rate_limit(self, time_diff_noauth, time_diff_auth, func):
        """
        Controle de rate-limit local.
        """

        # Verifica se está autenticado via token
        is_auth = bool(self._get_token())

        diff = abs(time.time() - self._last_requests[func])

        if not is_auth:
            # Usuário anônimo
            return diff >= time_diff_noauth
        else:
            # Usuário autenticado
            return diff >= time_diff_auth

    # =====================================================
    # VALIDAÇÃO DE COORDENADAS
    # =====================================================

    @staticmethod
    def _check_lat(lat):
        if lat < -90 or lat > 90:
            raise ValueError(
                "Latitude inválida {:f}! Deve estar entre [-90, 90]".format(lat)
            )

    @staticmethod
    def _check_lon(lon):
        if lon < -180 or lon > 180:
            raise ValueError(
                "Longitude inválida {:f}! Deve estar entre [-180, 180]".format(lon)
            )

    # =====================================================
    # API PRINCIPAL
    # =====================================================

    def get_states(self, time_secs=0, icao24=None, serials=None, bbox=()):
        """
        Obtém estados dos aviões.
        """

        if not self._check_rate_limit(10, 5, self.get_states):
            logger.debug("Bloqueado por rate limit")
            return None

        t = time_secs

        if type(time_secs) == datetime:
            t = calendar.timegm(t.timetuple())

        params = {
            "time": int(t),
            "icao24": icao24
        }

        # Bounding box
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

            raise ValueError(
                "Bounding box inválido! Use: [min_lat, max_lat, min_lon, max_lon]"
            )

        states_json = self._get_json(
            "/states/all",
            self.get_states,
            params=params
        )

        if states_json is not None:
            return OpenSkyStates(states_json)

        return None

    # =====================================================
    # ESTADOS PRÓPRIOS
    # =====================================================

    def get_my_states(self, time_secs=0, icao24=None, serials=None):
        """
        Obtém dados dos próprios sensores.
        Exige autenticação OAuth2.
        """

        # Verifica autenticação
        if not self._get_token():
            raise Exception("Autenticação OAuth2 necessária!")

        if not self._check_rate_limit(0, 1, self.get_my_states):
            logger.debug("Bloqueado por rate limit")
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
