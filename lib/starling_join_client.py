#
#   Copyright (c) 2018-2020 One Identity
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
import requests

from base64 import b64encode
from safeguard.sessions.plugin.box_configuration import BoxConfiguration
from safeguard.sessions.plugin.logging import get_logger
from safeguard.sessions.plugin.mfa_client import (
    MFAAuthenticationFailure,
    MFACommunicationError,
)


STARLING_TOKEN_URL = "https://sts{}.cloud.oneidentity.com/auth/realms/StarlingClients/protocol/openid-connect/token"
CACHE_KEY = "join_access_token"
logger = get_logger(__name__)


class StarlingJoinClient(object):
    def __init__(self, environment="prod"):
        self._environment = environment
        self._starling_join = None

    def get_starling_access_token(self, cache):
        cached_access_token = cache.get(CACHE_KEY)
        if cached_access_token:
            logger.debug("Reusing cached Starling access token.")
            return cached_access_token
        else:
            return self._get_and_cache_access_token(cache)

    def _get_and_cache_access_token(self, cache):
        tokens = self._request_token()
        access_token = tokens["access_token"]
        cache_ttl = tokens["expires_in"] - 10  # cache should be invalidated a few seconds before the token expires
        logger.debug("Writing cache of Starling access token.")
        cache.set(key=CACHE_KEY, value=access_token, ttl=cache_ttl)
        return access_token

    def _request_token(self):
        url = STARLING_TOKEN_URL.format("" if self._environment.lower() == "prod" else "-" + self._environment)
        logger.debug("Requesting Starling access token on url: {}".format(url))
        headers = {"Authorization": "Basic " + b64encode(self.credential_string.encode()).decode()}
        response = requests.post(url, headers=headers, data={"grant_type": "client_credentials"})
        if response.status_code != requests.codes.ok:
            logger.error(
                "Starling access token request response is not 200: status code={}, text={}".format(
                    response.status_code, response.text
                )
            )
            raise MFACommunicationError("Starling access token request failed")
        logger.debug("Starling access token acquired.")
        return response.json()

    @property
    def credential_string(self):
        if self._starling_join is None:
            self._starling_join = {"credential_string": BoxConfiguration.open().get_starling_join_credential_string()}
        if self._starling_join["credential_string"] is None:
            raise MFAAuthenticationFailure("The node is not joined to Starling. Aborting.")
        return self._starling_join["credential_string"]
