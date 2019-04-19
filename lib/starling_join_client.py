#
#   Copyright (c) 2018-2019 One Identity
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
import json
import os
import requests
import time

from base64 import b64encode
from fcntl import flock, LOCK_EX
from safeguard.sessions.plugin.box_configuration import BoxConfiguration
from safeguard.sessions.plugin.logging import get_logger


STARLING_TOKEN_URL = 'https://sts{}.cloud.oneidentity.com/auth/realms/StarlingClients/protocol/openid-connect/token'
logger = get_logger(__name__)


class StarlingJoinClient(object):
    def __init__(self, environment='prod'):
        self._environment = environment
        self._cache_file_path = os.path.join(os.environ['SCB_PLUGIN_STATE_DIRECTORY'], 'starling_api_key')
        self._starling_join = None

    def get_starling_access_token(self):
        try:
            cache_file = self._open_cache()
        except IOError:
            logger.warning("Could not open/create access token cache {}".format(self._cache_file_path))
            return self._get_api_key()

        try:
            flock(cache_file, LOCK_EX)
            return self._get_cached_api_key(cache_file) or self._create_cached_api_key(cache_file)
        finally:
            cache_file.close()

    def _get_api_key(self):
        return self._request_token()['access_token']

    def _get_cached_api_key(self, cache_file):
        try:
            cache = json.load(cache_file)
        except ValueError:
            logger.warning('Starling access token cache is invalid.')
            return None

        if time.time() < cache['expires']:
            logger.debug('Reusing cached Starling access token.')
            return cache['data']['access_token']

        logger.debug('Cached Starling access token expired.')
        return None

    def _create_cached_api_key(self, cache_file):
        request_time = time.time()
        tokens = self._request_token()
        try:
            cache_file.seek(0)
            json.dump({
                'expires': request_time + tokens['expires_in'],
                'data': tokens,
            }, cache_file)
            logger.debug('Written cache of Starling access token')
        except RuntimeError:
            pass
        return tokens['access_token']

    def _open_cache(self):
        try:
            return open(self._cache_file_path, 'r+')
        except IOError:
            return open(self._cache_file_path, 'w+')

    def _request_token(self):
        url = STARLING_TOKEN_URL.format('' if self._environment.lower() == 'prod' else '-' + self._environment)
        headers = {'Authorization': 'Basic ' + b64encode(self.credential_string.encode()).decode()}
        logger.debug('Requesting Starling access token')
        response = requests.post(url, headers=headers, data={'grant_type': 'client_credentials'})
        if response.status_code != requests.codes.ok:
            raise RuntimeError('Failed to fetch Starling access token on {}'.format(url))
        logger.debug('Starling access token acquired.')
        return response.json()

    @property
    def credential_string(self):
        if self._starling_join is None:
            self._starling_join = {'credential_string': BoxConfiguration.open().get_starling_join_credential_string()}
        if self._starling_join['credential_string'] is None:
            raise RuntimeError("No api_key defined and the node is not joined to Starling either. Aborting.")
        return self._starling_join['credential_string']
