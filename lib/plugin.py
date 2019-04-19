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
from safeguard.sessions.plugin import AAPlugin
from safeguard.sessions.plugin.box_configuration import BoxConfiguration
from .client import AuthyClient, StarlingClient


class Plugin(AAPlugin):
    def do_authenticate(self):
        client = self.construct_mfa_client()
        return client.execute_authenticate(self.username, self.mfa_identity, self.mfa_password)

    def construct_mfa_client(self):
        api_key = self.plugin_configuration.get('starling', 'api_key')
        timeout = self.plugin_configuration.getint('starling', 'timeout', 60)
        rest_poll_interval = self.plugin_configuration.getint('starling', 'rest_poll_interval', 1)
        push_details = self.create_push_details()

        if api_key:
            return AuthyClient(api_key=api_key,
                               api_url=self.plugin_configuration.get('starling', 'api_url', default=AuthyClient.API_URL),
                               timeout=timeout,
                               poll_interval=rest_poll_interval,
                               push_details=push_details)
        else:
            return StarlingClient(
                environment=self.plugin_configuration.get('starling', 'environment', 'prod'),
                timeout=timeout,
                poll_interval=rest_poll_interval,
                push_details=push_details)

    def create_push_details(self):
        push_details = [
            ('Gateway', BoxConfiguration.open().get_gateway_fqdn()),
            ('Gateway User', self.username),
            ('Server User', self.connection.target_username),
            ('Client IP', self.connection.client_ip or 'N/A'),
            ('Protocol', self.connection.protocol or 'N/A'),
        ]

        return {k: v for k, v in push_details if v is not None}
