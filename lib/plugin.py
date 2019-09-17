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
from safeguard.sessions.plugin import AAPlugin, LDAPServer
from safeguard.sessions.plugin.box_configuration import BoxConfiguration
from .client import StarlingClient
from safeguard.sessions.plugin.memory_cache import MemoryCache


class Plugin(AAPlugin):

    def _authentication_steps(self):
        steps = list(super()._authentication_steps())
        for i, step in enumerate(steps):
            if step.__name__ == '_transform_username':
                steps.insert(i, self._provision_user)
                break
        self.logger.debug('Steps {}'.format(steps))
        return iter(steps)

    def do_authenticate(self):
        client = self.construct_mfa_client()
        return client.execute_authenticate(self.username, self.mfa_identity, self.mfa_password)

    def construct_mfa_client(self):
        timeout = self.plugin_configuration.getint('starling', 'timeout', 60)
        rest_poll_interval = self.plugin_configuration.getint('starling', 'rest_poll_interval', 1)
        push_details = self.create_push_details()
        return StarlingClient(
            environment=self.plugin_configuration.get('starling', 'environment', 'prod'),
            timeout=timeout,
            poll_interval=rest_poll_interval,
            push_details=push_details,
            cache=MemoryCache.from_config(self.plugin_configuration))

    def create_push_details(self):
        push_details = [
            ('Gateway', BoxConfiguration.open().get_gateway_fqdn()),
            ('Gateway User', self.username),
            ('Server User', self.connection.target_username),
            ('Client IP', self.connection.client_ip or 'N/A'),
            ('Protocol', self.connection.protocol or 'N/A'),
        ]

        return {k: v for k, v in push_details if v is not None}

    def _provision_user(self):
        phone_attribute = self.plugin_configuration.get('starling_auto_provision', 'phone_attribute')
        email_attribute = self.plugin_configuration.get('starling_auto_provision', 'email_attribute')
        name_attribute = 'displayName'
        if phone_attribute and email_attribute:
            self.logger.debug('Start auto provisioning of user: {}'.format(self.username))
            client = self.construct_mfa_client()
            ldap_info = self._query_user_ldap_information((phone_attribute, email_attribute, name_attribute))
            user_id = client.provision_user(ldap_info[phone_attribute],
                                            ldap_info[email_attribute],
                                            ldap_info[name_attribute])
            self.mfa_identity = user_id or self.mfa_identity

    def _query_user_ldap_information(self, required_attributes):
        ldap_service = LDAPServer.from_config(self.plugin_configuration)
        return ldap_service.get_user_string_attributes(self.username, required_attributes)
