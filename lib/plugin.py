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
from collections import namedtuple
from safeguard.sessions.plugin import AAPlugin, LDAPServer
from safeguard.sessions.plugin.box_configuration import BoxConfiguration
from safeguard.sessions.plugin.plugin_response import AAResponse
from safeguard.sessions.plugin.memory_cache import MemoryCache
from safeguard.sessions.plugin.plugin_base import lazy_property
from .client import StarlingClient

USER_ID_CACHE_KEY_PREFIX = "user_id"


LDAPInfo = namedtuple("LDAPInfo", "phone,email,name")


class Plugin(AAPlugin):
    def __init__(self, configuration, defaults=None, logger=None):
        super().__init__(configuration, defaults, logger)
        self.__cache = MemoryCache.from_config(self.plugin_configuration)

    @property
    def cache(self):
        return self.__cache

    @lazy_property
    def _client(self):
        return self.construct_mfa_client()

    @lazy_property
    def _ldap_user_info(self):
        return self._query_user_ldap_information()

    @lazy_property
    def _user_id_cache_key(self):
        return "_".join([USER_ID_CACHE_KEY_PREFIX, self._ldap_user_info.phone, self._ldap_user_info.email])

    def _authentication_steps(self):
        steps = list(super()._authentication_steps())
        for i, step in enumerate(steps):
            if step.__name__ == "_transform_username":
                steps.insert(i, self._provision_user)
                break
        self.logger.debug("Steps {}".format(steps))
        return iter(steps)

    def do_authenticate(self):
        verdict = self._client.execute_authenticate(self.username, self.mfa_identity, self.mfa_password)
        if verdict.get("verdict") == "DENY" and self._client.user_doesnt_exist:
            ttl = self.plugin_configuration.getint("memory_cache", "ttl", default=3600)
            self.__cache.set(key=self._user_id_cache_key, value={"user_id": None, "is_valid": False}, ttl=ttl)
        return verdict

    def construct_mfa_client(self):
        timeout = self.plugin_configuration.getint("starling", "timeout", 60)
        rest_poll_interval = self.plugin_configuration.getint("starling", "rest_poll_interval", 1)
        push_details = self.create_push_details()
        return StarlingClient(
            environment=self.plugin_configuration.get("starling", "environment", "prod"),
            timeout=timeout,
            poll_interval=rest_poll_interval,
            push_details=push_details,
            cache=self.__cache,
        )

    def create_push_details(self):
        push_details = [
            ("Gateway", BoxConfiguration.open().get_gateway_fqdn()),
            ("Gateway User", self.username),
            ("Server User", self.connection.target_username),
            ("Client IP", self.connection.client_ip or "N/A"),
            ("Protocol", self.connection.protocol or "N/A"),
        ]

        return {k: v for k, v in push_details if v is not None}

    def _provision_user(self):
        if self._ldap_user_info.phone and self._ldap_user_info.email:
            self.logger.debug("Start auto provisioning of user: {}".format(self.username))
            cached_user_info = self.__cache.get(self._user_id_cache_key)
            if cached_user_info:
                if cached_user_info["is_valid"]:
                    self.logger.debug("Using cached user ID: {}".format(cached_user_info["user_id"]))
                    self.mfa_identity = cached_user_info["user_id"]
                    return
                else:
                    reason = "Cached user ID is invalid, try again later; user_id={}".format(
                        cached_user_info["user_id"]
                    )
                    self.logger.warning(reason)
                    return AAResponse.deny(reason=reason)
            user_id = self._client.provision_user(
                self._ldap_user_info.phone, self._ldap_user_info.email, self._ldap_user_info.name
            )
            self.__cache.set(key=self._user_id_cache_key, value={"user_id": user_id, "is_valid": True}, ttl=0)
            self.mfa_identity = user_id or self.mfa_identity

    def _query_user_ldap_information(self):
        phone_attribute = self.plugin_configuration.get("starling_auto_provision", "phone_attribute")
        email_attribute = self.plugin_configuration.get("starling_auto_provision", "email_attribute")
        if phone_attribute and email_attribute:
            name_attribute = "displayName"
            attributes = [phone_attribute, email_attribute, name_attribute]
            ldap_service = LDAPServer.from_config(self.plugin_configuration)
            ldap_info = ldap_service.get_user_string_attributes(self.username, attributes)
            return LDAPInfo(
                self._first_or_none(ldap_info[phone_attribute]),
                self._first_or_none(ldap_info[email_attribute]),
                self._first_or_none(ldap_info[name_attribute]),
            )
        else:
            return LDAPInfo(None, None, None)

    @staticmethod
    def _first_or_none(input_list):
        return next(iter(input_list or []), None)
