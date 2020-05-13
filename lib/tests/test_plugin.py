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
from pytest import fixture
from unittest.mock import MagicMock
from textwrap import dedent
from ..plugin import Plugin, LDAPInfo

CONFIG = dedent(
    """
    [starling]
    environment=test
"""
)

USER_ID = "user_id"
USER_ID_CACHE_KEY = "user_id_+3601234_abc@def.com"


@fixture
def mocked_client():
    def get_mocked_client(user_id):
        client = MagicMock()
        client.execute_authenticate.return_value = dict(verdict="DENY")
        client.user_doesnt_exist = user_id is None
        client.provision_user = lambda x, y, z: user_id
        return client

    return get_mocked_client


@fixture
def mocked_plugin(mocked_client):
    def get_mocked_plugin(user_id):
        plugin = Plugin(CONFIG)
        plugin.construct_mfa_client = lambda: mocked_client(user_id)
        plugin._query_user_ldap_information = lambda: LDAPInfo(phone="+3601234", email="abc@def.com", name=None)
        return plugin

    return get_mocked_plugin


def test_cache_user_id(mocked_plugin):
    plugin = mocked_plugin(USER_ID)
    expected_cached_value = {"user_id": USER_ID, "is_valid": True}
    assert_cached_user_id(plugin, expected_cached_value)


def test_cache_invalid_user_id_if_user_doesnt_exist(mocked_plugin):
    plugin = mocked_plugin(None)
    expected_cached_value = {"user_id": None, "is_valid": False}
    assert_cached_user_id(plugin, expected_cached_value)


def assert_cached_user_id(plugin, expected_cached_value):
    plugin.authenticate(
        cookie=dict(), session_cookie=dict(), gateway_username="wsmith", key_value_pairs=dict(otp="otp")
    )
    cached = plugin.cache.get(USER_ID_CACHE_KEY)
    assert cached == expected_cached_value


def test_warn_about_non_numeric_mfa_identity(mocked_plugin, caplog):
    plugin = mocked_plugin(USER_ID)
    plugin.authenticate(
        cookie=dict(), session_cookie=dict(), gateway_username="wsmith", key_value_pairs=dict(otp="otp")
    )
    assert "The MFA identity (user_id) does not look like a Starling ID which contains only digits!" in caplog.text


def test_no_warning_for_numeric_mfa_identity(mocked_plugin, caplog):
    plugin = mocked_plugin("12345678")
    plugin.authenticate(
        cookie=dict(), session_cookie=dict(), gateway_username="wsmith", key_value_pairs=dict(otp="otp")
    )
    assert "does not look like a Starling ID" not in caplog.text
