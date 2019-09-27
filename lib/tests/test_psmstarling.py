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
import pytest
from safeguard.sessions.plugin import AAResponse
from safeguard.sessions.plugin.mfa_client import MFAAuthenticationFailure
from ..plugin import Plugin


@pytest.mark.interactive
def test_otp_ok(client, starling_userid, interactive):
    otp = interactive.askforinput("Please enter OTP generated with Starling mobile application")
    return client.otp_authenticate(starling_userid, otp)


def test_otp_no_user(client):
    with pytest.raises(MFAAuthenticationFailure) as excinfo:
        client.otp_authenticate('unknown', '123456')
    assert 'User doesn\'t exist' in str(excinfo.value)


def test_otp_bad_otp(client, starling_userid):
    with pytest.raises(MFAAuthenticationFailure) as excinfo:
        client.otp_authenticate(starling_userid, '123456')
    assert 'Token is invalid' in str(excinfo.value)


@pytest.mark.interactive
def test_push_ok(client, starling_userid, interactive):
    interactive.message("Please ACCEPT Starling push authentication request")
    return client.push_authenticate(starling_userid)


@pytest.mark.interactive
def test_push_denied(client, starling_userid, interactive):
    interactive.message("Please REJECT Starling push authentication request")
    with pytest.raises(MFAAuthenticationFailure) as excinfo:
        client.push_authenticate(starling_userid)
    assert 'Request denied by user' in str(excinfo.value)


def test_push_timeout(client, starling_userid):
    with pytest.raises(MFAAuthenticationFailure) as excinfo:
        client.timeout = 1
        client.push_authenticate(starling_userid)
    assert 'Request timeout' in str(excinfo.value)


def test_can_provision_user(client, starling_userid, starling_phone_number, starling_email_address, monkeypatch):
    user_id = client.provision_user(starling_phone_number, starling_email_address, '')
    assert starling_userid == user_id


def test_provision_fails_when_phone_number_is_incorrect(client, monkeypatch):
    with pytest.raises(MFAAuthenticationFailure):
        client.provision_user('incorrect_phone_number', 'test_email@acme.com', '')


def test_provision_fails_when_email_address_is_incorrect(client, starling_phone_number, monkeypatch):
    with pytest.raises(MFAAuthenticationFailure):
        client.provision_user(starling_phone_number, 'incorrect_email_address', '')


class DummyPlugin(Plugin):
    def do_authenticate(self):
        return AAResponse.accept().with_cookie({
            'push_details': self.create_push_details()
        })

    def _provision_user(self):
        pass


def test_push_details(gateway_fqdn):
    params = {
        'cookie': {},
        'session_cookie': {},
        'session_id': 'example-1',
        'protocol': 'SSH',
        'connection_name': 'example',
        'client_ip': '1.2.3.4',
        'client_port': 2222,
        'gateway_user': 'wsmith',
        'target_username': 'root',
        'key_value_pairs': {'otp': 'one_time_password'},
    }

    verdict = DummyPlugin('').authenticate(**params)
    assert verdict['cookie']['push_details'] == {
        'Gateway': 'acme.foo.bar',
        'Gateway User': 'wsmith',
        'Server User': 'root',
        'Protocol': 'SSH',
        'Client IP': '1.2.3.4',
    }


def test_push_details_omits_unset_value(gateway_fqdn):
    params = {
        'cookie': {},
        'session_cookie': {},
        'session_id': 'example-1',
        'protocol': 'SSH',
        'connection_name': 'example',
        'client_ip': '1.2.3.4',
        'client_port': 2222,
        'gateway_user': 'wsmith',
        'key_value_pairs': {'otp': 'one_time_password'},
    }

    verdict = DummyPlugin('').authenticate(**params)
    assert verdict['cookie']['push_details'] == {
        'Gateway': 'acme.foo.bar',
        'Gateway User': 'wsmith',
        'Protocol': 'SSH',
        'Client IP': '1.2.3.4',
    }


def test_push_details_fills_expected_parameter_with_NA(gateway_fqdn):
    params = {
        'cookie': {},
        'session_cookie': {},
        'session_id': 'example-1',
        'connection_name': 'example',
        'client_port': 2222,
        'gateway_user': 'wsmith',
        'key_value_pairs': {'otp': 'one_time_password'},
    }

    verdict = DummyPlugin('').authenticate(**params)
    assert verdict['cookie']['push_details'] == {
        'Gateway': 'acme.foo.bar',
        'Gateway User': 'wsmith',
        'Protocol': 'N/A',
        'Client IP': 'N/A',
    }
