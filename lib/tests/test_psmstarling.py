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
from authy import AuthyException
from requests import RequestException
from safeguard.sessions.plugin import AAResponse
from safeguard.sessions.plugin.mfa_client import MFAAuthenticationFailure, MFACommunicationError, MFAServiceUnreachable
from unittest.mock import MagicMock, Mock
from ..plugin import Plugin


@pytest.fixture
def inject_authy_connection_error(monkeypatch):
    request_mock = MagicMock()
    monkeypatch.setattr("authy.api.resources.Resource.request", request_mock)
    request_mock.side_effect = RequestException("injected connection error")

@pytest.fixture
def inject_authy_onetouch_failure(monkeypatch):
    request_mock = MagicMock()
    monkeypatch.setattr("authy.api.resources.OneTouch.send_request", request_mock)
    request_mock.return_value = Mock(ok=Mock(return_value=False), errors=Mock(return_value={'message': ''}))


@pytest.fixture
def inject_authy_onetiuch_approval_failure(monkeypatch):
    request_mock = MagicMock()
    monkeypatch.setattr("authy.api.resources.OneTouch.get_approval_status", request_mock)
    request_mock.return_value = Mock(ok=Mock(return_value=False), errors=Mock(return_value={'message': ''}))


@pytest.fixture
def inject_authy_onetouch_exception(monkeypatch):
    request_mock = MagicMock()
    monkeypatch.setattr("authy.api.resources.OneTouch.send_request", request_mock)
    request_mock.side_effect = AuthyException('Push called')


@pytest.mark.parametrize('client', ['authy', 'starling'], indirect=True)
@pytest.mark.interactive
def test_otp_ok(client, starling_userid, interactive):
    otp = interactive.askforinput("Please enter OTP generated with Starling mobile application")
    return client.otp_authenticate(starling_userid, otp)


@pytest.mark.parametrize('client', ['authy', 'starling'], indirect=True)
def test_otp_no_user(client):
    with pytest.raises(MFAAuthenticationFailure) as excinfo:
        client.otp_authenticate('unknown', '123456')
    assert 'User not found' in str(excinfo) or 'User doesn\'t exist' in str(excinfo)


@pytest.mark.parametrize('client', ['authy', 'starling'], indirect=True)
def test_otp_bad_otp(client, starling_userid):
    with pytest.raises(MFAAuthenticationFailure) as excinfo:
        client.otp_authenticate(starling_userid, '123456')
    assert 'Token is invalid' in str(excinfo)


# Authy specific error
@pytest.mark.parametrize('client', ['authy'], indirect=True)
def test_otp_conn_error(client, starling_userid, inject_authy_connection_error):
    with pytest.raises(MFAServiceUnreachable):
        client.otp_authenticate(starling_userid, '123456')


# Not applicable to Starling, it gives invalid token
@pytest.mark.parametrize('client', ['authy'], indirect=True)
def test_otp_invalid_format(client, starling_userid):
    with pytest.raises(MFACommunicationError, match='Unexpected length'):
        client.otp_authenticate(starling_userid, '123')


# Gives 500, internal server error on Starling!
@pytest.mark.parametrize('client', ['authy'], indirect=True)
def test_push_no_user(client):
    with pytest.raises(MFAAuthenticationFailure) as excinfo:
        client.push_authenticate('unkown')
    assert 'User not found' in str(excinfo)


@pytest.mark.parametrize('client', ['authy', 'starling'], indirect=True)
@pytest.mark.interactive
def test_push_ok(client, starling_userid, interactive):
    interactive.message("Please ACCEPT Starling push authentication request")
    return client.push_authenticate(starling_userid)


@pytest.mark.parametrize('client', ['authy', 'starling'], indirect=True)
@pytest.mark.interactive
def test_push_denied(client, starling_userid, interactive):
    interactive.message("Please REJECT Starling push authentication request")
    with pytest.raises(MFAAuthenticationFailure) as excinfo:
        client.push_authenticate(starling_userid)
    assert 'Request denied by user' in str(excinfo)


@pytest.mark.parametrize('client', ['authy', 'starling'], indirect=True)
def test_push_timeout(client, starling_userid):
    with pytest.raises(MFAAuthenticationFailure) as excinfo:
        client.timeout = 1
        client.push_authenticate(starling_userid)
    assert 'Request timeout' in str(excinfo)


# Authy specific error
@pytest.mark.parametrize('client', ['authy'], indirect=True)
def test_push_exception(client, starling_userid, inject_authy_onetouch_exception):
    with pytest.raises(MFACommunicationError, match='Push called'):
        client.push_authenticate(starling_userid)


# Authy specific error
@pytest.mark.parametrize('client', ['authy'], indirect=True)
def test_push_request_exception(client, starling_userid, inject_authy_onetouch_failure):
    with pytest.raises(MFAAuthenticationFailure):
        client.push_authenticate(starling_userid)


# Authy specific error
@pytest.mark.parametrize('client', ['authy'], indirect=True)
def test_push_status_exception(client, starling_userid, inject_authy_onetiuch_approval_failure):
    with pytest.raises(MFAAuthenticationFailure):
        client.push_authenticate(starling_userid)


# Authy specific error
@pytest.mark.parametrize('client', ['authy'], indirect=True)
def test_push_conn_error(client, starling_userid, inject_authy_connection_error):
    with pytest.raises(MFAServiceUnreachable):
        client.push_authenticate(starling_userid)


class DummyPlugin(Plugin):
    def do_authenticate(self):
        return AAResponse.accept().with_cookie({
            'push_details': self.create_push_details()
        })


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
