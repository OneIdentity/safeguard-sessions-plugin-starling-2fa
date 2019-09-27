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
import requests
from pytest import fixture
from unittest.mock import patch, MagicMock
from safeguard.sessions.plugin.mfa_client import MFAAuthenticationFailure
from ..client import StarlingClient


@fixture
def mocked_client():
    cache_mock = MagicMock()
    cache_mock.get.return_value = 'token'
    return StarlingClient(cache=cache_mock)


@fixture
def mocked_response():
    def get_mocked_response(error_json):
        response = MagicMock()
        error_json.update({'id': 'user_id'})
        response.json.return_value = error_json
        response.status_code = requests.codes.ok
        return response
    return get_mocked_response


@patch('requests.post')
def test_user_doesnt_exist_gets_set(post, mocked_client, mocked_response):
    response = mocked_response({'errorMessage': {'errorCode': 60016}})
    post.return_value = response
    mocked_client.provision_user('phone', 'email', 'name')
    assert mocked_client.user_doesnt_exist


@patch('requests.post')
def test_user_doesnt_exist_gets_set_on_general_error(post, mocked_client, mocked_response):
    response = mocked_response({'errorMessage': 'General error'})
    post.return_value = response
    mocked_client.provision_user('phone', 'email', 'name')
    assert not mocked_client.user_doesnt_exist
