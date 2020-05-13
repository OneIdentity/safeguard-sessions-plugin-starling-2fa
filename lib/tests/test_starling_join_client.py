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
from pytest import fixture, raises
from unittest.mock import patch, MagicMock
from safeguard.sessions.plugin.mfa_client import (
    MFAAuthenticationFailure,
    MFACommunicationError,
)
from safeguard.sessions.plugin_impl.box_config import stable_box_configuration
from ..starling_join_client import StarlingJoinClient


@fixture
def mocked_response():
    def get_mocked_response(error_json, status_code=requests.codes.ok):
        response = MagicMock()
        error_json.update({"id": "user_id"})
        response.json.return_value = error_json
        response.status_code = status_code
        return response

    return get_mocked_response


def test_handling_of_not_joined_node():
    client = StarlingJoinClient()
    with raises(MFAAuthenticationFailure) as exc:
        client.get_starling_access_token(cache={})
    assert "The node is not joined to Starling. Aborting." in str(exc.value)


@patch("requests.post")
def test_handling_of_failure_to_fetch_access_token(post, monkeypatch, mocked_response):
    monkeypatch.setitem(stable_box_configuration, "starling_join_credential_string", "secret")
    post.return_value = mocked_response({"errorMessage": "General error"}, 403)
    client = StarlingJoinClient()
    with raises(MFACommunicationError) as exc:
        client.get_starling_access_token(cache={})
    assert "Starling access token request failed" in str(exc.value)
