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
from safeguard.sessions.plugin.box_configuration import BoxConfiguration
from safeguard.sessions.plugin_impl.box_config import stable_box_configuration
from safeguard.sessions.plugin.memory_cache import MemoryCache
from safeguard.sessions.plugin_impl.memory_cache import MemoryCache as MemoryCacheImpl
from ..client import StarlingClient


@pytest.fixture(scope="module")
def vcr_config():
    return {"filter_headers": ["X-Authy-API-Key"]}


@pytest.fixture
def gateway_fqdn(monkeypatch):
    monkeypatch.setitem(stable_box_configuration, "gateway_fqdn", "acme.foo.bar")
    yield "acme.foo.bar"


@pytest.fixture
def push_details():
    return {
        "Gateway": "some.fqdn",
        "Gateway User": "gwuser",
        "Server User": "serveruser",
        "Client IP": "1.2.3.4",
        "Protocol": "ssh",
    }


@pytest.fixture
def client(monkeypatch, gateway_fqdn, site_parameters, push_details):
    monkeypatch.setitem(
        stable_box_configuration, "starling_join_credential_string", site_parameters["starling_join_credential_string"],
    )
    yield StarlingClient(
        environment=site_parameters["environment"],
        poll_interval=0.1,
        push_details=push_details,
        cache=MemoryCache(MemoryCacheImpl(), prefix="test", ttl=0),
    )


@pytest.fixture
def starling_userid(site_parameters):
    return site_parameters["userid"]


@pytest.fixture
def starling_phone_number(site_parameters):
    return site_parameters["phone_number"]


@pytest.fixture
def starling_email_address(site_parameters):
    return site_parameters["email_address"]
