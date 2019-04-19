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
import time
from .starling_join_client import StarlingJoinClient
from socket import error as SocketError
from ssl import SSLError
from requests.exceptions import RequestException
from authy.api import AuthyApiClient
from authy import AuthyException
from safeguard.sessions.plugin.logging import get_logger
from safeguard.sessions.plugin.mfa_client import (MFAClient, MFAAuthenticationFailure, MFACommunicationError,
                                                  MFAServiceUnreachable)


logger = get_logger(__name__)


class Client(MFAClient):
    PUSH_REQUEST_TEXT = 'SPS Gateway Authentication'

    def __init__(self, timeout=30, poll_interval=1, push_details=None):
        super().__init__('SPS Starling client')
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.push_details = push_details if push_details is not None else {}

    def otp_authenticate(self, user, otp):
        return self.backend_otp_authenticate(user, otp)

    def push_authenticate(self, user):
        return self.backend_push_authenticate(user)

    def backend_otp_authenticate(self, user_id, otp):
        raise NotImplementedError()

    def backend_push_authenticate(self, user_id):
        raise NotImplementedError()


class AuthyClient(Client):
    API_URL = 'https://api.2fa.cloud.oneidentity.com'

    def __init__(self, api_key, api_url, timeout=30, poll_interval=1, push_details=None):
        super(AuthyClient, self).__init__(timeout=timeout, poll_interval=poll_interval, push_details=push_details)
        self.authy = AuthyApiClient(api_key=api_key, api_uri=api_url)
        logger.info('Client initialized.')

    def backend_otp_authenticate(self, user_id, otp):
        try:
            logger.debug('Looking up user.')
            user = self.authy.users.status(user_id)

            if not user.ok():
                raise MFAAuthenticationFailure(user.errors()['message'])

            logger.info('Account found, running passcode authentication.')
            auth = self.authy.tokens.verify(user_id, otp)

            if not auth.ok():
                raise MFAAuthenticationFailure(auth.errors()['message'])

            logger.info('All is well.')

        except AuthyException as e:
            raise MFACommunicationError(e)

        except (SSLError, SocketError, RequestException) as e:
            raise MFAServiceUnreachable(e)

        return True

    def backend_push_authenticate(self, user_id):
        try:
            logger.debug('Looking up user.')
            user = self.authy.users.status(user_id)

            if not user.ok():
                raise MFAAuthenticationFailure(user.errors()['message'])

            logger.info('Account found, running push authentication.')
            auth = self.authy.one_touch.send_request(int(user_id), message=self.PUSH_REQUEST_TEXT,
                                                     details=self.push_details, seconds_to_expire=self.timeout)

            if not auth.ok():
                raise MFAAuthenticationFailure(auth.errors()['message'])

            logger.debug('Push request sent, polling for response.')

            uuid = auth.get_uuid()
            end_time = time.time() + self.timeout

            while time.time() < end_time:
                status = self.authy.one_touch.get_approval_status(uuid)

                if not status.ok():
                    raise MFAAuthenticationFailure(status.errors()['message'])

                verdict = status.content['approval_request']['status']

                if verdict == 'approved':
                    break
                elif verdict == 'denied':
                    raise MFAAuthenticationFailure('Request denied by user')
                elif verdict == 'expired':
                    raise MFAAuthenticationFailure('Request timeout (server)')
                elif verdict == 'pending':
                    time.sleep(self.poll_interval)
                    continue
            else:
                raise MFAAuthenticationFailure('Request timeout (client)')

            logger.info('All is well.')

        except AuthyException as e:
            raise MFACommunicationError(e)

        except (SSLError, SocketError, RequestException) as e:
            raise MFAServiceUnreachable(e)

        return True


class StarlingClient(Client):
    API_URL = 'https://2faclient{}.cloud.oneidentity.com'

    def __init__(self, environment='prod', timeout=30, poll_interval=1, push_details=None):
        super(StarlingClient, self).__init__(timeout=timeout, poll_interval=poll_interval, push_details=push_details)
        self.headers = {'Authorization': 'Bearer ' + StarlingJoinClient(environment).get_starling_access_token()}
        self.url = self.API_URL.format('' if environment == 'prod' else '-' + environment)

    def backend_otp_authenticate(self, user_id, otp):
        logger.debug("Start OTP verification")
        response = requests.get(
            self.url + '/v1/Users/{userId}/verify'.format(userId=user_id),
            headers=self.headers,
            params={'tokenResponse': otp}
        )

        self._handle_response_error(
            response,
            "Unexpected error during one-time password verification",
            {
                401: "Unauthorized or invalid one-time password",
                404: "User not found",
             },
        )

        logger.info("OTP was correct")
        return True

    def backend_push_authenticate(self, user_id):
        logger.debug("Start push request")
        response = requests.post(
            self.url + '/v1/Users/{userId}/approvalrequests'.format(userId=user_id),
            headers=self.headers,
            json={
                'message': self.PUSH_REQUEST_TEXT,
                'secondsToExpire': self.timeout,
                'details': self.push_details
            }
        )

        self._handle_response_error(
            response,
            "Unexpected error during push request",
            {401: "Unauthorized to make push notification request"}
        )

        id = response.json()['id']
        end_time = time.time() + self.timeout
        while time.time() < end_time:
            response = requests.get(self.url + '/v1/ApprovalRequests/' + id, headers=self.headers)

            self._handle_response_error(
                response,
                "Unexpected error during push request status check",
                {
                    401: "Unauthorized to check approval (push) status",
                    402: "Approval (push) request with this ID not found",
                }
            )

            verdict = response.json()['status']

            if verdict == 'approved':
                break
            elif verdict == 'denied':
                raise MFAAuthenticationFailure('Request denied by user')
            elif verdict == 'expired':
                raise MFAAuthenticationFailure('Request timeout (server)')
            elif verdict == 'pending':
                time.sleep(self.poll_interval)
                continue
        else:
            raise MFAAuthenticationFailure('Request timeout (client)')

        logger.info('Push request was approved')
        return True

    @classmethod
    def _handle_response_error(cls, response, default_message='Unknown error', error_map=None):
        if response.status_code == requests.codes.ok:
            return
        error_map = error_map or {}
        raise MFAAuthenticationFailure('{}, code={}, details={}'.format(
            error_map.get(response.status_code, default_message),
            response.status_code,
            response.text
        ))
