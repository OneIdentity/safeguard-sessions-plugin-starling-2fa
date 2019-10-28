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
from json.decoder import JSONDecodeError
from .starling_join_client import StarlingJoinClient
from safeguard.sessions.plugin.logging import get_logger
from safeguard.sessions.plugin.mfa_client import MFAClient, MFAAuthenticationFailure


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


class StarlingClient(Client):
    API_URL = 'https://2faclient{}.cloud.oneidentity.com'

    def __init__(self, environment='prod', timeout=30, poll_interval=1, push_details=None, cache=None):
        super(StarlingClient, self).__init__(timeout=timeout, poll_interval=poll_interval, push_details=push_details)
        self.__cache = cache
        self.__user_doesnt_exist = None
        self.headers = {'Authorization': 'Bearer ' + StarlingJoinClient(environment).get_starling_access_token(self.__cache)}
        self.url = self.API_URL.format('' if environment == 'prod' else '-' + environment)

    @property
    def user_doesnt_exist(self):
        return self.__user_doesnt_exist

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

    def provision_user(self, phone_number, email_address, display_name):
        logger.debug('Provisioning user with the following details: phone number: {}, email address: {}, display name: {} '.format(
            phone_number, email_address, display_name
        ))
        response = requests.post(self.url + '/v1/Users',
                                 headers=self.headers,
                                 json={
                                    'phone': phone_number,
                                    'email': email_address,
                                    'displayName': display_name
                                 })
        self._handle_response_error(
            response,
            "Unexpected error during user provisioning",
            {
                401: "Unauthorized to provision user",
                400: "User was not valid, check the email address or phone number"
            }
        )
        return response.json()['id']

    def _handle_response_error(self, response, default_message='Unknown error', error_map=None):
        self._set_user_doesnt_exist(response)
        if response.status_code == requests.codes.ok:
            return
        error_map = error_map or {}
        raise MFAAuthenticationFailure('{}, code={}, details={}'.format(
            error_map.get(response.status_code, default_message),
            response.status_code,
            response.text
        ))

    def _set_user_doesnt_exist(self, response):
        try:
            error_message = response.json().get('errorMessage')
            error_code = error_message.get('errorCode')
        except (AttributeError, JSONDecodeError):
            error_code = None
        self.__user_doesnt_exist = error_code == 60016 if error_code else False
