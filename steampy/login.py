from base64 import b64encode
from http import HTTPStatus
import logging
import time
from typing import Dict, Optional

from requests import Response, Session
from requests.exceptions import RequestException
from rsa import PublicKey, encrypt

from steampy import guard
from steampy.exceptions import ApiException, CaptchaRequired, InvalidCredentials
from steampy.models import DEFAULT_USER_AGENT, SteamUrl
from steampy.utils import create_cookie

logger = logging.getLogger(__name__)


class LoginExecutor:
    REQUEST_TIMEOUT_SECONDS = 20
    MAX_RSA_ATTEMPTS = 5
    NETWORK_RETRIES = 3
    RETRY_BACKOFF_SECONDS = 1

    def __init__(
        self, username: str, password: str, shared_secret: str, session: Session, refresh_token: Optional[str] = None
    ) -> None:
        self.username = username
        self.password = password
        self.shared_secret = shared_secret
        self.session = session
        self.session.headers.setdefault('User-Agent', DEFAULT_USER_AGENT)
        self.refresh_token = refresh_token or ''

    def _request(self, method: str, url: str, **kwargs) -> Response:
        kwargs.setdefault('timeout', self.REQUEST_TIMEOUT_SECONDS)
        last_exc = None
        for attempt in range(1, self.NETWORK_RETRIES + 1):
            try:
                return self.session.request(method=method.upper(), url=url, **kwargs)
            except RequestException as exc:
                last_exc = exc
                if attempt == self.NETWORK_RETRIES:
                    break
                wait_seconds = self.RETRY_BACKOFF_SECONDS * attempt
                logger.warning(
                    '%s | Network error for %s %s (attempt %s/%s): %s. Retrying in %ss',
                    self.username,
                    method.upper(),
                    url,
                    attempt,
                    self.NETWORK_RETRIES,
                    exc,
                    wait_seconds,
                )
                time.sleep(wait_seconds)
        raise ApiException(
            f'HTTP request failed after {self.NETWORK_RETRIES} attempts: {method.upper()} {url}. {last_exc}'
        ) from last_exc

    def _api_call(self, method: str, service: str, endpoint: str, version: str = 'v1', params: dict = None) -> Response:
        url = '/'.join((SteamUrl.API_URL, service, endpoint, version))
        headers = {'Referer': f'{SteamUrl.COMMUNITY_URL}/', 'Origin': SteamUrl.COMMUNITY_URL}
        if method.upper() == 'GET':
            return self._request('GET', url, params=params, headers=headers)
        if method.upper() == 'POST':
            return self._request('POST', url, data=params, headers=headers)
        raise ValueError('Method must be either GET or POST')

    @staticmethod
    def _parse_json(response: Response, context: str) -> Dict:
        try:
            return response.json()
        except ValueError as exc:
            preview = response.text[:300].replace('\n', ' ')
            raise ApiException(f'Invalid JSON during {context}. Status: {response.status_code}. Body: {preview}') from exc

    def login(self) -> Session:
        if self.refresh_token and self.refresh_session():
            if self._check_steam_session():
                logger.info('%s | Session restored via refresh token', self.username)
                return self.session
            logger.info('%s | Refresh session check failed, using full login flow', self.username)

        login_response = self._send_login_request()
        login_payload = self._parse_json(login_response, 'BeginAuthSessionViaCredentials')
        if not login_payload.get('response'):
            raise ApiException('No response received from Steam API. Please try again later.')

        self._check_for_captcha(login_payload)
        self._update_steam_guard(login_payload)
        finalized_response = self._finalize_login()
        finalized_payload = self._parse_json(finalized_response, 'jwt/finalizelogin')
        self._perform_redirects(finalized_payload)
        self.set_sessionid_cookies()
        return self.session

    def refresh_session(self) -> bool:
        logger.info('%s | Trying to refresh session with refresh token', self.username)
        try:
            finalized_response = self._finalize_login(use_cookie_sessionid=False)
            finalized_payload = self._parse_json(finalized_response, 'jwt/finalizelogin.refresh')
            self._perform_redirects(finalized_payload)
            self.set_sessionid_cookies()
            self._request('GET', SteamUrl.COMMUNITY_URL)
            self._request('GET', SteamUrl.STORE_URL)
            return True
        except ApiException as exc:
            logger.warning('%s | Session refresh failed: %s', self.username, exc)
            return False

    def _send_login_request(self) -> Response:
        rsa_params = self._fetch_rsa_params()
        encrypted_password = self._encrypt_password(rsa_params)
        request_data = self._prepare_login_request_data(encrypted_password, rsa_params['rsa_timestamp'])
        return self._api_call('POST', 'IAuthenticationService', 'BeginAuthSessionViaCredentials', params=request_data)

    def set_sessionid_cookies(self) -> None:
        community_domain = SteamUrl.COMMUNITY_URL[8:]
        store_domain = SteamUrl.STORE_URL[8:]
        community_cookie_dic = self.session.cookies.get_dict(domain=community_domain)
        store_cookie_dic = self.session.cookies.get_dict(domain=store_domain)

        for name in ('steamLoginSecure', 'sessionid', 'steamRefresh_steam', 'steamCountry'):
            all_cookies = self.session.cookies.get_dict()
            if name not in all_cookies:
                continue

            cookie_value = all_cookies.get(name)
            if cookie_value is None:
                continue
            store_value = store_cookie_dic.get(name, cookie_value)
            community_value = community_cookie_dic.get(name, cookie_value)
            if store_value is None and community_value is None:
                continue
            if store_value is None:
                store_value = community_value
            if community_value is None:
                community_value = store_value

            store_cookie = create_cookie(name, store_value, store_domain)
            community_cookie = create_cookie(name, community_value, community_domain)

            self.session.cookies.set(**community_cookie)
            self.session.cookies.set(**store_cookie)

    def _fetch_rsa_params(self) -> dict:
        request_data = {'account_name': self.username}
        last_status = None

        for _ in range(self.MAX_RSA_ATTEMPTS):
            self._request('GET', SteamUrl.COMMUNITY_URL)
            response = self._api_call('GET', 'IAuthenticationService', 'GetPasswordRSAPublicKey', params=request_data)
            last_status = response.status_code
            payload = self._parse_json(response, 'GetPasswordRSAPublicKey')
            key_data = payload.get('response') or {}
            if all(k in key_data for k in ('publickey_mod', 'publickey_exp', 'timestamp')):
                rsa_mod = int(key_data['publickey_mod'], 16)
                rsa_exp = int(key_data['publickey_exp'], 16)
                return {'rsa_key': PublicKey(rsa_mod, rsa_exp), 'rsa_timestamp': key_data['timestamp']}

        raise ApiException(f'Could not obtain rsa-key. Status code: {last_status}')

    def _encrypt_password(self, rsa_params: dict) -> bytes:
        return b64encode(encrypt(self.password.encode('utf-8'), rsa_params['rsa_key']))

    def _prepare_login_request_data(self, encrypted_password: bytes, rsa_timestamp: str) -> dict:
        return {
            'persistence': '1',
            'encrypted_password': encrypted_password,
            'account_name': self.username,
            'encryption_timestamp': rsa_timestamp,
        }

    @staticmethod
    def _check_for_captcha(login_payload: dict) -> None:
        if login_payload.get('captcha_needed', False):
            raise CaptchaRequired('Captcha required')

    def _perform_redirects(self, response_dict: dict) -> None:
        transfer_info = response_dict.get('transfer_info')
        if not transfer_info:
            raise ApiException('Cannot perform redirects after login, no transfer_info fetched')
        steam_id = response_dict.get('steamID')
        if not steam_id:
            raise ApiException('Cannot perform redirects after login, no steamID fetched')

        for pass_data in transfer_info:
            post_params = dict(pass_data.get('params', {}))
            post_params['steamID'] = steam_id
            self._request('POST', pass_data['url'], data=post_params)

    def _update_steam_guard(self, login_payload: dict) -> None:
        response_data = login_payload['response']
        client_id = response_data['client_id']
        steamid = response_data['steamid']
        request_id = response_data['request_id']
        code = guard.generate_one_time_code(self.shared_secret)

        update_data = {'client_id': client_id, 'steamid': steamid, 'code_type': 3, 'code': code}
        response = self._api_call(
            'POST', 'IAuthenticationService', 'UpdateAuthSessionWithSteamGuardCode', params=update_data
        )
        if response.status_code != HTTPStatus.OK:
            raise ApiException('Cannot update Steam guard')

        self._poll_session_status(client_id, request_id)

    def _poll_session_status(self, client_id: str, request_id: str) -> None:
        poll_data = {'client_id': client_id, 'request_id': request_id}
        response = self._api_call('POST', 'IAuthenticationService', 'PollAuthSessionStatus', params=poll_data)
        payload = self._parse_json(response, 'PollAuthSessionStatus')
        response_data = payload.get('response', {})
        refresh_token = response_data.get('refresh_token')
        if not refresh_token:
            raise InvalidCredentials(f'Steam did not return refresh token during login. Response: {payload}')
        self.refresh_token = refresh_token

    def _check_steam_session(self) -> bool:
        try:
            response = self._request('GET', f'{SteamUrl.STORE_URL}/account/')
        except ApiException:
            return False
        return self.username.lower() in response.text.lower()

    def _finalize_login(self, use_cookie_sessionid: bool = True) -> Response:
        sessionid = ''
        if use_cookie_sessionid:
            sessionid = self.session.cookies.get('sessionid')
            if not sessionid:
                raise ApiException('sessionid cookie is missing before finalizing login')

        redir = f'{SteamUrl.COMMUNITY_URL}/login/home/?goto='
        files = {'nonce': (None, self.refresh_token), 'sessionid': (None, sessionid), 'redir': (None, redir)}
        headers = {'Referer': redir, 'Origin': SteamUrl.COMMUNITY_URL}
        return self._request(
            'POST',
            f'{SteamUrl.LOGIN_URL}/jwt/finalizelogin',
            headers=headers,
            files=files,
        )
