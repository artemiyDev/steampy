import json
import logging
import re
import time
import urllib.parse as urlparse
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple, Union

import requests
from requests import Response
from requests.exceptions import RequestException

from steampy.confirmation import ConfirmationExecutor
from steampy.exceptions import ApiException, SevenDaysHoldException, TooManyRequests
from steampy.login import InvalidCredentials, LoginExecutor
from steampy.market import SteamMarket
from steampy.models import DEFAULT_USER_AGENT, Asset, GameOptions, SteamUrl, TradeOfferState
from steampy.utils import (
    account_id_to_steam_id,
    get_description_key,
    get_key_value_from_url,
    login_required,
    merge_items_with_descriptions_from_inventory,
    merge_items_with_descriptions_from_offer,
    merge_items_with_descriptions_from_offers,
    ping_proxy,
    steam_id_to_account_id,
    text_between,
    texts_between,
)

logger = logging.getLogger(__name__)


class SteamClient:
    REQUEST_TIMEOUT_SECONDS = 20
    MAX_JSON_RETRIES = 3
    NETWORK_RETRIES = 3
    RETRY_BACKOFF_SECONDS = 1

    def __init__(
        self,
        api_key: str,
        username: str = None,
        password: str = None,
        steam_id: str = None,
        shared_secret: str = None,
        identity_secret: str = None,
        refresh_token: str = None,
        login_cookies: dict = None,
        proxies: dict = None,
    ) -> None:
        self._api_key = api_key
        self._session = requests.Session()
        self._session.headers.setdefault('User-Agent', DEFAULT_USER_AGENT)
        self._access_token: Optional[str] = None

        if proxies:
            self.set_proxies(proxies)

        self.was_login_executed = False
        self.username = username
        self._password = password
        self._steam_id = steam_id
        self._shared_secret = shared_secret
        self._identity_secret = identity_secret
        self.steam_guard: Dict[str, str] = {}
        self._sync_steam_guard()
        self._refresh_token = refresh_token
        self.market = SteamMarket(self._session)

        if login_cookies:
            self.set_login_cookies(login_cookies)

    def _request(self, method: str, url: str, **kwargs) -> Response:
        kwargs.setdefault('timeout', self.REQUEST_TIMEOUT_SECONDS)
        last_exc = None
        for attempt in range(1, self.NETWORK_RETRIES + 1):
            try:
                return self._session.request(method=method.upper(), url=url, **kwargs)
            except RequestException as exc:
                last_exc = exc
                if attempt == self.NETWORK_RETRIES:
                    break
                wait_seconds = self.RETRY_BACKOFF_SECONDS * attempt
                logger.warning(
                    'Network error for %s %s (attempt %s/%s): %s. Retrying in %ss',
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

    @staticmethod
    def _json_or_raise(response: Response, context: str) -> dict:
        try:
            return response.json()
        except json.JSONDecodeError as exc:
            body_preview = response.text[:300].replace('\n', ' ')
            raise ApiException(f'Failed to decode JSON for {context}. Status: {response.status_code}. Body: {body_preview}') from exc

    def _ensure_webtoken(self) -> None:
        if self._access_token:
            return
        if not self.was_login_executed:
            raise InvalidCredentials('Web token requires authenticated session. Call login() first.')
        raise ApiException('Web token is not available in current session. Re-login and retry.')

    @staticmethod
    def _extract_access_token(cookie_value: str) -> Optional[str]:
        decoded_cookie_value = urlparse.unquote(cookie_value)
        access_token_parts = decoded_cookie_value.split('||')
        if len(access_token_parts) < 2:
            return None
        return access_token_parts[1]

    @staticmethod
    def _extract_steam_id_from_steam_login_secure(cookie_value: str) -> Optional[str]:
        decoded_cookie_value = urlparse.unquote(cookie_value)
        parts = decoded_cookie_value.split('||')
        if not parts:
            return None
        candidate = parts[0].strip()
        return candidate if candidate.isdigit() else None

    def _fetch_steam_id_from_community_page(self) -> str:
        response = self._request('GET', SteamUrl.COMMUNITY_URL)
        steam_id_match = re.search(r'g_steamID = "(\d+)";', response.text)
        if not steam_id_match:
            raise ValueError('Unable to parse steam id from community page')
        return steam_id_match.group(1)

    def _sync_steam_guard(self) -> None:
        updated_guard: Dict[str, str] = {}
        if self._steam_id:
            updated_guard['steamid'] = str(self._steam_id)
        if self._shared_secret:
            updated_guard['shared_secret'] = self._shared_secret
        if self._identity_secret:
            updated_guard['identity_secret'] = self._identity_secret
        self.steam_guard = updated_guard

    def _clear_auth_cookies(self) -> None:
        auth_cookie_names = {'sessionid', 'steamLoginSecure', 'steamRefresh_steam', 'steamCountry', 'steamRememberLogin'}
        cookies_to_clear = [cookie for cookie in self._session.cookies if cookie.name in auth_cookie_names]
        for cookie in cookies_to_clear:
            try:
                self._session.cookies.clear(domain=cookie.domain, path=cookie.path, name=cookie.name)
            except KeyError:
                # If a cookie cannot be removed by exact domain/path, continue and let login overwrite it.
                continue

    def set_proxies(self, proxies: dict) -> dict:
        if not isinstance(proxies, dict):
            raise TypeError(
                'Proxy must be a dict. Example: '
                '{"http": "http://login:password@host:port", "https": "http://login:password@host:port"}'
            )

        if ping_proxy(proxies):
            self._session.proxies.update(proxies)

        return proxies

    def set_login_cookies(self, cookies: dict) -> None:
        self._session.cookies.update(cookies)
        self.was_login_executed = True

        if not self._steam_id:
            steam_login_secure = cookies.get('steamLoginSecure')
            if steam_login_secure:
                self._steam_id = self._extract_steam_id_from_steam_login_secure(steam_login_secure)
            if not self._steam_id:
                self._steam_id = str(self.get_steam_id())
        self._sync_steam_guard()

        self.market._set_login_executed(self.steam_guard, self._get_session_id())

    @login_required
    def get_steam_id(self) -> int:
        return int(self._fetch_steam_id_from_community_page())

    def login(
        self,
        username: str = None,
        password: str = None,
        shared_secret: str = None,
        steam_id: str = None,
        identity_secret: str = None,
    ) -> None:
        if steam_id:
            self._steam_id = str(steam_id)
        if identity_secret:
            self._identity_secret = identity_secret
        if shared_secret:
            self._shared_secret = shared_secret
        self._sync_steam_guard()

        has_client_credentials = all((self.username, self._password, self._shared_secret))
        has_call_credentials = all((username, password, shared_secret))
        has_refresh_token = bool(self._refresh_token)

        if not has_client_credentials and has_call_credentials:
            self.username = username
            self._password = password
            self._shared_secret = shared_secret
            self._sync_steam_guard()
            has_client_credentials = True

        if not has_client_credentials and not has_refresh_token:
            raise InvalidCredentials(
                'You must provide either username/password/shared_secret or a valid refresh_token'
            )

        if self.was_login_executed and self.is_session_alive():
            return

        # Old auth cookies may conflict with refresh/cookie rotation. Start login from a clean auth state.
        self._clear_auth_cookies()
        self._session.cookies.set('steamRememberLogin', 'true')
        login_executor = LoginExecutor(
            self.username,
            self._password,
            self._shared_secret,
            self._session,
            refresh_token=self._refresh_token,
        )
        login_executor.login()
        self._refresh_token = login_executor.refresh_token
        if not self._steam_id:
            steam_login_secure_cookie = next((c for c in self._session.cookies if c.name == 'steamLoginSecure'), None)
            if steam_login_secure_cookie and steam_login_secure_cookie.value:
                self._steam_id = self._extract_steam_id_from_steam_login_secure(steam_login_secure_cookie.value)
            if not self._steam_id:
                self._steam_id = self._fetch_steam_id_from_community_page()
        self._sync_steam_guard()
        self.was_login_executed = True
        self.market._set_login_executed(self.steam_guard, self._get_session_id())

        steam_login_secure_cookie = next((c for c in self._session.cookies if c.name == 'steamLoginSecure'), None)
        self._access_token = None
        if steam_login_secure_cookie and steam_login_secure_cookie.value:
            self._access_token = self._extract_access_token(steam_login_secure_cookie.value)
        if not self._access_token:
            logger.warning(
                'steamLoginSecure/access token is missing after login for user=%s. '
                'API-key mode will still work, webtoken mode may fail.',
                self.username,
            )

    @login_required
    def logout(self) -> None:
        url = f'{SteamUrl.STORE_URL}/login/logout/'
        data = {'sessionid': self._get_session_id()}
        self._request('POST', url, data=data)

        if self.is_session_alive():
            raise ApiException('Logout unsuccessful')

        self.was_login_executed = False
        self._access_token = None

    def __enter__(self):
        self.login(self.username, self._password, self._shared_secret, self._steam_id, self._identity_secret)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logout()

    @login_required
    def is_session_alive(self) -> bool:
        # Account page redirect to login is a reliable signal that session is dead.
        store_account_response = self._request('GET', f'{SteamUrl.STORE_URL}/account/')
        store_url = (getattr(store_account_response, 'url', '') or '').lower()
        if '/login' in store_url:
            return False

        # Community page usually contains g_steamID script variable when authenticated.
        community_response = self._request('GET', SteamUrl.COMMUNITY_URL)
        community_url = (getattr(community_response, 'url', '') or '').lower()
        if '/login' in community_url:
            return False
        if re.search(r'g_steamID = "(\d+)";', community_response.text):
            return True

        if self.username:
            return self.username.lower() in community_response.text.lower()

        return store_account_response.status_code == 200

    def get_refresh_token(self) -> Optional[str]:
        return self._refresh_token

    def get_login_cookies(self) -> Dict[str, str]:
        cookies: Dict[str, str] = {}
        session_id = self._get_cookie_value('sessionid')
        steam_login_secure = self._get_cookie_value('steamLoginSecure')
        if session_id:
            cookies['sessionid'] = session_id
        if steam_login_secure:
            cookies['steamLoginSecure'] = steam_login_secure
        return cookies

    def _get_cookie_value(
        self, cookie_name: str, preferred_domains: Tuple[str, ...] = ('steamcommunity.com', 'store.steampowered.com')
    ) -> Optional[str]:
        for domain in preferred_domains:
            cookie_value = self._session.cookies.get_dict(domain=domain, path='/').get(cookie_name)
            if cookie_value:
                return cookie_value
        for cookie in self._session.cookies:
            if cookie.name == cookie_name and cookie.value:
                return cookie.value
        return None

    def api_call(
        self, method: str, interface: str, api_method: str, version: str, params: dict = None
    ) -> requests.Response:
        request_method = method.upper()
        if request_method not in ('GET', 'POST'):
            raise ValueError('Method must be either GET or POST')

        url = '/'.join((SteamUrl.API_URL, interface, api_method, version))
        response = self._request(
            request_method, url, params=params if request_method == 'GET' else None, data=params if request_method == 'POST' else None
        )

        if response.status_code == 429:
            raise TooManyRequests('Too many requests, try again later.')
        if response.status_code >= 500:
            raise ApiException(f'Steam API server error: {response.status_code}')
        if self.is_invalid_api_key(response):
            raise InvalidCredentials('Invalid API key')

        return response

    @staticmethod
    def is_invalid_api_key(response: requests.Response) -> bool:
        msg = 'Access is denied. Retrying will not help. Please verify your <pre>key=</pre> parameter'
        return msg in response.text

    @login_required
    def get_my_inventory(self, game: GameOptions, merge: bool = True, count: int = 1000) -> dict:
        steam_id = self._steam_id or self.steam_guard.get('steamid')
        if not steam_id:
            steam_id = str(self.get_steam_id())
            self._steam_id = steam_id
            self._sync_steam_guard()
        return self.get_partner_inventory(steam_id, game, merge, count)

    @login_required
    def get_partner_inventory(
        self, partner_steam_id: str, game: GameOptions, merge: bool = True, count: int = 1000
    ) -> dict:
        url = '/'.join((SteamUrl.COMMUNITY_URL, 'inventory', partner_steam_id, game.app_id, game.context_id))
        params = {'l': 'english', 'count': count}

        full_response = self._request('GET', url, params=params)
        if full_response.status_code == 429:
            raise TooManyRequests('Too many requests, try again later.')

        response_dict = self._json_or_raise(full_response, 'get_partner_inventory')
        if response_dict is None or response_dict.get('success') != 1:
            raise ApiException('Success value should be 1.')

        return merge_items_with_descriptions_from_inventory(response_dict, game) if merge else response_dict

    def _get_session_id(self) -> str:
        session_id = self._get_cookie_value('sessionid')
        if not session_id:
            raise ApiException('sessionid cookie is missing')
        return session_id

    def get_trade_offers_summary(self) -> dict:
        params = {'key': self._api_key}
        response = self.api_call('GET', 'IEconService', 'GetTradeOffersSummary', 'v1', params)
        return self._json_or_raise(response, 'get_trade_offers_summary')

    def get_trade_offers(
        self, merge: bool = True, sent: int = 1, received: int = 1, use_webtoken: bool = False
    ) -> dict:
        if use_webtoken:
            self._ensure_webtoken()
            auth_key = 'access_token'
            auth_value = self._access_token
        else:
            auth_key = 'key'
            auth_value = self._api_key

        params = {
            auth_key: auth_value,
            'get_sent_offers': sent,
            'get_received_offers': received,
            'get_descriptions': 1,
            'language': 'english',
            'active_only': 1,
            'historical_only': 0,
            'time_historical_cutoff': '',
        }

        response_data: Optional[Dict[str, Any]] = None
        for attempt in range(1, self.MAX_JSON_RETRIES + 1):
            response = self.api_call('GET', 'IEconService', 'GetTradeOffers', 'v1', params)
            try:
                response_data = response.json()
                break
            except json.JSONDecodeError:
                if attempt == self.MAX_JSON_RETRIES:
                    raise ApiException('Failed to decode GetTradeOffers response after retries')
                wait_seconds = attempt
                logger.warning('GetTradeOffers JSON decode failed (attempt %s). Retrying in %s s.', attempt, wait_seconds)
                time.sleep(wait_seconds)

        response_data = self._filter_non_active_offers(response_data)
        return merge_items_with_descriptions_from_offers(response_data) if merge else response_data

    @staticmethod
    def _filter_non_active_offers(offers_response: dict) -> dict:
        offers_section = offers_response.get('response', {})
        offers_received = offers_section.get('trade_offers_received', [])
        offers_sent = offers_section.get('trade_offers_sent', [])

        offers_section['trade_offers_received'] = [
            offer for offer in offers_received if offer.get('trade_offer_state') == TradeOfferState.Active
        ]
        offers_section['trade_offers_sent'] = [
            offer for offer in offers_sent if offer.get('trade_offer_state') == TradeOfferState.Active
        ]
        offers_response['response'] = offers_section
        return offers_response

    def get_trade_offer(self, trade_offer_id: str, merge: bool = True, use_webtoken: bool = False) -> dict:
        if use_webtoken:
            self._ensure_webtoken()
            auth_key = 'access_token'
            auth_value = self._access_token
        else:
            auth_key = 'key'
            auth_value = self._api_key

        params = {auth_key: auth_value, 'tradeofferid': trade_offer_id, 'language': 'english'}
        response = self.api_call('GET', 'IEconService', 'GetTradeOffer', 'v1', params)
        data = self._json_or_raise(response, 'get_trade_offer')

        if merge and 'descriptions' in data.get('response', {}):
            descriptions = {get_description_key(offer): offer for offer in data['response']['descriptions']}
            offer = data['response']['offer']
            data['response']['offer'] = merge_items_with_descriptions_from_offer(offer, descriptions)

        return data

    def get_trade_history(
        self,
        max_trades: int = 100,
        start_after_time=None,
        start_after_tradeid=None,
        get_descriptions: bool = True,
        navigating_back: bool = True,
        include_failed: bool = True,
        include_total: bool = True,
    ) -> dict:
        params = {
            'key': self._api_key,
            'max_trades': max_trades,
            'start_after_time': start_after_time,
            'start_after_tradeid': start_after_tradeid,
            'get_descriptions': get_descriptions,
            'navigating_back': navigating_back,
            'include_failed': include_failed,
            'include_total': include_total,
        }
        response = self.api_call('GET', 'IEconService', 'GetTradeHistory', 'v1', params)
        return self._json_or_raise(response, 'get_trade_history')

    @login_required
    def get_trade_receipt(self, trade_id: str) -> list:
        response = self._request('GET', f'{SteamUrl.COMMUNITY_URL}/trade/{trade_id}/receipt')
        html = response.content.decode()
        return [json.loads(item) for item in texts_between(html, 'oItem = ', ';\r\n\toItem')]

    @login_required
    def accept_trade_offer(self, trade_offer_id: str) -> dict:
        trade = self.get_trade_offer(trade_offer_id, use_webtoken=bool(self._access_token))
        try:
            trade_offer_state = TradeOfferState(trade['response']['offer']['trade_offer_state'])
        except ValueError as exc:
            raw_state = trade.get('response', {}).get('offer', {}).get('trade_offer_state')
            raise ApiException(f'Unknown trade offer state returned by Steam: {raw_state}') from exc
        if trade_offer_state is not TradeOfferState.Active:
            raise ApiException(f'Invalid trade offer state: {trade_offer_state.name} ({trade_offer_state.value})')

        partner = self._fetch_trade_partner_id(trade_offer_id)
        accept_url = f'{SteamUrl.COMMUNITY_URL}/tradeoffer/{trade_offer_id}/accept'
        params = {
            'sessionid': self._get_session_id(),
            'tradeofferid': trade_offer_id,
            'serverid': '1',
            'partner': partner,
            'captcha': '',
        }
        headers = {'Referer': self._get_trade_offer_url(trade_offer_id)}

        response = self._request('POST', accept_url, data=params, headers=headers)
        response_json = self._json_or_raise(response, 'accept_trade_offer')
        if response_json.get('needs_mobile_confirmation', False):
            return self._confirm_transaction(trade_offer_id)

        return response_json

    def _fetch_trade_partner_id(self, trade_offer_id: str) -> str:
        url = self._get_trade_offer_url(trade_offer_id)
        offer_response_text = self._request('GET', url).text

        if 'You have logged in from a new device. In order to protect the items' in offer_response_text:
            raise SevenDaysHoldException("Account has logged in a new device and can't trade for 7 days")

        return text_between(offer_response_text, "var g_ulTradePartnerSteamID = '", "';")

    def _confirm_transaction(self, trade_offer_id: str) -> dict:
        if not self._identity_secret:
            raise ApiException('identity_secret is required for mobile confirmations')
        steam_id = self._steam_id or self.steam_guard.get('steamid')
        if not steam_id:
            raise ApiException('steam_id is required for mobile confirmations')
        confirmation_executor = ConfirmationExecutor(
            self._identity_secret, steam_id, self._session
        )
        return confirmation_executor.send_trade_allow_request(trade_offer_id)

    def decline_trade_offer(self, trade_offer_id: str) -> dict:
        url = f'{SteamUrl.COMMUNITY_URL}/tradeoffer/{trade_offer_id}/decline'
        response = self._request('POST', url, data={'sessionid': self._get_session_id()})
        return self._json_or_raise(response, 'decline_trade_offer')

    def cancel_trade_offer(self, trade_offer_id: str) -> dict:
        url = f'{SteamUrl.COMMUNITY_URL}/tradeoffer/{trade_offer_id}/cancel'
        response = self._request('POST', url, data={'sessionid': self._get_session_id()})
        return self._json_or_raise(response, 'cancel_trade_offer')

    @login_required
    def make_offer(
        self, items_from_me: List[Asset], items_from_them: List[Asset], partner_steam_id: str, message: str = ''
    ) -> dict:
        offer = self._create_offer_dict(items_from_me, items_from_them)
        url = f'{SteamUrl.COMMUNITY_URL}/tradeoffer/new/send'
        params = {
            'sessionid': self._get_session_id(),
            'serverid': 1,
            'partner': partner_steam_id,
            'tradeoffermessage': message,
            'json_tradeoffer': json.dumps(offer),
            'captcha': '',
            'trade_offer_create_params': '{}',
        }
        partner_account_id = steam_id_to_account_id(partner_steam_id)
        headers = {
            'Referer': f'{SteamUrl.COMMUNITY_URL}/tradeoffer/new/?partner={partner_account_id}',
            'Origin': SteamUrl.COMMUNITY_URL,
        }

        response = self._request('POST', url, data=params, headers=headers)
        response_json = self._json_or_raise(response, 'make_offer')
        if response_json.get('needs_mobile_confirmation'):
            response_json.update(self._confirm_transaction(response_json['tradeofferid']))

        return response_json

    def get_profile(self, steam_id: str) -> dict:
        params = {'steamids': steam_id, 'key': self._api_key}
        response = self.api_call('GET', 'ISteamUser', 'GetPlayerSummaries', 'v0002', params)
        data = self._json_or_raise(response, 'get_profile')
        players = data.get('response', {}).get('players', [])
        if not players:
            raise ApiException(f'No profile found for steam_id={steam_id}')
        return players[0]

    def get_friend_list(self, steam_id: str, relationship_filter: str = 'all') -> list:
        params = {'key': self._api_key, 'steamid': steam_id, 'relationship': relationship_filter}
        response = self.api_call('GET', 'ISteamUser', 'GetFriendList', 'v1', params)
        data = self._json_or_raise(response, 'get_friend_list')
        return data.get('friendslist', {}).get('friends', [])

    @staticmethod
    def _create_offer_dict(items_from_me: List[Asset], items_from_them: List[Asset]) -> dict:
        return {
            'newversion': True,
            'version': 4,
            'me': {'assets': [asset.to_dict() for asset in items_from_me], 'currency': [], 'ready': False},
            'them': {'assets': [asset.to_dict() for asset in items_from_them], 'currency': [], 'ready': False},
        }

    @login_required
    def get_escrow_duration(self, trade_offer_url: str) -> int:
        headers = {
            'Referer': f'{SteamUrl.COMMUNITY_URL}{urlparse.urlparse(trade_offer_url).path}',
            'Origin': SteamUrl.COMMUNITY_URL,
        }
        response = self._request('GET', trade_offer_url, headers=headers).text

        my_escrow_duration = int(text_between(response, 'var g_daysMyEscrow = ', ';'))
        their_escrow_duration = int(text_between(response, 'var g_daysTheirEscrow = ', ';'))

        return max(my_escrow_duration, their_escrow_duration)

    @login_required
    def make_offer_with_url(
        self,
        items_from_me: List[Asset],
        items_from_them: List[Asset],
        trade_offer_url: str,
        message: str = '',
        case_sensitive: bool = True,
    ) -> dict:
        token = get_key_value_from_url(trade_offer_url, 'token', case_sensitive)
        partner_account_id = get_key_value_from_url(trade_offer_url, 'partner', case_sensitive)
        partner_steam_id = account_id_to_steam_id(partner_account_id)
        offer = self._create_offer_dict(items_from_me, items_from_them)
        url = f'{SteamUrl.COMMUNITY_URL}/tradeoffer/new/send'
        trade_offer_create_params = {'trade_offer_access_token': token}
        params = {
            'sessionid': self._get_session_id(),
            'serverid': 1,
            'partner': partner_steam_id,
            'tradeoffermessage': message,
            'json_tradeoffer': json.dumps(offer),
            'captcha': '',
            'trade_offer_create_params': json.dumps(trade_offer_create_params),
        }

        headers = {
            'Referer': f'{SteamUrl.COMMUNITY_URL}{urlparse.urlparse(trade_offer_url).path}',
            'Origin': SteamUrl.COMMUNITY_URL,
        }

        response = self._request('POST', url, data=params, headers=headers)
        response_json = self._json_or_raise(response, 'make_offer_with_url')
        if response_json.get('needs_mobile_confirmation'):
            response_json.update(self._confirm_transaction(response_json['tradeofferid']))

        return response_json

    @staticmethod
    def _get_trade_offer_url(trade_offer_id: str) -> str:
        return f'{SteamUrl.COMMUNITY_URL}/tradeoffer/{trade_offer_id}'

    @login_required
    def get_wallet_balance(self, convert_to_decimal: bool = True, on_hold: bool = False) -> Union[str, Decimal]:
        response = self._request('GET', f'{SteamUrl.COMMUNITY_URL}/market')
        wallet_info_match = re.search(r'var g_rgWalletInfo = (.*?);', response.text)
        if not wallet_info_match:
            raise ApiException('Unable to parse wallet info from market page')

        balance_dict = json.loads(wallet_info_match.group(1))
        balance_dict_key = 'wallet_delayed_balance' if on_hold else 'wallet_balance'
        if balance_dict_key not in balance_dict:
            raise ApiException(f'Wallet key "{balance_dict_key}" is missing in Steam response')

        if convert_to_decimal:
            return Decimal(balance_dict[balance_dict_key]) / 100
        return balance_dict[balance_dict_key]
