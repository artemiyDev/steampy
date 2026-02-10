import json
from unittest import TestCase
from unittest.mock import MagicMock, patch

from requests.cookies import RequestsCookieJar
from requests.exceptions import RequestException

from steampy.client import SteamClient
from steampy.exceptions import ApiException
from steampy.login import InvalidCredentials
from steampy.models import TradeOfferState


class DummyResponse:
    def __init__(self, status_code=200, json_data=None, text='', url=''):
        self.status_code = status_code
        self._json_data = json_data
        self.text = text
        self.url = url
        self.content = text.encode('utf-8')

    def json(self):
        if isinstance(self._json_data, Exception):
            raise self._json_data
        return self._json_data


class TestSteamClientUnit(TestCase):
    def test_set_login_cookies_uses_constructor_steam_id(self):
        with patch.object(SteamClient, 'get_steam_id', side_effect=AssertionError('should not be called')):
            client = SteamClient(
                'api-key',
                steam_id='76561198000000000',
                login_cookies={'sessionid': 'sid', 'steamLoginSecure': 'x'},
            )
        self.assertEqual(client.steam_guard['steamid'], '76561198000000000')

    def test_set_login_cookies_extracts_steam_id_from_steam_login_secure(self):
        with patch.object(SteamClient, 'get_steam_id', side_effect=AssertionError('should not be called')):
            client = SteamClient(
                'api-key',
                login_cookies={'sessionid': 'sid', 'steamLoginSecure': '76561198012345678%7C%7Cjwt-token'},
            )
        self.assertEqual(client.steam_guard['steamid'], '76561198012345678')

    def test_set_login_cookies_sets_auth_cookies_for_both_domains(self):
        with patch.object(SteamClient, 'get_steam_id', side_effect=AssertionError('should not be called')):
            client = SteamClient(
                'api-key',
                login_cookies={'sessionid': 'sid', 'steamLoginSecure': '76561198012345678%7C%7Cjwt-token'},
            )

        community_cookies = client._session.cookies.get_dict(domain='steamcommunity.com', path='/')
        store_cookies = client._session.cookies.get_dict(domain='store.steampowered.com', path='/')

        self.assertEqual(community_cookies.get('sessionid'), 'sid')
        self.assertEqual(store_cookies.get('sessionid'), 'sid')
        self.assertEqual(community_cookies.get('steamLoginSecure'), '76561198012345678%7C%7Cjwt-token')
        self.assertEqual(store_cookies.get('steamLoginSecure'), '76561198012345678%7C%7Cjwt-token')

    def test_set_login_cookies_accepts_jsonable_cookie_list(self):
        jsonable_cookies = [
            {
                'name': 'sessionid',
                'value': 'sid-community',
                'domain': 'steamcommunity.com',
                'path': '/',
                'expires': None,
                'secure': True,
                'discard': False,
                'rest': {},
            },
            {
                'name': 'sessionid',
                'value': 'sid-store',
                'domain': 'store.steampowered.com',
                'path': '/',
                'expires': None,
                'secure': True,
                'discard': False,
                'rest': {},
            },
            {
                'name': 'steamLoginSecure',
                'value': '76561198012345678%7C%7Cjwt-token',
                'domain': 'steamcommunity.com',
                'path': '/',
                'expires': None,
                'secure': True,
                'discard': False,
                'rest': {'HttpOnly': None},
            },
            {
                'name': 'steamLoginSecure',
                'value': '76561198012345678%7C%7Cjwt-token',
                'domain': 'store.steampowered.com',
                'path': '/',
                'expires': None,
                'secure': True,
                'discard': False,
                'rest': {'HttpOnly': None},
            },
        ]

        with patch.object(SteamClient, 'get_steam_id', side_effect=AssertionError('should not be called')):
            client = SteamClient('api-key', login_cookies=jsonable_cookies)

        self.assertTrue(client.was_login_executed)
        self.assertEqual(client.steam_guard['steamid'], '76561198012345678')
        self.assertEqual(client._session.cookies.get_dict(domain='steamcommunity.com', path='/').get('sessionid'), 'sid-community')
        self.assertEqual(client._session.cookies.get_dict(domain='store.steampowered.com', path='/').get('sessionid'), 'sid-store')

    def test_login_requires_shared_secret_for_credentials_login(self):
        client = SteamClient('api-key', username='user', password='pass')
        with self.assertRaises(InvalidCredentials):
            client.login()

    @patch('steampy.client.LoginExecutor')
    def test_login_allows_refresh_token_only_mode(self, mocked_login_executor_cls):
        client = SteamClient('api-key', refresh_token='refresh-token')

        mocked_executor = mocked_login_executor_cls.return_value
        mocked_executor.refresh_token = 'refresh-token-2'
        mocked_executor.login = MagicMock(
            side_effect=lambda: client._session.cookies.set('sessionid', 'sid-new', domain='steamcommunity.com', path='/')
        )
        client._fetch_steam_id_from_community_page = MagicMock(return_value='76561198012345678')

        client.login()

        self.assertTrue(client.was_login_executed)
        self.assertEqual(client.get_refresh_token(), 'refresh-token-2')
        self.assertEqual(client.steam_guard['steamid'], '76561198012345678')
        mocked_executor.login.assert_called_once()

    @patch('steampy.client.LoginExecutor')
    def test_login_checks_cookies_before_refresh_executor(self, mocked_login_executor_cls):
        client = SteamClient(
            'api-key',
            refresh_token='refresh-token',
            login_cookies={'sessionid': 'sid', 'steamLoginSecure': '76561198012345678%7C%7Cjwt-token'},
        )
        events = []

        mocked_executor = mocked_login_executor_cls.return_value
        mocked_executor.refresh_token = 'refresh-token-2'
        mocked_executor.login = MagicMock(side_effect=lambda: events.append('executor_login'))
        client.is_session_alive = MagicMock(side_effect=lambda: events.append('cookies_check') or False)

        client.login()

        self.assertEqual(events, ['cookies_check', 'executor_login'])
        mocked_executor.login.assert_called_once()

    @patch('steampy.client.LoginExecutor')
    def test_login_skips_refresh_and_credentials_when_cookies_alive(self, mocked_login_executor_cls):
        client = SteamClient(
            'api-key',
            refresh_token='refresh-token',
            login_cookies={'sessionid': 'sid', 'steamLoginSecure': '76561198012345678%7C%7Cjwt-token'},
        )
        client.is_session_alive = MagicMock(return_value=True)

        client.login()

        mocked_login_executor_cls.assert_not_called()

    @patch('steampy.client.LoginExecutor')
    def test_login_continues_to_refresh_when_cookie_check_raises(self, mocked_login_executor_cls):
        client = SteamClient(
            'api-key',
            username='user',
            password='pass',
            shared_secret='secret',
            login_cookies={'sessionid': 'sid', 'steamLoginSecure': '76561198012345678%7C%7Cjwt-token'},
        )

        mocked_executor = mocked_login_executor_cls.return_value
        mocked_executor.refresh_token = None
        mocked_executor.login = MagicMock()
        client.is_session_alive = MagicMock(side_effect=ApiException('cookie check failed'))

        client.login()

        mocked_executor.login.assert_called_once()

    def test_filter_non_active_offers_keeps_only_active(self):
        payload = {
            'response': {
                'trade_offers_received': [
                    {'trade_offer_state': TradeOfferState.Active},
                    {'trade_offer_state': TradeOfferState.Canceled},
                ],
                'trade_offers_sent': [
                    {'trade_offer_state': TradeOfferState.Accepted},
                    {'trade_offer_state': TradeOfferState.Active},
                ],
            }
        }

        result = SteamClient._filter_non_active_offers(payload)

        self.assertEqual(len(result['response']['trade_offers_received']), 1)
        self.assertEqual(len(result['response']['trade_offers_sent']), 1)

    def test_get_trade_offers_raises_after_json_retries(self):
        client = SteamClient('api-key')
        client.MAX_JSON_RETRIES = 2
        client.api_call = MagicMock(return_value=DummyResponse(json_data=json.JSONDecodeError('bad', 'doc', 0)))

        with patch('steampy.client.time.sleep'):
            with self.assertRaises(ApiException):
                client.get_trade_offers()

    def test_get_trade_offer_requires_webtoken_when_enabled(self):
        client = SteamClient('api-key')
        with self.assertRaises(InvalidCredentials):
            client.get_trade_offer('123', use_webtoken=True)

    def test_get_session_id_raises_when_missing(self):
        client = SteamClient('api-key')
        client._session.cookies = RequestsCookieJar()

        with self.assertRaises(ApiException):
            client._get_session_id()

    def test_get_login_cookies_returns_expected_dict(self):
        client = SteamClient('api-key')
        jar = RequestsCookieJar()
        jar.set('sessionid', 'sid-community', domain='steamcommunity.com', path='/')
        jar.set('sessionid', 'sid-store', domain='store.steampowered.com', path='/')
        jar.set('steamLoginSecure', 'login-secure-token', domain='store.steampowered.com', path='/')
        client._session.cookies = jar

        self.assertEqual(
            client.get_login_cookies(),
            {'sessionid': 'sid-community', 'steamLoginSecure': 'login-secure-token'},
        )

    def test_get_login_cookies_prefers_store_for_steam_login_secure(self):
        client = SteamClient('api-key')
        jar = RequestsCookieJar()
        jar.set('sessionid', 'sid-community', domain='steamcommunity.com', path='/')
        jar.set('steamLoginSecure', 'community-token', domain='steamcommunity.com', path='/')
        jar.set('steamLoginSecure', 'store-token', domain='store.steampowered.com', path='/')
        client._session.cookies = jar

        self.assertEqual(
            client.get_login_cookies(),
            {'sessionid': 'sid-community', 'steamLoginSecure': 'store-token'},
        )

    def test_get_and_set_jsonable_cookies_round_trip(self):
        with patch.object(SteamClient, 'get_steam_id', side_effect=AssertionError('should not be called')):
            source_client = SteamClient(
                'api-key',
                login_cookies={'sessionid': 'sid', 'steamLoginSecure': '76561198012345678%7C%7Cjwt-token'},
            )
        source_client._session.cookies.set('timezoneOffset', '10800,0', domain='steamcommunity.com', path='/')

        dumped_cookies = source_client.get_jsonable_cookies()
        self.assertTrue(any(cookie['name'] == 'sessionid' and cookie['domain'] == 'steamcommunity.com' for cookie in dumped_cookies))
        self.assertTrue(any(cookie['name'] == 'timezoneOffset' for cookie in dumped_cookies))

        with patch.object(SteamClient, 'get_steam_id', side_effect=AssertionError('should not be called')):
            restored_client = SteamClient('api-key')
            restored_client.set_jsonable_cookies(dumped_cookies)

        self.assertEqual(
            restored_client._session.cookies.get_dict(domain='steamcommunity.com', path='/').get('sessionid'),
            'sid',
        )
        self.assertEqual(
            restored_client._session.cookies.get_dict(domain='steamcommunity.com', path='/').get('timezoneOffset'),
            '10800,0',
        )
        self.assertEqual(
            restored_client.get_login_cookies(),
            {'sessionid': 'sid', 'steamLoginSecure': '76561198012345678%7C%7Cjwt-token'},
        )

    def test_set_jsonable_cookies_raises_for_non_list(self):
        client = SteamClient('api-key')

        with self.assertRaises(TypeError):
            client.set_jsonable_cookies({'sessionid': 'sid'})

    def test_get_session_id_falls_back_to_store_domain(self):
        client = SteamClient('api-key')
        jar = RequestsCookieJar()
        jar.set('sessionid', 'sid-store', domain='store.steampowered.com', path='/')
        client._session.cookies = jar

        self.assertEqual(client._get_session_id(), 'sid-store')

    def test_get_session_id_with_duplicate_name_uses_community_cookie(self):
        client = SteamClient('api-key')
        jar = RequestsCookieJar()
        jar.set('sessionid', 'sid-community', domain='steamcommunity.com', path='/')
        jar.set('sessionid', 'sid-store', domain='store.steampowered.com', path='/')
        client._session.cookies = jar

        self.assertEqual(client._get_session_id(), 'sid-community')

    def test_extract_access_token_returns_none_for_invalid_cookie(self):
        self.assertIsNone(SteamClient._extract_access_token('invalid-cookie'))

    def test_accept_trade_offer_raises_api_exception_for_unknown_state(self):
        client = SteamClient('api-key')
        client.was_login_executed = True
        client.username = 'user'
        client._access_token = None
        client.get_trade_offer = MagicMock(return_value={'response': {'offer': {'trade_offer_state': 999}}})

        with self.assertRaises(ApiException):
            client.accept_trade_offer('123')

    def test_request_retries_network_errors_then_succeeds(self):
        client = SteamClient('api-key')
        expected_response = DummyResponse(status_code=200, json_data={'ok': 1})
        client._session.request = MagicMock(
            side_effect=[RequestException('proxy down'), RequestException('connector error'), expected_response]
        )

        with patch('steampy.client.time.sleep'):
            response = client._request('GET', 'https://example.com')

        self.assertIs(response, expected_response)
        self.assertEqual(client._session.request.call_count, 3)

    def test_clear_auth_cookies_removes_steam_auth_entries(self):
        client = SteamClient('api-key')
        client._session.cookies.set('sessionid', 'sid1', domain='steamcommunity.com', path='/')
        client._session.cookies.set('steamLoginSecure', 'token', domain='steamcommunity.com', path='/')
        client._session.cookies.set('some_other_cookie', 'value', domain='steamcommunity.com', path='/')

        client._clear_auth_cookies()

        self.assertNotIn('sessionid', client._session.cookies.get_dict(domain='steamcommunity.com', path='/'))
        self.assertNotIn('steamLoginSecure', client._session.cookies.get_dict(domain='steamcommunity.com', path='/'))
        self.assertIn('some_other_cookie', client._session.cookies.get_dict(domain='steamcommunity.com', path='/'))

    def test_is_session_alive_true_without_username_by_steamid_marker(self):
        client = SteamClient('api-key')
        client.was_login_executed = True
        client._request = MagicMock(
            side_effect=[
                DummyResponse(status_code=200, text='account page', url='https://store.steampowered.com/account/'),
                DummyResponse(
                    status_code=200,
                    text='var g_steamID = "76561198012345678";',
                    url='https://steamcommunity.com/',
                ),
            ]
        )

        self.assertTrue(client.is_session_alive())

    def test_is_session_alive_false_on_store_login_redirect(self):
        client = SteamClient('api-key')
        client.was_login_executed = True
        client._request = MagicMock(
            return_value=DummyResponse(status_code=200, text='login page', url='https://store.steampowered.com/login/')
        )

        self.assertFalse(client.is_session_alive())
