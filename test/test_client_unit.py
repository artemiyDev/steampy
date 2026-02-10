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
    def __init__(self, status_code=200, json_data=None, text=''):
        self.status_code = status_code
        self._json_data = json_data
        self.text = text
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

    def test_login_requires_shared_secret_for_credentials_login(self):
        client = SteamClient('api-key', username='user', password='pass')
        with self.assertRaises(InvalidCredentials):
            client.login()

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

    def test_get_session_id_falls_back_to_store_domain(self):
        client = SteamClient('api-key')
        jar = RequestsCookieJar()
        jar.set('sessionid', 'sid-store', domain='store.steampowered.com', path='/')
        client._session.cookies = jar

        self.assertEqual(client._get_session_id(), 'sid-store')

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
