from unittest import TestCase
from unittest.mock import MagicMock

from steampy.exceptions import ApiException
from steampy.market import SteamMarket
from steampy.models import Currency, GameOptions


class DummyResponse:
    def __init__(self, status_code=200, json_data=None, text=''):
        self.status_code = status_code
        self._json_data = json_data or {}
        self.text = text

    def json(self):
        return self._json_data


class TestSteamMarketUnit(TestCase):
    def test_create_buy_order_raises_when_failed_without_confirmation(self):
        market = SteamMarket(MagicMock())
        market.was_login_executed = True
        market._session_id = 'sid'
        market._request = MagicMock(return_value=DummyResponse(json_data={'success': 0, 'message': 'failed'}))

        with self.assertRaises(ApiException):
            market.create_buy_order('AK-47', '10.00', 2, GameOptions.CS, Currency.USD)

    def test_buy_item_raises_on_non_success_wallet_info(self):
        market = SteamMarket(MagicMock())
        market.was_login_executed = True
        market._session_id = 'sid'
        market._request = MagicMock(return_value=DummyResponse(json_data={'wallet_info': {'success': 0}}))

        with self.assertRaises(ApiException):
            market.buy_item('AK-47', '1', 100, 10, GameOptions.CS, Currency.USD)
