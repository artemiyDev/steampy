import json
import logging
import random
import time
import urllib.parse
from decimal import Decimal
from http import HTTPStatus

from requests import Response, Session
from requests.exceptions import RequestException

from steampy.confirmation import ConfirmationExecutor
from steampy.exceptions import ApiException, TooManyRequests
from steampy.models import DEFAULT_USER_AGENT, Currency, GameOptions, SteamUrl
from steampy.utils import (
    get_listing_id_to_assets_address_from_html,
    get_market_listings_from_html,
    get_market_sell_listings_from_api,
    login_required,
    merge_items_with_descriptions_from_listing,
    text_between,
)

logger = logging.getLogger(__name__)


class SteamMarket:
    REQUEST_TIMEOUT_SECONDS = 20
    NETWORK_RETRIES = 3
    RETRY_BACKOFF_SECONDS = 1

    def __init__(self, session: Session) -> None:
        self._session = session
        self._session.headers.setdefault('User-Agent', DEFAULT_USER_AGENT)
        self._steam_guard = None
        self._session_id = None
        self.was_login_executed = False

    def _set_login_executed(self, steamguard: dict, session_id: str) -> None:
        self._steam_guard = steamguard
        self._session_id = session_id
        self.was_login_executed = True

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

    def fetch_price(
        self, item_hash_name: str, game: GameOptions, currency: Currency = Currency.USD, country: str = 'US'
    ) -> dict:
        url = f'{SteamUrl.COMMUNITY_URL}/market/priceoverview/'
        params = {
            'country': country,
            'currency': currency.value,
            'appid': game.app_id,
            'market_hash_name': item_hash_name,
        }

        response = self._request('GET', url, params=params)
        if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
            raise TooManyRequests('You can fetch maximum 20 prices in 60s period')

        return self._json_or_raise(response, 'fetch_price')

    @login_required
    def fetch_price_history(self, item_hash_name: str, game: GameOptions, country: str = 'US') -> dict:
        url = f'{SteamUrl.COMMUNITY_URL}/market/pricehistory/'
        params = {'country': country, 'appid': game.app_id, 'market_hash_name': item_hash_name}

        response = self._request('GET', url, params=params)
        if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
            raise TooManyRequests('You can fetch maximum 20 prices in 60s period')

        return self._json_or_raise(response, 'fetch_price_history')

    @login_required
    def get_my_market_listings(self, language: str = 'english') -> dict:
        response = self._request('GET', f'{SteamUrl.COMMUNITY_URL}/market?l={language}')
        if response.status_code != HTTPStatus.OK:
            raise ApiException(f'There was a problem getting the listings. HTTP code: {response.status_code}')

        assets_descriptions = json.loads(text_between(response.text, 'var g_rgAssets = ', ';\n'))
        listing_id_to_assets_address = get_listing_id_to_assets_address_from_html(response.text)
        listings = get_market_listings_from_html(response.text)
        listings = merge_items_with_descriptions_from_listing(
            listings, listing_id_to_assets_address, assets_descriptions
        )

        if '<span id="tabContentsMyActiveMarketListings_end">' in response.text:
            n_showing = int(text_between(response.text, '<span id="tabContentsMyActiveMarketListings_end">', '</span>'))
            n_total = int(
                text_between(response.text, '<span id="tabContentsMyActiveMarketListings_total">', '</span>').replace(
                    ',', ''
                )
            )

            if n_showing < n_total < 1000:
                url = (
                    f'{SteamUrl.COMMUNITY_URL}/market/mylistings/render/'
                    f'?query=&start={n_showing}&count=-1&l={language}'
                )
                response = self._request('GET', url)
                if response.status_code != HTTPStatus.OK:
                    raise ApiException(f'There was a problem getting the listings. HTTP code: {response.status_code}')
                jresp = self._json_or_raise(response, 'get_my_market_listings.render')
                listing_id_to_assets_address = get_listing_id_to_assets_address_from_html(jresp.get('hovers', ''))
                listings_2 = get_market_sell_listings_from_api(jresp.get('results_html', ''))
                listings_2 = merge_items_with_descriptions_from_listing(
                    listings_2, listing_id_to_assets_address, jresp.get('assets', {})
                )
                listings['sell_listings'] = {**listings['sell_listings'], **listings_2['sell_listings']}
            else:
                for i in range(0, n_total, 100):
                    url = (
                        f'{SteamUrl.COMMUNITY_URL}/market/mylistings/'
                        f'?query=&start={n_showing + i}&count=100&l={language}'
                    )
                    response = self._request('GET', url)
                    if response.status_code != HTTPStatus.OK:
                        raise ApiException(f'There was a problem getting the listings. HTTP code: {response.status_code}')
                    jresp = self._json_or_raise(response, 'get_my_market_listings.page')
                    listing_id_to_assets_address = get_listing_id_to_assets_address_from_html(jresp.get('hovers', ''))
                    listings_2 = get_market_sell_listings_from_api(jresp.get('results_html', ''))
                    listings_2 = merge_items_with_descriptions_from_listing(
                        listings_2, listing_id_to_assets_address, jresp.get('assets', {})
                    )
                    listings['sell_listings'] = {**listings['sell_listings'], **listings_2['sell_listings']}

        return listings

    @login_required
    def create_sell_order(self, assetid: str, game: GameOptions, money_to_receive: str) -> dict:
        if not self._steam_guard or not self._steam_guard.get('steamid'):
            raise ApiException('steam_id is required for creating sell orders')

        data = {
            'assetid': assetid,
            'sessionid': self._session_id,
            'contextid': game.context_id,
            'appid': game.app_id,
            'amount': 1,
            'price': money_to_receive,
        }
        headers = {'Referer': f'{SteamUrl.COMMUNITY_URL}/profiles/{self._steam_guard["steamid"]}/inventory'}

        response = self._request('POST', f'{SteamUrl.COMMUNITY_URL}/market/sellitem/', data=data, headers=headers)
        response_json = self._json_or_raise(response, 'create_sell_order')
        has_pending_confirmation = 'pending confirmation' in response_json.get('message', '').lower()
        if response_json.get('needs_mobile_confirmation') or (not response_json.get('success') and has_pending_confirmation):
            return self._confirm_sell_listing(assetid)

        return response_json

    @login_required
    def create_buy_order(
        self,
        market_name: str,
        price_single_item: str,
        quantity: int,
        game: GameOptions,
        currency: Currency = Currency.USD,
    ) -> dict:
        data = {
            'sessionid': self._session_id,
            'currency': currency.value,
            'appid': game.app_id,
            'market_hash_name': market_name,
            'price_total': str(Decimal(price_single_item) * Decimal(quantity)),
            'quantity': quantity,
            'confirmation': 0,
        }
        headers = {
            'Referer': f'{SteamUrl.COMMUNITY_URL}/market/listings/{game.app_id}/{urllib.parse.quote(market_name)}'
        }

        response = self._request('POST', f'{SteamUrl.COMMUNITY_URL}/market/createbuyorder/', data=data, headers=headers)
        response_json = self._json_or_raise(response, 'create_buy_order.initial')
        if response_json.get('success') == 1:
            return response_json

        if not response_json.get('need_confirmation'):
            raise ApiException(f'Order creation failed: {response_json}')

        if not self._steam_guard:
            raise ApiException('Order requires mobile confirmation, but auth secrets are not provided')
        if not self._steam_guard.get('identity_secret'):
            raise ApiException('identity_secret is required for mobile confirmation')
        if not self._steam_guard.get('steamid'):
            raise ApiException('steam_id is required for mobile confirmation')

        confirmation_data = response_json.get('confirmation', {})
        confirmation_id = confirmation_data.get('confirmation_id')
        if not confirmation_id:
            raise ApiException(f'Order requires confirmation but no confirmation_id returned: {response_json}')

        confirmation_executor = ConfirmationExecutor(
            self._steam_guard['identity_secret'],
            self._steam_guard['steamid'],
            self._session,
        )
        time.sleep(random.uniform(1.0, 2.0))
        success = confirmation_executor.confirm_by_id(str(confirmation_id))
        if not success:
            raise ApiException(f'Mobile confirmation failed for confirmation_id={confirmation_id}')

        data['confirmation'] = confirmation_id
        time.sleep(random.uniform(1.0, 2.0))
        second_response = self._request('POST', f'{SteamUrl.COMMUNITY_URL}/market/createbuyorder/', data=data, headers=headers)
        second_response_json = self._json_or_raise(second_response, 'create_buy_order.confirmed')
        if second_response_json.get('success') != 1:
            raise ApiException(f'Order failed after confirmation: {second_response_json}')

        logger.info('Buy order created after mobile confirmation. confirmation_id=%s', confirmation_id)
        return second_response_json

    @login_required
    def buy_item(
        self,
        market_name: str,
        market_id: str,
        price: int,
        fee: int,
        game: GameOptions,
        currency: Currency = Currency.USD,
    ) -> dict:
        data = {
            'sessionid': self._session_id,
            'currency': currency.value,
            'subtotal': price - fee,
            'fee': fee,
            'total': price,
            'quantity': '1',
        }
        headers = {
            'Referer': f'{SteamUrl.COMMUNITY_URL}/market/listings/{game.app_id}/{urllib.parse.quote(market_name)}'
        }
        response = self._request('POST', f'{SteamUrl.COMMUNITY_URL}/market/buylisting/{market_id}', data=data, headers=headers)
        response_json = self._json_or_raise(response, 'buy_item')

        wallet_info = response_json.get('wallet_info', {})
        success = wallet_info.get('success')
        if success != 1:
            raise ApiException(
                f'There was a problem buying this item. success: {success}, message: {response_json.get("message")}'
            )

        return response_json

    @login_required
    def cancel_sell_order(self, sell_listing_id: str) -> None:
        data = {'sessionid': self._session_id}
        headers = {'Referer': f'{SteamUrl.COMMUNITY_URL}/market/'}
        url = f'{SteamUrl.COMMUNITY_URL}/market/removelisting/{sell_listing_id}'

        response = self._request('POST', url, data=data, headers=headers)
        if response.status_code != HTTPStatus.OK:
            raise ApiException(f'There was a problem removing the listing. HTTP code: {response.status_code}')

    @login_required
    def cancel_buy_order(self, buy_order_id: str) -> dict:
        data = {'sessionid': self._session_id, 'buy_orderid': buy_order_id}
        headers = {'Referer': f'{SteamUrl.COMMUNITY_URL}/market'}
        response = self._request('POST', f'{SteamUrl.COMMUNITY_URL}/market/cancelbuyorder/', data=data, headers=headers)
        response_json = self._json_or_raise(response, 'cancel_buy_order')

        if response_json.get('success') != 1:
            raise ApiException(f'There was a problem canceling the order. response: {response_json}')

        return response_json

    def _confirm_sell_listing(self, asset_id: str) -> dict:
        if not self._steam_guard:
            raise ApiException('Auth secrets are required for sell listing confirmation')
        if not self._steam_guard.get('identity_secret'):
            raise ApiException('identity_secret is required for sell listing confirmation')
        if not self._steam_guard.get('steamid'):
            raise ApiException('steam_id is required for sell listing confirmation')

        con_executor = ConfirmationExecutor(
            self._steam_guard['identity_secret'], self._steam_guard['steamid'], self._session
        )
        return con_executor.confirm_sell_listing(asset_id)
