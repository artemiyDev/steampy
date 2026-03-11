import enum
import json
import logging
import re
import time
from datetime import datetime
from http import HTTPStatus
from typing import List

import requests
from bs4 import BeautifulSoup

from steampy import guard
from steampy.exceptions import ConfirmationExpected
from steampy.login import InvalidCredentials
from steampy.models import DEFAULT_USER_AGENT

logger = logging.getLogger(__name__)


class Confirmation:
    def __init__(
        self,
        data_confid: str,
        nonce: str,
        creator_id: str = None,
        conf_type: str = None,
        creation_time: datetime = None,
    ):
        self.data_confid = data_confid
        self.nonce = nonce
        self.creator_id = creator_id
        self.id = str(data_confid)
        self.type = conf_type
        self.creation_time = creation_time
        self.details = None


class Tag(enum.Enum):
    CONF = 'conf'
    GETLIST = 'getlist'
    DETAILS = 'details'
    ALLOW = 'allow'
    CANCEL = 'cancel'


class ConfirmationExecutor:
    CONF_URL = 'https://steamcommunity.com/mobileconf'
    ITEM_INFO_RE = re.compile(r"'confiteminfo', (?P<item_info>.+), UserYou")
    REQUEST_TIMEOUT_SECONDS = 20
    NETWORK_RETRIES = 3
    RETRY_BACKOFF_SECONDS = 1

    def __init__(self, identity_secret: str, my_steam_id: str, session: requests.Session) -> None:
        self._my_steam_id = my_steam_id
        self._identity_secret = identity_secret
        self._session = session
        self._session.headers.setdefault('User-Agent', DEFAULT_USER_AGENT)

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault('timeout', self.REQUEST_TIMEOUT_SECONDS)
        last_exc = None
        for attempt in range(1, self.NETWORK_RETRIES + 1):
            try:
                return self._session.request(method=method.upper(), url=url, **kwargs)
            except requests.RequestException as exc:
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
        raise ConfirmationExpected(f'Network error while requesting confirmations: {last_exc}')

    def send_trade_allow_request(self, trade_offer_id: str) -> dict:
        confirmations = self._get_confirmations()
        confirmation = self._select_trade_offer_confirmation(confirmations, trade_offer_id)
        return self._send_confirmation(confirmation)

    def confirm_sell_listing(self, asset_id: str, app_id: str = None, context_id: str = None) -> dict:
        time.sleep(1)
        confirmations = self._get_confirmations()
        confirmation = self._select_sell_listing_confirmation(confirmations, asset_id, app_id, context_id)
        return self._send_confirmation(confirmation)

    def _send_confirmation(self, confirmation: Confirmation) -> dict:
        tag = Tag.ALLOW
        params = self._create_confirmation_params(tag.value)
        params['op'] = tag.value
        params['cid'] = confirmation.data_confid
        params['ck'] = confirmation.nonce
        headers = {'X-Requested-With': 'XMLHttpRequest'}
        return self._request('GET', f'{self.CONF_URL}/ajaxop', params=params, headers=headers).json()

    def _get_confirmations(self) -> List[Confirmation]:
        last_error = None
        for tag in (Tag.GETLIST.value, Tag.CONF.value):
            try:
                confirmations_json = self._fetch_confirmations_page(tag)
            except ConfirmationExpected as exc:
                last_error = exc
                continue

            confirmations: List[Confirmation] = []
            for conf in confirmations_json.get('conf', []):
                creation_time = None
                if conf.get('creation_time') is not None:
                    creation_time = datetime.fromtimestamp(conf['creation_time'])
                confirmations.append(
                    Confirmation(
                        conf['id'],
                        conf['nonce'],
                        conf.get('creator_id'),
                        conf.get('type'),
                        creation_time,
                    )
                )
            if confirmations or tag == Tag.CONF.value:
                return confirmations

        if last_error is not None:
            raise last_error
        raise ConfirmationExpected('Unable to fetch mobile confirmations')

    def _fetch_confirmations_page(self, tag: str) -> dict:
        params = self._create_confirmation_params(tag)
        response = self._request('GET', f'{self.CONF_URL}/getlist', params=params)
        if 'Steam Guard Mobile Authenticator is providing incorrect Steam Guard codes.' in response.text:
            raise InvalidCredentials('Invalid Steam Guard file')
        if response.status_code != HTTPStatus.OK:
            raise ConfirmationExpected(f'Failed to fetch confirmations. HTTP {response.status_code}')
        try:
            response_json = response.json()
        except ValueError as exc:
            raise ConfirmationExpected('Confirmation list is not valid JSON') from exc
        if response_json.get('needauth'):
            raise ConfirmationExpected('Steam requires renewed mobile confirmation auth')
        if response_json.get('success') not in (None, 1, True):
            raise ConfirmationExpected(response_json.get('message', 'Failed to fetch confirmation list'))
        return response_json

    def _fetch_confirmation_details_page(self, confirmation: Confirmation) -> str:
        tag = f'details{confirmation.data_confid}'
        params = self._create_confirmation_params(tag)
        response = self._request('GET', f'{self.CONF_URL}/details/{confirmation.data_confid}', params=params)
        return response.json()['html']

    def _fetch_confirmation_details(self, confirmation: Confirmation) -> dict:
        html = self._fetch_confirmation_details_page(confirmation)
        match = self.ITEM_INFO_RE.search(html)
        if match is None:
            return {}
        return json.loads(match.group('item_info'))

    def _create_confirmation_params(self, tag_string: str) -> dict:
        timestamp = int(time.time())
        confirmation_key = guard.generate_confirmation_key(self._identity_secret, tag_string, timestamp)
        android_id = guard.generate_device_id(self._my_steam_id)
        return {
            'p': android_id,
            'a': self._my_steam_id,
            'k': confirmation_key,
            't': timestamp,
            'm': 'android',
            'tag': tag_string,
        }

    def _select_trade_offer_confirmation(self, confirmations: List[Confirmation], trade_offer_id: str) -> Confirmation:
        for confirmation in confirmations:
            if str(confirmation.creator_id) == str(trade_offer_id):
                return confirmation
            confirmation_details_page = self._fetch_confirmation_details_page(confirmation)
            confirmation_id = self._get_confirmation_trade_offer_id(confirmation_details_page)
            if confirmation_id == trade_offer_id:
                return confirmation
        raise ConfirmationExpected

    def _select_sell_listing_confirmation(
        self,
        confirmations: List[Confirmation],
        asset_id: str,
        app_id: str = None,
        context_id: str = None,
    ) -> Confirmation:
        for confirmation in confirmations:
            confirmation_details = self._fetch_confirmation_details(confirmation)
            confirmation.details = confirmation_details or None
            if self._details_match_sell_listing(confirmation_details, asset_id, app_id, context_id):
                return confirmation
        raise ConfirmationExpected

    @staticmethod
    def _details_match_sell_listing(details: dict, asset_id: str, app_id: str = None, context_id: str = None) -> bool:
        if not details:
            return False
        if str(details.get('id')) != str(asset_id):
            return False
        if app_id is not None and str(details.get('appid')) != str(app_id):
            return False
        if context_id is not None and str(details.get('contextid')) != str(context_id):
            return False
        return True

    @staticmethod
    def _get_confirmation_trade_offer_id(confirmation_details_page: str) -> str:
        soup = BeautifulSoup(confirmation_details_page, 'html.parser')
        tradeoffers = soup.select('.tradeoffer')
        if not tradeoffers:
            raise ConfirmationExpected('Unable to parse trade offer confirmation details')

        full_offer_id = tradeoffers[0]['id']
        return full_offer_id.split('_')[1]

    def confirm_by_id(self, confirmation_id: str) -> bool:
        confirmations = self._get_confirmations()
        for conf in confirmations:
            logger.debug('mobile confirmation candidate: data_confid=%s creator_id=%s', conf.data_confid, conf.creator_id)
            if str(conf.creator_id) == str(confirmation_id):
                result = self._send_confirmation(conf)
                return bool(result.get('success', False))

        logger.warning('confirmation_id=%s not found among mobile confirmations', confirmation_id)
        return False
