import enum
import json
import logging
import time
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
    def __init__(self, data_confid: str, nonce: str, creator_id: str):
        self.data_confid = data_confid
        self.nonce = nonce
        self.creator_id = creator_id


class Tag(enum.Enum):
    CONF = 'conf'
    DETAILS = 'details'
    ALLOW = 'allow'
    CANCEL = 'cancel'


class ConfirmationExecutor:
    CONF_URL = 'https://steamcommunity.com/mobileconf'
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

    def confirm_sell_listing(self, asset_id: str) -> dict:
        time.sleep(1)
        confirmations = self._get_confirmations()
        confirmation = self._select_sell_listing_confirmation(confirmations, asset_id)
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
        confirmations: List[Confirmation] = []
        confirmations_page = self._fetch_confirmations_page()
        if confirmations_page.status_code != HTTPStatus.OK:
            raise ConfirmationExpected

        confirmations_json = json.loads(confirmations_page.text)
        for conf in confirmations_json.get('conf', []):
            confirmations.append(Confirmation(conf['id'], conf['nonce'], conf['creator_id']))
        return confirmations

    def _fetch_confirmations_page(self) -> requests.Response:
        tag = Tag.CONF.value
        params = self._create_confirmation_params(tag)
        headers = {'X-Requested-With': 'com.valvesoftware.android.steam.community'}
        response = self._request('GET', f'{self.CONF_URL}/getlist', params=params, headers=headers)
        if 'Steam Guard Mobile Authenticator is providing incorrect Steam Guard codes.' in response.text:
            raise InvalidCredentials('Invalid Steam Guard file')
        return response

    def _fetch_confirmation_details_page(self, confirmation: Confirmation) -> str:
        tag = f'details{confirmation.data_confid}'
        params = self._create_confirmation_params(tag)
        response = self._request('GET', f'{self.CONF_URL}/details/{confirmation.data_confid}', params=params)
        return response.json()['html']

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
            confirmation_details_page = self._fetch_confirmation_details_page(confirmation)
            confirmation_id = self._get_confirmation_trade_offer_id(confirmation_details_page)
            if confirmation_id == trade_offer_id:
                return confirmation
        raise ConfirmationExpected

    def _select_sell_listing_confirmation(self, confirmations: List[Confirmation], asset_id: str) -> Confirmation:
        for confirmation in confirmations:
            confirmation_details_page = self._fetch_confirmation_details_page(confirmation)
            confirmation_id = self._get_confirmation_sell_listing_id(confirmation_details_page)
            if confirmation_id == asset_id:
                return confirmation
        raise ConfirmationExpected

    @staticmethod
    def _get_confirmation_sell_listing_id(confirmation_details_page: str) -> str:
        soup = BeautifulSoup(confirmation_details_page, 'html.parser')
        scripts = soup.select('script')
        if len(scripts) < 3 or scripts[2].string is None:
            raise ConfirmationExpected('Unable to parse sell listing confirmation details')

        scr_raw = scripts[2].string.strip()
        scr_raw = scr_raw[scr_raw.index("'confiteminfo', ") + 16 :]
        scr_raw = scr_raw[: scr_raw.index(', UserYou')].replace('\n', '')
        return json.loads(scr_raw)['id']

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
