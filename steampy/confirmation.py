import enum
import json
import time
from typing import List
from http import HTTPStatus

import requests
from bs4 import BeautifulSoup

from steampy import guard
from steampy.exceptions import ConfirmationExpected
from steampy.login import InvalidCredentials


class Confirmation:
    def __init__(self, data_confid, nonce, creator_id):
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

    def __init__(self, identity_secret: str, my_steam_id: str, session: requests.Session) -> None:
        self._my_steam_id = my_steam_id
        self._identity_secret = identity_secret
        self._session = session

    def send_trade_allow_request(self, trade_offer_id: str) -> dict:
        confirmations = self._get_confirmations()
        confirmation = self._select_trade_offer_confirmation(confirmations, trade_offer_id)
        return self._send_confirmation(confirmation)

    def confirm_sell_listing(self, asset_id: str) -> dict:
        time.sleep(1)
        confirmations = self._get_confirmations()
        print(confirmations)
        confirmation = self._select_sell_listing_confirmation(confirmations, asset_id)
        return self._send_confirmation(confirmation)

    def _send_confirmation(self, confirmation: Confirmation) -> dict:
        tag = Tag.ALLOW
        params = self._create_confirmation_params(tag.value)
        params['op'] = (tag.value,)
        params['cid'] = confirmation.data_confid
        params['ck'] = confirmation.nonce
        headers = {'X-Requested-With': 'XMLHttpRequest'}
        return self._session.get(f'{self.CONF_URL}/ajaxop', params=params, headers=headers).json()

    def _get_confirmations(self) -> List[Confirmation]:
        confirmations = []
        confirmations_page = self._fetch_confirmations_page()
        if confirmations_page.status_code == HTTPStatus.OK:
            confirmations_json = json.loads(confirmations_page.text)
            for conf in confirmations_json['conf']:
                data_confid = conf['id']
                nonce = conf['nonce']
                creator_id = conf['creator_id']
                confirmations.append(Confirmation(data_confid, nonce, creator_id))
            return confirmations
        else:
            raise ConfirmationExpected

    def _fetch_confirmations_page(self) -> requests.Response:
        tag = Tag.CONF.value
        params = self._create_confirmation_params(tag)
        headers = {'X-Requested-With': 'com.valvesoftware.android.steam.community'}
        response = self._session.get(f'{self.CONF_URL}/getlist', params=params, headers=headers)
        if 'Steam Guard Mobile Authenticator is providing incorrect Steam Guard codes.' in response.text:
            raise InvalidCredentials('Invalid Steam Guard file')
        return response

    def _fetch_confirmation_details_page(self, confirmation: Confirmation) -> str:
        tag = f'details{confirmation.data_confid}'
        params = self._create_confirmation_params(tag)
        response = self._session.get(f'{self.CONF_URL}/details/{confirmation.data_confid}', params=params)
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
        print(confirmations)
        for confirmation in confirmations:
            confirmation_details_page = self._fetch_confirmation_details_page(confirmation)
            confirmation_id = self._get_confirmation_sell_listing_id(confirmation_details_page)
            if confirmation_id == asset_id:
                return confirmation
            else:
                print('Different confirmation exceprion. Accepting confirmation')
                self._send_confirmation(confirmation)
        raise ConfirmationExpected

    @staticmethod
    def _get_confirmation_sell_listing_id(confirmation_details_page: str) -> str:
        soup = BeautifulSoup(confirmation_details_page, 'html.parser')
        scr_raw = soup.select('script')[2].string.strip()
        scr_raw = scr_raw[scr_raw.index("'confiteminfo', ") + 16:]
        scr_raw = scr_raw[: scr_raw.index(', UserYou')].replace('\n', '')
        return json.loads(scr_raw)['id']

    @staticmethod
    def _get_confirmation_trade_offer_id(confirmation_details_page: str) -> str:
        soup = BeautifulSoup(confirmation_details_page, 'html.parser')
        full_offer_id = soup.select('.tradeoffer')[0]['id']
        return full_offer_id.split('_')[1]

    def confirm_by_id(self, confirmation_id: str) -> bool:
        """
        Confirm a trade/order based on confirmation_id
        """

        confirmations = self._get_confirmations()
        for conf in confirmations:
            print(f"data_confid: {conf.data_confid}, creator_id: {conf.creator_id}")
        if str(conf.creator_id) == str(confirmation_id):
            result = self._send_confirmation(conf)
        print(result)
        return result.get("success", False)
        return False
