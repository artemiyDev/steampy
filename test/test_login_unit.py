from http import HTTPStatus
from unittest import TestCase
from unittest.mock import MagicMock

from requests import Session
from requests.cookies import RequestsCookieJar

from steampy.exceptions import ApiException
from steampy.login import LoginExecutor, InvalidCredentials


class TestLoginExecutorUnit(TestCase):
    def test_login_uses_refresh_token_when_session_restored(self):
        executor = LoginExecutor('user', 'pass', 'secret', MagicMock(), refresh_token='rtok')
        executor.refresh_session = MagicMock(return_value=True)
        executor._check_steam_session = MagicMock(return_value=True)
        executor._send_login_request = MagicMock()

        executor.login()

        executor._send_login_request.assert_not_called()

    def test_login_falls_back_to_full_login_when_refresh_invalid(self):
        executor = LoginExecutor('user', 'pass', 'secret', MagicMock(), refresh_token='rtok')
        executor.refresh_session = MagicMock(return_value=False)
        executor._send_login_request = MagicMock(return_value=MagicMock(json=lambda: {'response': {'ok': 1}}))
        executor._check_for_captcha = MagicMock()
        executor._update_steam_guard = MagicMock()
        executor._finalize_login = MagicMock(return_value=MagicMock(json=lambda: {'transfer_info': [{'url': 'u', 'params': {}}], 'steamID': '1'}))
        executor._parse_json = MagicMock(side_effect=[{'response': {'ok': 1}}, {'transfer_info': [{'url': 'u', 'params': {}}], 'steamID': '1'}])
        executor._perform_redirects = MagicMock()
        executor.set_sessionid_cookies = MagicMock()

        executor.login()

        executor._send_login_request.assert_called_once()

    def test_login_raises_when_refresh_fails_and_no_credentials(self):
        executor = LoginExecutor('', '', '', MagicMock(), refresh_token='rtok')
        executor.refresh_session = MagicMock(return_value=False)
        executor._send_login_request = MagicMock()

        with self.assertRaises(InvalidCredentials):
            executor.login()

        executor._send_login_request.assert_not_called()

    def test_poll_session_status_raises_when_refresh_token_missing(self):
        session = MagicMock()
        executor = LoginExecutor('user', 'pass', 'secret', session)
        executor._api_call = MagicMock(return_value=MagicMock(json=lambda: {'response': {}}))
        executor._parse_json = MagicMock(return_value={'response': {}})

        with self.assertRaises(InvalidCredentials):
            executor._poll_session_status('client', 'request')

    def test_finalize_login_uses_domain_specific_sessionid_without_cookie_conflict(self):
        session = Session()
        jar = RequestsCookieJar()
        jar.set('sessionid', 'community-sid', domain='steamcommunity.com', path='/')
        jar.set('sessionid', 'store-sid', domain='store.steampowered.com', path='/')
        session.cookies = jar

        executor = LoginExecutor('user', 'pass', 'secret', session, refresh_token='refresh-token')
        executor._request = MagicMock(return_value=MagicMock())

        executor._finalize_login(use_cookie_sessionid=True)

        _, kwargs = executor._request.call_args
        self.assertEqual(kwargs['files']['sessionid'][1], 'community-sid')

    def test_refresh_session_tries_cookie_then_refresh_only(self):
        session = Session()
        jar = RequestsCookieJar()
        jar.set('sessionid', 'community-sid', domain='steamcommunity.com', path='/')
        session.cookies = jar

        executor = LoginExecutor('user', 'pass', 'secret', session, refresh_token='refresh-token')
        executor._finalize_login = MagicMock(side_effect=[ApiException('cookie refresh failed'), MagicMock()])
        executor._parse_json = MagicMock(return_value={'transfer_info': [{'url': 'u', 'params': {}}], 'steamID': '1'})
        executor._perform_redirects = MagicMock()
        executor.set_sessionid_cookies = MagicMock()
        executor._request = MagicMock(return_value=MagicMock(status_code=200, url='https://steamcommunity.com', text='ok'))

        result = executor.refresh_session()

        self.assertTrue(result)
        self.assertEqual(executor._finalize_login.call_count, 2)
        self.assertEqual(executor._finalize_login.call_args_list[0].kwargs, {'use_cookie_sessionid': True})
        self.assertEqual(executor._finalize_login.call_args_list[1].kwargs, {'use_cookie_sessionid': False})

    def test_refresh_session_retries_without_cookie_when_first_attempt_not_authenticated(self):
        session = Session()
        jar = RequestsCookieJar()
        jar.set('sessionid', 'community-sid', domain='steamcommunity.com', path='/')
        session.cookies = jar

        executor = LoginExecutor('user', 'pass', 'secret', session, refresh_token='refresh-token')
        executor._finalize_login = MagicMock(side_effect=[MagicMock(), MagicMock()])
        executor._parse_json = MagicMock(return_value={'transfer_info': [{'url': 'u', 'params': {}}], 'steamID': '1'})
        executor._perform_redirects = MagicMock()
        executor.set_sessionid_cookies = MagicMock()
        executor._request = MagicMock(return_value=MagicMock(status_code=200, url='https://steamcommunity.com', text='ok'))
        executor._check_steam_session = MagicMock(side_effect=[False, True])

        result = executor.refresh_session()

        self.assertTrue(result)
        self.assertEqual(executor._check_steam_session.call_count, 2)
        self.assertEqual(executor._finalize_login.call_args_list[0].kwargs, {'use_cookie_sessionid': True})
        self.assertEqual(executor._finalize_login.call_args_list[1].kwargs, {'use_cookie_sessionid': False})

    def test_check_steam_session_uses_store_fallback_when_username_missing_in_html(self):
        executor = LoginExecutor('user', 'pass', 'secret', MagicMock())
        store_response = MagicMock(status_code=HTTPStatus.OK, url='https://store.steampowered.com/account/', text='account')
        community_response = MagicMock(status_code=HTTPStatus.OK, url='https://steamcommunity.com/', text='public page')
        executor._request = MagicMock(side_effect=[store_response, community_response])

        self.assertTrue(executor._check_steam_session())

    def test_check_steam_session_false_when_community_redirects_to_login(self):
        executor = LoginExecutor('user', 'pass', 'secret', MagicMock())
        store_response = MagicMock(status_code=HTTPStatus.OK, url='https://store.steampowered.com/account/', text='account')
        community_response = MagicMock(status_code=HTTPStatus.OK, url='https://steamcommunity.com/login/home/', text='login')
        executor._request = MagicMock(side_effect=[store_response, community_response])

        self.assertFalse(executor._check_steam_session())
