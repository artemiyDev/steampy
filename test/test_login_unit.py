from unittest import TestCase
from unittest.mock import MagicMock

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
        executor.refresh_session = MagicMock(return_value=True)
        executor._check_steam_session = MagicMock(return_value=False)
        executor._send_login_request = MagicMock(return_value=MagicMock(json=lambda: {'response': {'ok': 1}}))
        executor._check_for_captcha = MagicMock()
        executor._update_steam_guard = MagicMock()
        executor._finalize_login = MagicMock(return_value=MagicMock(json=lambda: {'transfer_info': [{'url': 'u', 'params': {}}], 'steamID': '1'}))
        executor._parse_json = MagicMock(side_effect=[{'response': {'ok': 1}}, {'transfer_info': [{'url': 'u', 'params': {}}], 'steamID': '1'}])
        executor._perform_redirects = MagicMock()
        executor.set_sessionid_cookies = MagicMock()

        executor.login()

        executor._send_login_request.assert_called_once()

    def test_poll_session_status_raises_when_refresh_token_missing(self):
        session = MagicMock()
        executor = LoginExecutor('user', 'pass', 'secret', session)
        executor._api_call = MagicMock(return_value=MagicMock(json=lambda: {'response': {}}))
        executor._parse_json = MagicMock(return_value={'response': {}})

        with self.assertRaises(InvalidCredentials):
            executor._poll_session_status('client', 'request')
