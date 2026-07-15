from unittest import TestCase

from requests import Session

from steampy.client import SteamClient
from steampy.confirmation import ConfirmationExecutor
from steampy.login import LoginExecutor
from steampy.market import SteamMarket
from steampy.models import DEFAULT_USER_AGENT


class TestDefaultUserAgent(TestCase):
    def test_steam_client_overrides_requests_default_user_agent(self):
        client = SteamClient('api-key')

        self.assertEqual(client._session.headers['User-Agent'], DEFAULT_USER_AGENT)
        self.assertNotIn('python-requests', client._session.headers['User-Agent'].lower())

    def test_session_consumers_replace_existing_user_agent(self):
        constructors = (
            lambda session: SteamMarket(session),
            lambda session: LoginExecutor('user', 'pass', 'secret', session),
            lambda session: ConfirmationExecutor('identity', 'steam-id', session),
        )

        for construct in constructors:
            with self.subTest(consumer=construct):
                session = Session()
                self.assertIn('python-requests', session.headers['User-Agent'].lower())

                construct(session)

                self.assertEqual(session.headers['User-Agent'], DEFAULT_USER_AGENT)
