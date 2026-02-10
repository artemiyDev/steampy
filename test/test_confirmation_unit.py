from unittest import TestCase
from unittest.mock import MagicMock

from steampy.confirmation import Confirmation, ConfirmationExecutor


class TestConfirmationExecutorUnit(TestCase):
    def test_confirm_by_id_returns_true_for_matching_confirmation(self):
        session = MagicMock()
        executor = ConfirmationExecutor('identity', 'steamid', session)
        executor._get_confirmations = MagicMock(
            return_value=[Confirmation('cid-1', 'nonce-1', '123'), Confirmation('cid-2', 'nonce-2', '456')]
        )
        executor._send_confirmation = MagicMock(return_value={'success': True})

        result = executor.confirm_by_id('456')

        self.assertTrue(result)
        executor._send_confirmation.assert_called_once()

    def test_confirm_by_id_returns_false_when_not_found(self):
        session = MagicMock()
        executor = ConfirmationExecutor('identity', 'steamid', session)
        executor._get_confirmations = MagicMock(return_value=[Confirmation('cid-1', 'nonce-1', '123')])
        executor._send_confirmation = MagicMock(return_value={'success': True})

        result = executor.confirm_by_id('999')

        self.assertFalse(result)
        executor._send_confirmation.assert_not_called()
