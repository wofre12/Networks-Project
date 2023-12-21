import unittest
from unittest.mock import patch, Mock
from registry import handle_login, handle_create_account, handle_exit, handle_logout

class RegistryTestCase(unittest.TestCase):

    @patch('registry.send_to_client')
    def test_handle_create_account(self, mock_send_to_client):
        conn = Mock()
        message_data = {'username': 'ZZdddXXX', 'password': 'newpassword'}

        handle_create_account(conn, message_data)

        expected_response = {"type": "create_account_response", "status": "ok", "msg": "Account creation successful."}
        mock_send_to_client.assert_called_with(conn, expected_response)

    @patch('registry.db', autospec=True)
    @patch('registry.send_to_client')
    def test_handle_login(self, mock_send_to_client, mock_db):
        # Set up a mock user in the database
        mock_db.verify_user_login.return_value = True

        conn = Mock()
        addresses = {conn: ('127.0.0.1', 12345)}  # Provide a valid value for addresses
        message_data = {'username': 'ZZdddXXX', 'password': 'newpassword'}

        with patch('registry.addresses', addresses):
            handle_login(conn, message_data)

        expected_response = {"type": "login_response", "status": "ok", "msg": "Login successful."}
        mock_send_to_client.assert_called_with(conn, expected_response)

if __name__ == '__main__':

    unittest.main()
