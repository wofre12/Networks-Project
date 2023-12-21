import unittest
import json
from unittest.mock import patch
from colorama import init, Fore, Style
import socket
from peer import (
    create_and_connect_client,
    handle_server_response,
    receive,
    wait_for_response,
    send_login,
    send_create_account,
    is_strong_password

)

class TestClientFunctions(unittest.TestCase):

    def setUp(self):
        # Patch the 'peer.client' for each test
        self.mock_client_patcher = patch('peer.client')
        self.mock_client = self.mock_client_patcher.start()

        # Configure the mock to avoid real network calls
        self.mock_client.connect.return_value = None
        self.mock_client.recv.return_value = b'{"status": "ok"}'
        self.mock_client.send.return_value = None
        self.mock_client.close.return_value = None

        # Reset the mock_client before each test
        self.mock_client.reset_mock()

        global is_logged_in
        is_logged_in = False  # Reset the logged-in state before each test


    @patch('socket.socket')
    def test_create_and_connect_client_successful(self, mock_socket):
        create_and_connect_client()
        mock_socket.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        mock_socket.return_value.connect.assert_called_once_with(('localhost', 5000))

    @patch('builtins.print')
    def test_handle_server_response_login_response(self, mock_print):
        message_data = {"type": "login_response", "status": "ok"}
        handle_server_response(message_data)
        # Adjust the expected call based on the actual print call in handle_server_response
        mock_print.assert_called_once_with("Login successful.")

    @patch('peer.client')
    def test_receive_valid_message(self, mock_client):
        mock_client.recv.return_value = b'{"type": "welcome", "msg": "Welcome!"}'
        message_data = receive()
        self.assertEqual(message_data, {"type": "welcome", "msg": "Welcome!"})

    @patch('peer.client')
    @patch('logging.error')
    def test_receive_invalid_message(self, mock_logging_error, mock_client):
        mock_client.recv.return_value = b'invalid json'
        message_data = receive()
        self.assertIsNone(message_data)
        mock_logging_error.assert_called_once_with("An error occurred while receiving: Invalid JSON.")

    @patch('peer.client')
    def test_wait_for_response(self, mock_client):
        # Create a MagicMock to simulate .recv() being called multiple times.
        # First call returns a non-matching type, second call returns the expected type.
        mock_client.recv.side_effect = [
            b'{"type": "login_response", "status": "ok"}'
        ]
        response = wait_for_response('login_response')
        self.assertEqual(response, {"type": "login_response", "status": "ok"})


    @patch('peer.client')
    @patch('builtins.input', side_effect=["testuser", "testpassword"])
    def test_send_login_successful(self, mock_input, mock_client):
        mock_client.recv.return_value = b'{"type": "login_response", "status": "ok"}'
        result = send_login("testuser", "testpassword")
        self.assertTrue(result)

    @patch('peer.client')
    @patch('builtins.input', side_effect=["testuser", "testpassword"])
    def test_send_login_failure(self, mock_input, mock_client):
        mock_client.recv.return_value = b'{"type": "login_response", "status": "error"}'
        result = send_login("testuser", "testpassword")
        self.assertFalse(result)

    @patch('peer.client')
    @patch('peer.wait_for_response')
    def test_send_create_account_failure(self,  mock_wait_for_response,mock_client):
        mock_client.recv.return_value = b'{"type": "create_account_response", "status": "error"}'
        result = send_create_account("gehad", "gehad")
        self.assertFalse(result)


    @patch('peer.client')
    @patch('peer.wait_for_response', return_value={"type": "create_account_response", "status": "ok"})
    @patch('peer.send_login', return_value=True)
    def test_send_create_account_successful(self, mock_send_login, mock_wait_for_response,mock_client):
        mock_client.recv.return_value = b'{"type": "create_account_response", "status": "ok"}'
        result = send_create_account("AHMED", "ajdWOJOWMOo*311")
        self.assertTrue(result)

    def test_strong_password(self):
        # Test with strong passwords
        strong_passwords = [
            "Abcdefg1!",
            "P@ssw0rd",
            "S0m3Str0ngP@ss"
        ]

        for password in strong_passwords:
            with self.subTest(password=password):
                result = is_strong_password(password)
                self.assertTrue(result, f"Expected {password} to be a strong password")

    def test_weak_password(self):
        # Test with weak passwords
        weak_passwords = [
            "password",           # No uppercase letter
            "12345678",           # No letters
            "AbcdEfgh",           # No special character
            "Short1!"             # Too short
        ]

        for password in weak_passwords:
            with self.subTest(password=password):
                result = is_strong_password(password)
                self.assertFalse(result, f"Expected {password} to be a weak password")

    def tearDown(self):
        # Stop the patch after each test
        self.mock_client_patcher.stop()

if __name__ == "__main__":
    unittest.main()
