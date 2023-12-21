import unittest
from database import P2PChatDB

class TestP2PChatDB(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chat_db = P2PChatDB()
        cls.chat_db.users.delete_many({})  # Clean slate before starting tests


    def setUp(self):
        # Create users for testing
        self.chat_db.create_user_account('testuser', 'password123')
        self.chat_db.create_user_account('GEHAD', 'password123')
        self.chat_db.create_user_account('gehad', 'password123')



    def test_create_user_account(self):
        # Ensure that creating a user account works
        result = self.chat_db.create_user_account('ee', 'password123')
        self.assertTrue(result)

        # Ensure that creating a user account with an existing username fails
        result = self.chat_db.create_user_account('testuser', 'password123')
        self.assertFalse(result)

    def test_verify_user_login(self):
        # Verify that a correct username and password is authenticated
        self.assertTrue(self.chat_db.verify_user_login('testuser', 'password123'))

        # Verify that an incorrect username or password is not authenticated
        self.assertFalse(self.chat_db.verify_user_login('testuser', 'wrongpassword'))
        self.assertFalse(self.chat_db.verify_user_login('nonexistentuser', 'password123'))

    def test_user_login_logout(self):
        # Test the user login and logout processes
        self.chat_db.user_login('testuser', '127.0.0.1', 8080)
        user = self.chat_db.users.find_one({'username': 'testuser'})
        self.assertTrue(user['online'])
        self.assertIsNotNone(user['address'])

        # Test the user logout process
        self.chat_db.user_logout('testuser')
        user = self.chat_db.users.find_one({'username': 'testuser'})
        self.assertFalse(user['online'])
        self.assertIsNone(user['address'])

    def test_get_username_by_address(self):
        # Test retrieval of username by IP address and port
        self.chat_db.user_login('testuser', '127.0.0.1', 8080)
        username = self.chat_db.get_username_by_address('127.0.0.1', 8080)
        self.assertEqual(username, 'testuser')

        # Ensure that a non-existent IP and port returns None
        username = self.chat_db.get_username_by_address('nonexistent_ip', 1234)
        self.assertIsNone(username)
    def test_get_address_by_username(self):
        # Test retrieval of address by username
        self.chat_db.user_login('testuser', '127.0.0.1', 8080)
        address = self.chat_db.get_address_by_username('testuser')
        self.assertEqual(address, {'ip': '127.0.0.1', 'port': 8080})

        # Ensure that a non-existent username returns None
        address = self.chat_db.get_address_by_username('nonexistentuser')
        self.assertIsNone(address)

    def test_get_online_users(self):
        # Test retrieval of online users
        self.chat_db.user_login('GEHAD', '127.0.0.1', 8080)
        self.chat_db.user_login('gehad', '127.0.0.1', 8081)

        online_users = self.chat_db.get_online_users()
        self.assertIn('GEHAD', online_users)
        self.assertIn('gehad', online_users)

    def test_update_online_users_count(self):
        # Test updating the count of online users
        # First, ensure users are marked as online
        self.chat_db.user_login('GEHAD', '127.0.0.1', 8080)

        # Now update the count
        self.chat_db.update_online_users_count()

        # Fetch the updated user data
        user_gehad = self.chat_db.users.find_one({'username': 'GEHAD'})

        # Check the expected count
        # Assuming 'online_users_count' is the number of other online users
        self.assertEqual(user_gehad['online_users_count'], 1)


    def test_reset_online_users_count(self):
        # Test resetting the online status and count for all users
        self.chat_db.reset_online_users_count()
        user = self.chat_db.users.find_one({'username': 'testuser'})
        self.assertFalse(user['online'])
        self.assertEqual(user['online_users_count'], 0)

    def test_verify_user_login_incorrect_password(self):
        # Create a user account
        self.chat_db.create_user_account('testuser', 'password123')

        # Attempt to verify login with the correct username but incorrect password
        result = self.chat_db.verify_user_login('testuser', 'wrongpassword')

        # Ensure that the login attempt fails
        self.assertFalse(result)

    def test_verify_user_login_correct_credentials(self):
        # Create a user account
        self.chat_db.create_user_account('testuser', 'password123')

        # Attempt to verify login with the correct username and password
        result = self.chat_db.verify_user_login('testuser', 'password123')

        # Ensure that the login attempt is successful
        self.assertTrue(result)


    @classmethod
    def tearDownClass(cls):
        # Clean up the test database after all tests
        cls.chat_db.users.delete_many({})

if __name__ == '__main__':
    unittest.main()
