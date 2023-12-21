import pymongo
from pymongo import MongoClient
import hashlib
import os

class P2PChatDB:
    def __init__(self):
        # Connect to the MongoDB database server
        self.client = MongoClient('localhost', 27017)

        # Create or access the p2pchat database
        self.db = self.client['p2pchat']

        # Access the users collection
        self.users = self.db['users']

    def get_address_by_username(self, username):
        try:
            user = self.users.find_one({'username': username})
            if user and 'address' in user:
                return user['address']
            return None
        except Exception as e:
            print(f"Error getting address for user {username}: {e}")
            return None

    def create_user_account(self, username, password):
        # Check if username already exists
        if self.users.find_one({'username': username}):
            return False

        # Generate a new salt for this user
        salt = os.urandom(32)  # 32 bytes = 256 bits

        # Use the SHA-256 hash function
        hashed_pw = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()

        # Create new user document
        user = {
            'username': username,
            'password': hashed_pw,
            'salt': salt.hex(),  # Store the salt as a hex string for retrieval
            'online': False,
            'address': None
        }

        # Insert new user into the database
        self.users.insert_one(user)
        return True

    def verify_user_login(self, username, password):
        # Find user by username
        user = self.users.find_one({'username': username})

        # Check if user exists
        if user:
            # Retrieve the stored salt for this user and convert it from hex to bytes
            salt = bytes.fromhex(user['salt'])

            # Hash the provided password using the stored salt
            hashed_pw_attempt = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()

            # Compare the hashed password with the stored hashed password
            if hashed_pw_attempt == user['password']:
                return True
        return False

    def user_login(self, username, ip, port):
        # Update user status to online and set last_login information
        self.users.update_one(
            {'username': username},
            {'$set': {'online': True, 'address': {'ip': ip, 'port': port}}}
        )

    def user_logout(self, username):
        # Update user status to offline and clear last_login information
        self.users.update_one(
            {'username': username},
            {'$set': {'online': False, 'address': None}}
        )

    def get_username_by_address(self, ip, port):
        # Find user by ip and port
        user = self.users.find_one({'address.ip': ip, 'address.port': port})
        if user:
            return user['username']
        return None

    def get_online_users(self):
        online_users = self.users.find({'online': True})
        return [user['username'] for user in online_users]

    def update_online_users_count(self):
        online_users_count = self.users.count_documents({'online': True})
        self.users.update_many({}, {'$set': {'online_users_count': online_users_count}})

    def reset_online_users_count(self):
        # Reset the online status and count for all users
        self.users.update_many({}, {'$set': {'online': False, 'online_users_count': 0}})
