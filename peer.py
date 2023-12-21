import socket
import threading
import json
import sys
import time
from database import P2PChatDB
from colorama import init, Fore, Style
from pyfiglet import Figlet
import logging

# Initialize colorama
init()

# Initialize Figlet with a chosen font
fig = Figlet(font='slant')

# Initialize colorama
init()

# Client setup
host = 'localhost'
port = 5000
port_udp = 5001  # Use the same port for UDP communication as specified in the server

# UDP socket setup
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
addresses = {}

db = P2PChatDB()
client = None  # Initialize the client socket

# Variable to track login status
is_logged_in = False

# Variable to control the hello thread
send_hello = True

# Function to create and connect the client socket
def create_and_connect_client(max_attempts=5, retry_interval=3, final_retry_interval=60):
    global client

    for attempt in range(1, max_attempts + 1):
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((host, port))
            print_colored("Connection successful.", Fore.GREEN)
            return  # If successful, exit the function
        except ConnectionRefusedError:
            print_colored(f"Unable to connect to the server. Retrying in {retry_interval} seconds... (Attempt {attempt}/{max_attempts})",Fore.RED)
            time.sleep(retry_interval)

    # If still not connected after max_attempts, wait for a longer interval
    print_colored(f"Failed to connect after {max_attempts} attempts. Waiting for {final_retry_interval} seconds before exiting.",Fore.BLUE)
    time.sleep(final_retry_interval)

    # Attempt one more time after the longer interval
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((host, port))
        print_colored("Connection successful.", Fore.GREEN)
    except ConnectionRefusedError:
        print_colored("Final attempt failed. Exiting the program. Please try again later. Our server might be down momentarily.",Fore.RED)
        sys.exit()


# Function to handle disconnection or errors
def handle_disconnection():
    global client, is_logged_in
    print_colored("Disconnected from the server. Reconnecting...", Fore.RED)
    is_logged_in = False  # Reset login status
    if client:
        client.close()  # Close the existing client socket
    create_and_connect_client()  # Attempt to create and connect a new client socket



# Function to send a single "HELLO" message over UDP
def send_hello_message_udp():
    hello_message = {
        "type": "hello"
    }
    udp_socket.sendto(json.dumps(hello_message).encode('utf-8'), ('localhost', port_udp))

# Modify the start_hello_thread function to use UDP
def start_hello_thread():
    hello_thread = threading.Thread(target=send_continuous_hello_udp)
    hello_thread.daemon = True
    hello_thread.start()



# Handle server responses
def handle_server_response(message_data):
    global is_logged_in
    if message_data.get('type') == 'get_online_users_response':
        online_users = message_data.get('users')
        if online_users is not None:
            print("Online users: " + ', '.join(online_users))
        else:
            print("No online users.")
            print_colored("Disconnected from the server. Reconnecting...", Fore.LIGHTMAGENTA_EX)
    elif message_data.get('type') == 'login_response':
        if message_data.get('status') == 'ok':
            print("Login successful.")
            is_logged_in = True
    elif message_data.get('type') == 'logout_response':
        if message_data.get('status') == 'ok':
            print("Logout successful.")
            is_logged_in = False
    elif message_data.get('type') == 'create_account_response':
        if message_data.get('status') == 'ok':
            print("Account creation successful.")
    elif message_data.get('type') == 'welcome':
        print(f"Server: {message_data.get('msg')}")
    else:
        print(f"Ignored unexpected response: {message_data}")

def send_exit():
    # Construct the exit message
    message_data = {
        "type": "exit"
    }
    # Send the exit request to the server
    client.send(json.dumps(message_data).encode('utf-8'))
    print_colored("Exiting the chat...", Fore.LIGHTYELLOW_EX)

    try:
        # Wait for the exit response from the server
        response = wait_for_response('exit_response')

        if response:
            if response.get('status') == 'ok':
                print_colored("Exit successful.", Fore.GREEN)
                if client:
                    client.close()
                return True  # Indicate successful exit
            else:
                print_colored(f"Exit failed. Received response: {response}", Fore.RED)
                return False  # Indicate a failed exit
        else:
            print_colored("Did not receive a valid response from the server.",Fore.RED)
            return False  # Indicate a failed exit

    except Exception as e:
        print_colored(f"Error waiting for exit response: {e}",Fore.RED)
        return False  # Indicate a failed exit

# Global variable to track received messages
received_messages = []

# Handle receiving messages from the server
# Initialize the logging module
logging.basicConfig(level=logging.DEBUG)

# Handle receiving messages from the server
# Modify the receive function to return the received message
def receive():
    try:
        message = client.recv(1024).decode('utf-8')
        if message:
            message_data = json.loads(message)
            handle_server_response(message_data)  # Process server responses
            return message_data
    except socket.error as se:
        # Handle network-related errors (e.g., connection reset, timeout)
        logging.error(f"Network error occurred: {se}")
        # Optionally, you can decide whether to attempt reconnection here
        handle_disconnection()
    except Exception as e:
        # Handle other types of errors
        logging.error(f"An error occurred while receiving: {e}")
    return None



# Modify the send_login function to check the received message
def send_login(username, password):
    # Construct the login message
    message_data = {
        "type": "login",
        "username": username,
        "password": password
    }

    try:
        # Send the login request to the server
        client.send(json.dumps(message_data).encode('utf-8'))

        # Wait for the login response from the server
        response = wait_for_response('login_response')

        if response:
            if response.get('status') == 'ok':
                print_colored("Login successful.",Fore.LIGHTCYAN_EX)
                return True  # Indicate successful login attempt
            else:
                print_colored(f"Login failed. Received response: {response}", Fore.RED)
                return False  # Indicate a failed login attempt
        else:
            print_colored("Did not receive a valid response from the server.", Fore.RED)
            return False  # Indicate a failed login attempt

    except Exception as e:
        print_colored(f"Error sending login request: {e}", Fore.RED)
        return False  # Indicate a failed login attempt

# Add a function to wait for a specific response type
def wait_for_response(expected_type):
    try:
        while True:
            message = client.recv(1024).decode('utf-8')
            if message:
                message_data = json.loads(message)
                if message_data.get('type') == expected_type:
                    return message_data
    except Exception as e:
        print_colored(f"An error occurred while waiting for response: {e}", Fore.RED)
    return None




# Start the receiving thread
def start_receiving_thread():
    receive_thread = threading.Thread(target=receive)
    receive_thread.daemon = True  # This ensures the thread will close when the main program exits
    receive_thread.start()


# Function to send a logout request to the server
def send_continuous_hello_udp():
    global send_hello
    while send_hello:
        if is_logged_in:
            send_hello_message_udp()
        time.sleep(1)  # Send 'HELLO' every second


# Function to send a logout request to the server
def send_logout():
    global is_logged_in, send_hello
    # Construct the logout message
    message_data = {
        "type": "logout"
    }
    # Send the logout request to the server
    client.send(json.dumps(message_data).encode('utf-8'))

    # Wait for the login response from the server
    response = wait_for_response('logout_response')

    if response:
        if response.get('status') == 'ok':
            is_logged_in = False
            print_colored("Logout successful.", Fore.LIGHTGREEN_EX)
            send_hello = False  # Set send_hello to False after successful logout
            return True  # Indicate successful logout attempt
        else:
            print_colored(f"Logout failed. Received response: {response}", Fore.RED)
            return False  # Indicate a failed logout attempt
    else:
        print_colored("Did not receive a valid response from the server.", Fore.RED)
        return False  # Indicate a failed logout attempt


# Function to get online users from the server
def send_get_online_users():
    message_data = {
        "type": "get_online_users"
    }
    try:
        # Send the message to the server
        client.send(json.dumps(message_data).encode('utf-8'))

        # Wait for the response from the server
        response = wait_for_response('get_online_users_response')

        if response:
            online_users = response.get('users')
            if online_users is not None:

                print_colored("Online users: " + ', '.join(online_users), Fore.LIGHTMAGENTA_EX)

            else:
                print_colored("No online users.", Fore.MAGENTA)
        else:
            print_colored("Did not receive a valid response from the server.", Fore.RED)

    except Exception as e:
        print_colored(f"Error sending 'Get Online Users' request: {e}", Fore.RED)


def send_create_account(username, password):
    global is_logged_in

    # Construct the create account message
    message_data = {
        "type": "create_account",
        "username": username,
        "password": password
    }

    try:
        # Send the create account request to the server
        client.send(json.dumps(message_data).encode('utf-8'))

        # Wait for the create account response from the server
        response = wait_for_response('create_account_response')

        if response:
            if response.get('status') == 'ok':
                print_colored("Account creation successful.", Fore.LIGHTGREEN_EX)
                is_logged_in = send_login(username, password)
                return True  # Indicate successful account creation
            else:
                print_colored(f"Account creation failed. Received response: {response}", Fore.RED)
                return False  # Indicate a failed account creation
        else:
            print_colored("Did not receive a valid response from the server.", Fore.RED)
            return False  # Indicate a failed account creation

    except Exception as e:
        print_colored(f"Error sending create account request: {e}", Fore.RED)
        return False  # Indicate a failed account creation


# Modify print_colored function to include more styling options
def print_colored(message, color=Fore.WHITE, style=Style.NORMAL):
    print(f"{style}{color}{message}{Style.RESET_ALL}")

# Function to print colored ASCII art
def print_ascii_art(message, font='slant', color=Fore.CYAN):
    fig = Figlet(font=font)
    ascii_art = fig.renderText(message)
    print_colored(ascii_art, color=color)


import re


def is_strong_password(password):
    # Define criteria for a strong password
    # At least 8 characters
    # At least one uppercase letter
    # At least one lowercase letter
    # At least one digit
    # At least one special character (e.g., !@#$%^&*)
    pattern = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')

    # Check if the password matches the defined pattern
    return bool(re.match(pattern, password))


def get_password_from_user():
    while True:
        password = input("Enter your password: ")
        if is_strong_password(password):
            return password
        else:
            print_colored("Password does not meet the criteria for strength. Please try again.", Fore.LIGHTRED_EX)

# Modify main function to start the threads
def main():
    global is_logged_in, send_hello

    print_ascii_art("P2P Chat Client", font='slant', color=Fore.LIGHTYELLOW_EX)

    # Create and connect the client socket
    create_and_connect_client()

    start_receiving_thread()
    start_hello_thread()

    try:
        while True:
            print_colored("\nEnter the number of the command:", Fore.CYAN)

            if not is_logged_in:
                print_colored("1. Login\n2. Create Account\n3. Exit", Fore.YELLOW)
            else:
                print_colored("1. Logout\n2. Get Online Users\n3. Exit", Fore.YELLOW)

            command = input("Command: ")

            valid_command = False

            if not is_logged_in:
                if command == "1":
                    username = input("Username: ")
                    password = input("Password: ")
                    is_logged_in = send_login(username, password)
                    if is_logged_in:
                        print_colored(f"Welcome back, {username}!", Fore.GREEN)
                        send_hello_message_udp()
                    valid_command = True
                elif command == "2":
                    username = input("Choose a username: ")
                    password = get_password_from_user()
                    # Send create account request
                    create_account_success = send_create_account(username, password)

                    if create_account_success:
                        print_colored(f"Welcome, {username}! You are now logged in.", Fore.GREEN)
                    else:
                        print_colored("Account creation failed. Please try again.", Fore.RED)
                    valid_command = True
                elif command == "3":
                    send_hello = False
                    send_exit()
                    if client:
                        client.close()
                    time.sleep(1)
                    break

            else:
                if command == "1":
                    print_colored("Logging out...", Fore.LIGHTYELLOW_EX)
                    send_logout()
                    valid_command = True
                elif command == "2":
                    send_get_online_users()  # Call the function to get online users
                    valid_command = True
                elif command == "3":
                    send_hello = False
                    send_exit()
                    if client:
                        client.close()
                    time.sleep(1)
                    break

            if not valid_command:
                # Print error messages in red
                print_colored("Please choose a correct command.", Fore.RED)

    except Exception as main_exception:
        # Print exception messages in red
        print_colored(f"An error occurred: {main_exception}", Fore.RED)

    finally:
        # Clean up the UDP socket
        udp_socket.close()

# Start the client
if __name__ == "__main__":
    main()
