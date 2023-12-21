import json
import socket
import threading
import time
from database import P2PChatDB

# Server setup
host = 'localhost'
port = 5000
port_udp = 5001  # Choose a different port for UDP communication
# UDP socket setup
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_socket.bind(('localhost', port_udp))

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()




# Modify the accept_connections function to start the UDP thread


clients = {}
addresses = {}

# Initialize the database
db = P2PChatDB()

# At the top of your server code, define a dictionary to store connections and their addresses
active_connections = {}


def accept_connections():
    db.reset_online_users_count()
    check_thread = threading.Thread(target=check_and_disconnect_inactive_users)
    check_thread.daemon = True
    check_thread.start()

    # Start the UDP thread
    udp_thread = threading.Thread(target=handle_hello_udp)
    udp_thread.daemon = True
    udp_thread.start()

    while True:
        client_conn, client_addr = server.accept()
        print(f"{client_addr} has connected.")

        # Store the connection along with its address
        active_connections[client_conn] = client_addr

        threading.Thread(target=handle_client, args=(client_conn, client_addr)).start()


# Function to handle 'HELLO' messages over UDP
def handle_hello_udp():
    while True:
        try:
            message, client_address = udp_socket.recvfrom(1024)
            if message:
                message_data = json.loads(message.decode('utf-8'))
                # Print the received "HELLO" message
                print(f"Received HELLO from {client_address}: {message_data}")
                handle_hello(None, client_address)  # Reuse the handle_hello function
        except Exception as e:
            print(f"Error in handle_hello_udp: {e}")

# Now, define the get_connection_by_address function
def get_connection_by_address(address):
    for conn, addr in active_connections.items():
        if addr == address:
            return conn
    return None


last_hello_time = {}


# Function to handle 'HELLO' messages
def handle_hello(conn, addr):
    global last_hello_time
    try:
        if is_socket_open(conn):
            if conn in active_connections:
                username = db.get_username_by_address(*active_connections[conn])
                if username:
                    last_hello_time[username] = time.time()
    except Exception as e:
        print(f"Error in handle_hello: {e}")


def is_socket_open(sock):
    try:
        # This is a non-blocking call; it should return instantly no matter the state of the socket.
        # If the socket is open, it will not block. If it's closed, it will throw an exception.
        sock.getpeername()
        return True
    except:
        return False


def broadcast_online_users():
    online_users = db.get_online_users()
    message = {"type": "get_online_users_response", "users": online_users}
    print(f"Users online '{online_users}'.")
    for conn in clients:
        try:
            send_to_client(conn, message)
        except Exception as e:
            print(f"Error broadcasting to {addresses[conn]}: {e}")


def handle_get_online_users(conn):
    online_users = db.get_online_users()
    send_to_client(conn, {"type": "get_online_users_response", "users": online_users})


# Send a message to a single client
def send_to_client(conn, message):
    conn.send(json.dumps(message).encode('utf-8'))


# Handle client messages
def handle_client(conn, addr):
    # print(f"{addr} has connected.")
    send_to_client(conn, {"type":"welcome","msg": "Connection established. Welcome to the P2P Chat Server!"})

    # Save the address information in the global dictionary
    addresses[conn] = addr

    while True:
        try:
            message = conn.recv(1024).decode('utf-8')
            if message:
                print(f"{addr}: {message}")
                message_data = json.loads(message)

                if message_data['type'] == 'get_online_users':
                    handle_get_online_users(conn)
                elif message_data['type'] == 'login':
                    handle_login(conn, message_data)
                elif message_data['type'] == 'create_account':
                    handle_create_account(conn, message_data)
                elif message_data['type'] == 'logout':
                    handle_logout(conn)
                elif message_data['type'] == 'exit':
                    handle_exit(conn)
                elif message_data['type'] == 'hello':
                    handle_hello(conn, addr)  # Handle 'HELLO' messages

        except Exception as e:
            print(f"Error: {e}")
            break

    conn.close()


# Function to check and disconnect users who haven't sent a 'HELLO' message in 3 seconds
def check_and_disconnect_inactive_users():
    global last_hello_time
    while True:
        time.sleep(1)
        current_time = time.time()
        # Copy the dictionary to avoid changing size during iteration
        for username, last_time in last_hello_time.copy().items():
            if current_time - last_time > 3:
                # User hasn't sent a 'HELLO' message in 3 seconds, disconnect and remove entry
                address = db.get_address_by_username(username)
                if address:
                    conn = get_connection_by_address(address)
                    if conn:
                        handle_exit(conn)
                del last_hello_time[username]

def handle_login(conn, message_data):
    global is_logged_in
    username = message_data['username']
    password = message_data['password']
    login_success = db.verify_user_login(username, password)
    if login_success:
        db.user_login(username, *addresses[conn])  # Pass the IP and port
        send_to_client(conn, {"type": "login_response", "status": "ok", "msg": "Login successful."})
        print(f"User '{username}' logged in successfully.")
        is_logged_in = True
        db.update_online_users_count()  # Update online users count
        broadcast_online_users()
    else:
        send_to_client(conn, {"type": "login_response", "status": "error", "msg": "Invalid username or password."})
        print(f"User '{username}' attempted to login with invalid credentials.")



def handle_create_account(conn, message_data):
    # Handle account creation
    global is_logged_in
    username = message_data['username']
    password = message_data['password']
    account_creation_success = db.create_user_account(username, password)
    if account_creation_success:
        send_to_client(conn, {"type":"create_account_response","status": "ok", "msg": "Account creation successful."})
        print(f"User '{username}' created an account successfully.")
        is_logged_in = True  # Set is_logged_in to True after successful account creation
        db.update_online_users_count()
        broadcast_online_users()
    else:
        send_to_client(conn, {"type":"create_account_response","status": "error", "msg": "Username already taken."})
        print(f"User '{username}' attempted to create an account, but the username is already taken.")


def handle_exit(conn):
    global is_logged_in
    username = db.get_username_by_address(*addresses[conn])

    if username:
        if is_logged_in:
            db.user_logout(username)
            send_to_client(conn, {"type": "exit_response", "status": "ok", "msg": "Forced Logout because user exited."})
            print(f"User '{username}' exited successfully with forced Logout.")
        else:
            send_to_client(conn, {"type": "exit_response", "status": "ok", "msg": "Exit successful."})
            print(f"User '{username}' exited successfully.")

        db.update_online_users_count()
        broadcast_online_users()
        # Remove the address entry
        del addresses[conn]
        is_logged_in = False  # Set is_logged_in to False after successful logout
    else:
        send_to_client(conn, {"type": "exit_response", "status": "ok", "msg": "User not logged in and has exited."})
        print(f"An unauthenticated user at {addresses[conn]} has exited.")
        # Remove the address entry
        del addresses[conn]



def handle_logout(conn):
    # Handle user logout
    global is_logged_in
    username = db.get_username_by_address(*addresses[conn])
    if username:
        db.user_logout(username)
        send_to_client(conn, {"type":"logout_response","status": "ok", "msg": "Logout successful."})
        print(f"User '{username}' logged out successfully.")
        is_logged_in = False  # Set is_logged_in to False after successful logout
        db.update_online_users_count()
        broadcast_online_users()
    else:
        send_to_client(conn, {"type":"logout_response","status": "error", "msg": "User not logged in."})
        print(f"An unauthenticated user at {addresses[conn]} attempted to logout.")

def main():
    print(f"Listening on {host}:{port}...")

    # Reset online users count before starting the server
    db.reset_online_users_count()

    accept_thread = threading.Thread(target=accept_connections)
    accept_thread.start()
    accept_thread.join()
    server.close()

# Start the server
if __name__ == "__main__":
    main()
