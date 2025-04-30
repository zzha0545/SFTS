import socket
import threading
import os
import hashlib
import mysql.connector
import json
from datetime import datetime

# --- Configuration ---
SERVER_HOST = '0.0.0.0'
SERVER_PORT = 5001
DATABASE_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'root',
    'database': 'secure_file_transfer'
}
BUFFER_SIZE = 65536
ENCODING = 'utf-8'


def log_activity(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")


# --- Database Interaction ---
def create_db_connection():
    """Creates and returns a MySQL database connection."""
    try:
        mydb = mysql.connector.connect(**DATABASE_CONFIG)
        log_activity("Database connection established.")
        return mydb
    except mysql.connector.Error as err:
        log_activity(f"Error connecting to MySQL: {err}")
        return None


def create_tables():
    """Creates the users and file_transfers tables if they don't exist."""
    mydb = create_db_connection()
    if mydb:
        cursor = mydb.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            public_key TEXT NOT NULL
        )
    """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS file_transfers (
                id INT AUTO_INCREMENT PRIMARY KEY,
                sender_id INT NOT NULL,
                recipient_id INT NOT NULL,
                filename VARCHAR(255) NOT NULL,
                transfer_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                file_size BIGINT,
                status VARCHAR(50),
                encrypted_key TEXT NOT NULL,
                FOREIGN KEY (sender_id) REFERENCES users(id),
                FOREIGN KEY (recipient_id) REFERENCES users(id)
            )
        """)
        mydb.commit()
        log_activity("Checked and ensured 'users' and 'file_transfers' tables exist.")
        cursor.close()
        mydb.close()


def register_user(username, password, client_public_key):
    """Registers a new user in the database."""
    mydb = create_db_connection()
    if mydb:
        cursor = mydb.cursor()
        try:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            cursor.execute("INSERT INTO users (username, password, public_key) VALUES (%s, %s, %s)",
                           (username, hashed_password, client_public_key))
            mydb.commit()
            cursor.close()
            mydb.close()
            log_activity(f"User '{username}' registered successfully.")
            return True
        except mysql.connector.IntegrityError:
            cursor.close()
            mydb.close()
            log_activity(f"Registration failed: Username '{username}' already exists.")
            return False  # Username already exists
        except mysql.connector.Error as err:
            log_activity(f"Error registering user '{username}': {err}")
            cursor.close()
            mydb.close()
            return False


def login_user(username, password):
    """Verifies user credentials against the database."""
    mydb = create_db_connection()
    if mydb:
        cursor = mydb.cursor()
        cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
        result = cursor.fetchone()
        cursor.close()
        mydb.close()
        if result:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            if hashed_password == result[0]:
                log_activity(f"User '{username}' logged in successfully.")
                return True
            else:
                log_activity(f"Login failed for user '{username}': Incorrect password.")
                return False
        else:
            log_activity(f"Login failed: User '{username}' not found.")
            return False


def get_user_public_key(username):
    """Fetch the recipient's public key from the database."""
    mydb = create_db_connection()
    if mydb:
        cursor = mydb.cursor()
        cursor.execute("SELECT public_key FROM users WHERE username = %s", (username,))
        result = cursor.fetchone()
        cursor.close()
        mydb.close()
        if result:
            return result[0]  # Public key in PEM format
        return None


def get_user_id(username):
    """Retrieves the user ID based on the username."""
    mydb = create_db_connection()
    if mydb:
        cursor = mydb.cursor()
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        result = cursor.fetchone()
        cursor.close()
        mydb.close()
        if result:
            return result[0]
        else:
            log_activity(f"Could not retrieve ID for user '{username}'.")
            return None


def get_username_by_id(user_id):
    """Retrieves the username based on the user ID."""
    mydb = create_db_connection()
    if mydb:
        cursor = mydb.cursor()
        cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
        result = cursor.fetchone()
        cursor.close()
        mydb.close()
        if result:
            return result[0]
        else:
            log_activity(f"Could not retrieve username for ID '{user_id}'.")
            return None


def get_transfer_history(user_id):
    """Retrieves the file transfer history for a given user ID."""
    mydb = create_db_connection()
    if mydb:
        cursor = mydb.cursor()
        cursor.execute("""
            SELECT ft.filename, s.username AS sender, r.username AS recipient, ft.transfer_time, ft.file_size, ft.status
            FROM file_transfers ft
            JOIN users s ON ft.sender_id = s.id
            JOIN users r ON ft.recipient_id = r.id
            WHERE ft.sender_id = %s OR ft.recipient_id = %s
            ORDER BY ft.transfer_time DESC
        """, (user_id, user_id))
        history = cursor.fetchall()
        cursor.close()
        mydb.close()
        history_data = []
        for row in history:
            history_data.append({
                'filename': row[0],
                'sender': row[1],
                'recipient': row[2],
                'transfer_time': str(row[3]),
                'file_size': row[4],
                'status': row[5]
            })
        log_activity(f"Retrieved transfer history for user ID '{user_id}'. Found {len(history_data)} records.")
        return history_data
    else:
        log_activity(f"Failed to retrieve transfer history for user ID '{user_id}' due to database error.")
        return None


# --- Client Handling ---
def handle_client(client_socket, client_address):
    """Handles communication with a connected client."""
    log_activity(f"Connection from {client_address}")

    logged_in_user = None

    try:
        while True:
            try:
                data = client_socket.recv(BUFFER_SIZE)
                if not data:
                    log_activity(f"Client {client_address} disconnected.")
                    break

                try:
                    request = json.loads(data.decode(ENCODING))
                    action = request.get('action')
                    log_activity(
                        f"Received action '{action}' from {client_address} (User: {logged_in_user if logged_in_user else 'N/A'}). Request details: {request}")

                    if action == 'register':
                        username = request.get('username')
                        password = request.get('password')
                        client_public_key = request.get('public_key')
                        if username and password:
                            if register_user(username, password, client_public_key):
                                response = {'status': 'success', 'message': 'Registration successful'}
                            else:
                                response = {'status': 'error', 'message': 'Username already exists'}
                        else:
                            response = {'status': 'error', 'message': 'Username and password are required'}
                        client_socket.send(json.dumps(response).encode(ENCODING))
                        log_activity(f"Sent response to {client_address}: {response}")

                    elif action == 'login':
                        username = request.get('username')
                        password = request.get('password')
                        if username and password:
                            if login_user(username, password):
                                logged_in_user = username
                                response = {'status': 'success', 'message': 'Login successful'}
                            else:
                                response = {'status': 'error', 'message': 'Invalid username or password'}
                        else:
                            response = {'status': 'error', 'message': 'Username and password are required'}
                        client_socket.send(json.dumps(response).encode(ENCODING))
                        log_activity(f"Sent response to {client_address}: {response}")

                    elif action == 'send_file' and logged_in_user:
                        recipient_username = request.get('recipient')
                        filename = request.get('filename')
                        file_size = request.get('file_size')
                        encrypted_key = request.get('encrypted_key')  # ✅ Get encrypted Fernet key from client

                        if recipient_username and filename and file_size is not None and encrypted_key:
                            recipient_id = get_user_id(recipient_username)
                            sender_id = get_user_id(logged_in_user)

                            if recipient_id and sender_id:
                                response = {'status': 'ready', 'message': 'Ready to receive file'}
                                client_socket.send(json.dumps(response).encode(ENCODING))

                                # Receive encrypted file data
                                received_data = b""
                                bytes_received = 0
                                while bytes_received < file_size:
                                    chunk = client_socket.recv(BUFFER_SIZE)
                                    if not chunk:
                                        break
                                    received_data += chunk
                                    bytes_received += len(chunk)

                                if bytes_received == file_size:
                                    try:
                                        # Save encrypted file directly without decryption
                                        save_path = f"received_files/{logged_in_user}_{filename}.enc"
                                        os.makedirs("received_files", exist_ok=True)
                                        with open(save_path, 'wb') as f:
                                            f.write(received_data)

                                        # Store file metadata and encrypted Fernet key in database
                                        mydb = create_db_connection()
                                        if mydb:
                                            cursor = mydb.cursor()
                                            cursor.execute("""
                                                INSERT INTO file_transfers (sender_id, recipient_id, filename, file_size, status, encrypted_key)
                                                VALUES (%s, %s, %s, %s, %s, %s)
                                            """, (sender_id, recipient_id, filename, len(received_data), 'success',
                                                  encrypted_key))

                                            mydb.commit()
                                            cursor.close()
                                            mydb.close()

                                        log_activity(
                                            f"Encrypted file '{filename}' successfully received and stored at '{save_path}'.")
                                        response = {'status': 'success',
                                                    'message': f'Encrypted file "{filename}" received successfully.'}
                                    except Exception as e:
                                        log_activity(f"Error storing encrypted file: {e}")
                                        response = {'status': 'error', 'message': 'Error saving file'}

                                else:
                                    log_activity(
                                        f"File transfer incomplete ({bytes_received}/{file_size} bytes received).")
                                    response = {'status': 'error', 'message': 'File transfer incomplete'}
                            else:
                                response = {'status': 'error', 'message': f'Recipient "{recipient_username}" not found'}
                        else:
                            response = {'status': 'error', 'message': 'Invalid request parameters'}

                        client_socket.send(json.dumps(response).encode(ENCODING))



                    elif action == 'get_history' and logged_in_user:
                        user_id = get_user_id(logged_in_user)
                        if user_id:
                            history = get_transfer_history(user_id)
                            if history is not None:
                                response = {'status': 'success', 'history': history}
                            else:
                                response = {'status': 'error', 'message': 'Could not retrieve transfer history'}
                        else:
                            response = {'status': 'error', 'message': 'User not found'}
                        client_socket.send(json.dumps(response).encode(ENCODING))
                        log_activity(f"Sent transfer history response to {client_address} (User: {logged_in_user}).")

                    elif action == 'get_public_key':
                        recipient_username = request.get('recipient')
                        recipient_public_key = get_user_public_key(recipient_username)

                        if recipient_public_key:
                            response = {'status': 'success', 'public_key': recipient_public_key}
                        else:
                            response = {'status': 'error', 'message': 'Recipient not found'}

                        client_socket.send(json.dumps(response).encode(ENCODING))

                    elif action == 'download_file' and logged_in_user:
                        filename = request.get('filename')
                        recipient_username = logged_in_user  # The user requesting the file

                        if filename:
                            mydb = create_db_connection()
                            if mydb:
                                cursor = mydb.cursor()
                                cursor.execute("""
                                    SELECT file_size, encrypted_key FROM file_transfers
                                    WHERE filename = %s AND recipient_id = (SELECT id FROM users WHERE username = %s)
                                """, (filename, recipient_username))
                                result = cursor.fetchone()
                                cursor.close()
                                mydb.close()

                                if result:
                                    file_size, encrypted_key = result

                                    # Locate the encrypted file
                                    file_path = None
                                    for fname in os.listdir("received_files"):
                                        if fname.endswith(f"_{filename}.enc"):  # Match filename with sender prefix
                                            file_path = os.path.join("received_files", fname)
                                            break

                                    if file_path and os.path.exists(file_path):
                                        try:
                                            with open(file_path, 'rb') as f:
                                                encrypted_data = f.read()  # Read the encrypted file directly

                                            # Send metadata including encrypted Fernet key
                                            response = {'status': 'success', 'file_size': len(encrypted_data),
                                                        'encrypted_key': encrypted_key}
                                            client_socket.send(json.dumps(response).encode(ENCODING))

                                            # Send the actual encrypted file data
                                            client_socket.sendall(encrypted_data)

                                            log_activity(
                                                f"Encrypted file '{filename}' sent to recipient '{recipient_username}'.")
                                        except Exception as e:
                                            log_activity(f"Error reading encrypted file '{filename}': {e}")
                                            response = {'status': 'error', 'message': 'Error reading file'}
                                            client_socket.send(json.dumps(response).encode(ENCODING))
                                    else:
                                        response = {'status': 'error', 'message': 'File not found'}
                                        client_socket.send(json.dumps(response).encode(ENCODING))
                                else:
                                    response = {'status': 'error', 'message': 'No record found for this file'}
                                    client_socket.send(json.dumps(response).encode(ENCODING))
                            else:
                                response = {'status': 'error', 'message': 'Database connection failed'}
                                client_socket.send(json.dumps(response).encode(ENCODING))
                        else:
                            response = {'status': 'error', 'message': 'Filename not provided'}
                            client_socket.send(json.dumps(response).encode(ENCODING))


                    elif action == 'logout' and logged_in_user:
                        log_activity(f"User '{logged_in_user}' logged out.")
                        logged_in_user = None
                        response = {'status': 'success', 'message': 'Logged out successfully'}
                        client_socket.send(json.dumps(response).encode(ENCODING))
                        log_activity(f"Sent logout confirmation to {client_address}.")

                    else:
                        response = {'status': 'error', 'message': 'Invalid action or not logged in'}
                        client_socket.send(json.dumps(response).encode(ENCODING))
                        log_activity(f"Sent error response to {client_address}: {response}")

                except json.JSONDecodeError:
                    response = {'status': 'error', 'message': 'Invalid JSON format'}
                    client_socket.send(json.dumps(response).encode(ENCODING))
                    log_activity(f"Sent JSON decode error to {client_address}: {response}")

            except ConnectionResetError:
                log_activity(f"Client {client_address} disconnected unexpectedly.")
                break
            except Exception as e:
                log_activity(f"Error handling client {client_address}: {e}")
                break

    finally:
        log_activity(f"Connection with {client_address} closed.")
        client_socket.close()


# --- Server Startup ---
def start_server():
    """Starts the file transfer server."""
    create_tables()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.bind((SERVER_HOST, SERVER_PORT))
        server_socket.listen(5)
        log_activity(f"Server listening on {SERVER_HOST}:{SERVER_PORT}")

        while True:
            client_socket, client_address = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.start()

    except socket.error as e:
        log_activity(f"Socket error: {e}")
    finally:
        server_socket.close()
        log_activity("Server socket closed.")


if __name__ == "__main__":
    start_server()