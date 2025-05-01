import tkinter as tk
from tkinter.simpledialog import askstring  # Import a simple password prompt
from tkinter import ttk, filedialog, messagebox, simpledialog
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from datetime import datetime
import socket
import json
import os
import base64
import hashlib

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5001
BUFFER_SIZE = 65536
ENCODING = 'utf-8'

def decrypt_private_key(encrypted_private_key_data, password):
    """Decrypts an encrypted private RSA key using the user's password with enhanced error handling."""
    try:
        # Input validation
        if not encrypted_private_key_data or not password:
            raise ValueError("Missing required decryption parameters")
            
        # Parse private key components
        try:
            parts = encrypted_private_key_data.split(":")
            if len(parts) != 3:
                raise ValueError("Invalid private key format - expected 3 components")
                
            salt_encoded, iv_encoded, encrypted_private_key_encoded = parts
        except Exception as e:
            raise ValueError(f"Failed to parse private key data: {e}")

        # Decode Base64 components with specific error handling for each component
        try:
            salt = base64.urlsafe_b64decode(salt_encoded)
            if len(salt) != 16:
                raise ValueError("Invalid salt length - must be 16 bytes")
        except Exception as e:
            raise ValueError(f"Salt decoding failed: {e}")
            
        try:
            iv = base64.b64decode(iv_encoded)
            if len(iv) != 16:
                raise ValueError("Invalid IV length - must be 16 bytes")
        except Exception as e:
            raise ValueError(f"IV decoding failed: {e}")
            
        try:
            encrypted_private_key = base64.b64decode(encrypted_private_key_encoded)
        except Exception as e:
            raise ValueError(f"Encrypted key decoding failed: {e}")

        # Key derivation with separate error handling
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            derived_key = kdf.derive(password.encode())
        except Exception as e:
            raise ValueError(f"Key derivation process failed: {e}")

        # AES decryption with clear error messages
        try:
            cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            decrypted_private_key_padded = decryptor.update(encrypted_private_key) + decryptor.finalize()
        except Exception as e:
            raise ValueError(f"Decryption failed - password may be incorrect: {e}")

        # Process decrypted key
        try:
            # Remove padding bytes
            decrypted_private_key_pem = decrypted_private_key_padded.rstrip(b"\0")
            
            # Validate PEM structure before attempting to load
            if not decrypted_private_key_pem.startswith(b"-----BEGIN PRIVATE KEY-----"):
                raise ValueError("Decrypted data is not a valid PEM private key")
                
            # Load the private key
            private_key = serialization.load_pem_private_key(
                decrypted_private_key_pem,
                password=None
            )
            return private_key
        except Exception as e:
            raise ValueError(f"Failed to load decrypted private key: {e}")

    except ValueError as e:
        # Log specific error for debugging
        print(f"Private key decryption error: {e}")
        return None
    except Exception as e:
        # Catch any unexpected errors
        print(f"Unexpected error during private key decryption: {e}")
        return None

class FileTransferClientGUI:
    def __init__(self, master):
        self.master = master
        master.title("Secure File Transfer Client")

        self.logged_in = False
        self.logged_in_user = None
        self.user_id = None
        self.user_role = None
        self.client_socket = None

        self.style = ttk.Style()  # Create a style object
        self.style.configure("Green.TLabel", foreground="green")  # Define a green style
        self.style.configure("Red.TLabel", foreground="red")    # Define a red style
        self.style.configure("Blue.TLabel", foreground="blue")  # Define a blue style

        self.create_widgets()
        self.connect_server()
        self.transfer_history = []

    def connect_server(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((SERVER_HOST, SERVER_PORT))
            self.status_label.config(style="Green.TLabel", text=f"Connected to server at {SERVER_HOST}:{SERVER_PORT}")
        except socket.error as e:
            self.status_label.config(style="Red.TLabel", text=f"Error connecting to server: {e}")
            messagebox.showerror("Connection Error", f"Could not connect to the server: {e}")

    def create_widgets(self):
        self.notebook = ttk.Notebook(self.master)

        self.auth_frame = ttk.Frame(self.notebook)
        self.transfer_frame = ttk.Frame(self.notebook)
        self.history_frame = ttk.Frame(self.notebook)

        self.notebook.add(self.auth_frame, text='Authentication')
        self.notebook.add(self.transfer_frame, text='File Transfer')
        self.notebook.add(self.history_frame, text='Transfer History')
        self.notebook.pack(expand=True, fill='both', padx=10, pady=10)

        self.create_auth_widgets()
        self.create_transfer_widgets()
        self.create_history_widgets()

        self.status_label = ttk.Label(self.master, text="Not connected", anchor='w')
        self.status_label.pack(fill='x', padx=10, pady=5)

        # Disable transfer and history tabs initially
        self.notebook.tab(1, state="disabled")
        self.notebook.tab(2, state="disabled")
        
        # Admin tab will be created after login if user is admin
        self.admin_frame = None

    def create_auth_widgets(self):
        # --- Registration ---
        reg_group = ttk.LabelFrame(self.auth_frame, text="Register")
        reg_group.pack(padx=10, pady=10, fill='x')

        ttk.Label(reg_group, text="Username:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.reg_username_entry = ttk.Entry(reg_group)
        self.reg_username_entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

        ttk.Label(reg_group, text="Password:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.reg_password_entry = ttk.Entry(reg_group, show="*")
        self.reg_password_entry.grid(row=1, column=1, padx=5, pady=5, sticky='ew')
        
        # Add role selection
        ttk.Label(reg_group, text="Role:").grid(row=2, column=0, padx=5, pady=5, sticky='w')
        self.reg_role_combobox = ttk.Combobox(reg_group, values=('regular', 'admin'), state='readonly')
        self.reg_role_combobox.current(0)  # Default to 'regular'
        self.reg_role_combobox.grid(row=2, column=1, padx=5, pady=5, sticky='ew')
        
        # Add admin password field (hidden initially)
        self.admin_pw_frame = ttk.Frame(reg_group)
        self.admin_pw_frame.grid(row=3, column=0, columnspan=2, sticky='ew', padx=5, pady=5)
        self.admin_pw_frame.grid_remove()  # Hide initially
        
        ttk.Label(self.admin_pw_frame, text="Admin Password:").pack(side='left', padx=5)
        self.admin_password_entry = ttk.Entry(self.admin_pw_frame, show="*")
        self.admin_password_entry.pack(side='left', padx=5, fill='x', expand=True)
        
        # Add callback for role selection change
        self.reg_role_combobox.bind('<<ComboboxSelected>>', self.on_role_change)

        reg_button = ttk.Button(reg_group, text="Register", command=self.register)
        reg_button.grid(row=4, column=0, columnspan=2, padx=5, pady=10, sticky='ew')

        # --- Login ---
        login_group = ttk.LabelFrame(self.auth_frame, text="Login")
        login_group.pack(padx=10, pady=10, fill='x')

        ttk.Label(login_group, text="Username:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.login_username_entry = ttk.Entry(login_group)
        self.login_username_entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

        ttk.Label(login_group, text="Password:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.login_password_entry = ttk.Entry(login_group, show="*")
        self.login_password_entry.grid(row=1, column=1, padx=5, pady=5, sticky='ew')

        login_button = ttk.Button(login_group, text="Login", command=self.login)
        login_button.grid(row=2, column=0, columnspan=2, padx=5, pady=10, sticky='ew')

    def create_transfer_widgets(self):
        # --- Send File ---
        send_group = ttk.LabelFrame(self.transfer_frame, text="Send File")
        send_group.pack(padx=10, pady=10, fill='x')

        ttk.Label(send_group, text="Recipient:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.recipient_entry = ttk.Entry(send_group)
        self.recipient_entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

        ttk.Label(send_group, text="File:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.file_path_label = ttk.Label(send_group, text="No file selected")
        self.file_path_label.grid(row=1, column=1, padx=5, pady=5, sticky='ew')

        browse_button = ttk.Button(send_group, text="Browse", command=self.browse_file)
        browse_button.grid(row=1, column=2, padx=5, pady=5)

        self.send_button = ttk.Button(send_group, text="Send File", command=self.send_file, state='disabled')
        self.send_button.grid(row=2, column=0, columnspan=3, padx=5, pady=10, sticky='ew')

        # --- Logout ---
        logout_button = ttk.Button(self.transfer_frame, text="Logout", command=self.logout)
        logout_button.pack(pady=10, padx=10, fill='x')

    def create_history_widgets(self):
        self.history_tree = ttk.Treeview(
            self.history_frame,
            columns=('filename', 'sender', 'recipient', 'time', 'size', 'status'),
            show='headings'
        )
        self.history_tree.heading('filename', text='Filename')
        self.history_tree.heading('sender', text='Sender')
        self.history_tree.heading('recipient', text='Recipient')
        self.history_tree.heading('time', text='Time')
        self.history_tree.heading('size', text='Size (bytes)')
        self.history_tree.heading('status', text='Status')
        self.history_tree.pack(expand=True, fill='both', padx=10, pady=10)

        button_frame = ttk.Frame(self.history_frame)
        button_frame.pack(fill='x', pady=5)

        # Refresh Button
        refresh_button = ttk.Button(
            button_frame, text="Refresh History", command=self.get_transfer_history
        )
        refresh_button.pack(side='left', padx=5, fill='x', expand=True)

        # Download Button
        download_button = ttk.Button(
            button_frame, text="Download Selected File", command=self.download_selected_file
        )
        download_button.pack(side='left', padx=5, fill='x', expand=True)
        
        # File Permissions Button
        file_perm_button = ttk.Button(
            button_frame, text="Manage File Permissions", command=self.manage_file_permissions
        )
        file_perm_button.pack(side='left', padx=5, fill='x', expand=True)

    def send_request(self, request):
        """Sends a JSON request to the server."""
        if self.client_socket:
            try:
                self.client_socket.sendall(json.dumps(request).encode(ENCODING))
                return True
            except socket.error as e:
                self.status_label.config(style="Red.TLabel", text=f"Error sending request: {e}")
                messagebox.showerror("Send Error", f"Error sending data to server: {e}")
                return False
        else:
            self.status_label.config(style="Red.TLabel", text="Not connected to server.", fg="red")
            messagebox.showerror("Connection Error", "Not connected to the server.")
            return False

    def receive_response(self):
        """Receives and parses a complete JSON response from the server."""
        if self.client_socket:
            try:
                data = b""
                while True:  # Keep receiving until the full JSON response is received
                    chunk = self.client_socket.recv(BUFFER_SIZE)
                    if not chunk:
                        break  # Stop if connection is closed
                    data += chunk
                    try:
                        response = json.loads(data.decode(ENCODING))  # Try parsing JSON
                        return response  # ✅ If successful, return parsed JSON
                    except json.JSONDecodeError:
                        continue  # Keep receiving until we have a full JSON message
                
                # If we exit the loop without valid JSON, it means we got an incomplete response
                self.status_label.config(style="Red.TLabel", text="Server response incomplete.")
                messagebox.showerror("Error", "Incomplete response from server.")
                return None

            except socket.error as e:
                print(f"Socket error: {e}")  # ✅ Debugging step
                self.status_label.config(style="Red.TLabel", text="Error receiving response.")
                messagebox.showerror("Connection Error", "Connection lost.")
                return None

        return None  # 🚨 If the socket is not initialized, return None

    def on_role_change(self, event):
        """Show or hide the admin password field based on selected role."""
        selected_role = self.reg_role_combobox.get()
        if selected_role == 'admin':
            self.admin_pw_frame.grid()  # Show admin password field
        else:
            self.admin_pw_frame.grid_remove()  # Hide admin password field
            
    def register(self):
        username = self.reg_username_entry.get()
        password = self.reg_password_entry.get()
        role = self.reg_role_combobox.get()
        
        # Validate inputs
        if not username or not password:
            messagebox.showerror("Error", "Username and password are required")
            return
            
        # Check admin password if registering as admin
        if role == 'admin':
            admin_password = self.admin_password_entry.get()
            if not admin_password:
                messagebox.showerror("Error", "Admin password is required for admin registration")
                return
            
            # This is a simple check - in a real system, this would be more secure
            # For security reasons, you should have a more robust admin password verification
            ADMIN_PASSWORD = "secure_admin_password"  # In a real system, this would be stored securely
            if admin_password != ADMIN_PASSWORD:
                messagebox.showerror("Error", "Invalid admin password")
                return

        # Generate RSA key pair locally on the client
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        # Convert public key to PEM format
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        # Convert private key to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Generate a salt
        salt = os.urandom(16)
        salt_encoded = base64.urlsafe_b64encode(salt).decode()

        # Derive encryption key from the user's password and salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        derived_key = kdf.derive(password.encode())

        # Generate an initialization vector (IV) for AES encryption
        iv = os.urandom(16)

        # Encrypt the private key using AES-256-CBC
        cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        # Ensure private key length is a multiple of 16 (for AES)
        padded_private_key = private_pem + (b"\0" * (16 - len(private_pem) % 16))
        encrypted_private_key = encryptor.update(padded_private_key) + encryptor.finalize()

        # Store encrypted private key locally in Base64 format
        with open(f"{username}_private.enc", "w") as f:
            f.write(f"{salt_encoded}:{base64.b64encode(iv).decode()}:{base64.b64encode(encrypted_private_key).decode()}")

        # Send public key to the server for storage
        request = {
            'action': 'register', 
            'username': username, 
            'password': password, 
            'public_key': public_pem,
            'role': role
        }
        
        # If registering as admin, include admin password in request
        if role == 'admin':
            request['admin_password'] = admin_password
            
        if self.send_request(request):
            response = self.receive_response()
            if response and response.get('status') == 'success':
                messagebox.showinfo("Success", "User registered successfully!")
                # Clear fields after successful registration
                self.reg_username_entry.delete(0, tk.END)
                self.reg_password_entry.delete(0, tk.END)
                self.reg_role_combobox.current(0)  # Reset to regular
                self.admin_password_entry.delete(0, tk.END)
                self.admin_pw_frame.grid_remove()  # Hide admin password field
            else:
                messagebox.showerror("Error", response.get('message', "Registration failed."))
        else:
            messagebox.showerror("Error", "Failed to communicate with server.")

    def login(self):
        username = self.login_username_entry.get()
        password = self.login_password_entry.get()
        if username and password:
            request = {'action': 'login', 'username': username, 'password': password}
            if self.send_request(request):
                response = self.receive_response()
                if response:
                    messagebox.showinfo("Login", response['message'])
                    if response['status'] == 'success':
                        self.logged_in = True
                        self.logged_in_user = username
                        self.user_id = response.get('user_id')
                        self.user_role = response.get('role')
                        
                        # Update UI based on user role
                        self.notebook.tab(1, state="normal") # Enable transfer tab
                        self.notebook.tab(2, state="normal") # Enable history tab
                        self.notebook.select(1) # Switch to transfer tab
                        self.status_label.config(style="Blue.TLabel", 
                                               text=f"Logged in as {self.logged_in_user} ({self.user_role})")
                        self.send_button.config(state='normal')
                        self.get_transfer_history() # Load history on login
                        
                        # Create admin tab if user is an admin
                        if self.user_role == 'admin':
                            self.create_admin_tab()
                    else:
                        self.disable_transfer_tabs()
                        self.logged_in = False
                        self.logged_in_user = None
                        self.user_id = None
                        self.user_role = None
        else:
            messagebox.showerror("Error", "Username and password are required for login.")

    def logout(self):
        if self.logged_in:
            request = {'action': 'logout'}
            if self.send_request(request):
                response = self.receive_response()
                if response and response['status'] == 'success':
                    messagebox.showinfo("Logout", response['message'])
                    self.logged_in = False
                    self.logged_in_user = None
                    self.user_id = None
                    self.user_role = None
                    
                    # Remove admin tab if it exists
                    if self.admin_frame:
                        self.notebook.forget(self.admin_frame)
                        self.admin_frame = None
                        
                    self.disable_transfer_tabs()
                    self.notebook.select(0) # Switch back to authentication tab
                    self.status_label.config(text="Logged out", style="") # Revert to default style
                else:
                    messagebox.showerror("Logout Error", "Failed to logout.")
        else:
            messagebox.showinfo("Logout", "Not logged in.")

    def disable_transfer_tabs(self):
        self.notebook.tab(1, state="disabled")
        self.notebook.tab(2, state="disabled")
        self.file_path_label.config(text="No file selected")
        self.send_button.config(state='disabled')
        self.recipient_entry.delete(0, tk.END)
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        self.transfer_history = []

    def browse_file(self):
        self.file_path = filedialog.askopenfilename()
        if self.file_path:
            self.file_path_label.config(text=os.path.basename(self.file_path))

    def send_file(self):
        """Send file with encryption and integrity verification."""
        if not self.logged_in:
            messagebox.showerror("Error", "Please log in before sending files")
            return

        recipient = self.recipient_entry.get()
        file_path = self.file_path

        if not recipient:
            messagebox.showerror("Error", "Please enter a recipient username")
            return

        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Error", "Please select a valid file to send")
            return

        try:
            # Calculate file hash before encryption (for integrity verification)
            original_file_hash = None
            try:
                with open(file_path, 'rb') as f:
                    file_data = f.read()
                    # Calculate SHA-256 hash of the original file
                    hash_obj = hashlib.sha256()
                    hash_obj.update(file_data)
                    original_file_hash = hash_obj.hexdigest()
            except IOError as e:
                messagebox.showerror("File Error", f"Unable to read file: {e}")
                return
            except Exception as e:
                messagebox.showerror("File Error", f"Error processing file: {e}")
                return
                
            # Generate encryption key and encrypt file
            try:
                filename = os.path.basename(file_path)
                # Generate a random symmetric key
                symmetric_key = Fernet.generate_key()
                fernet = Fernet(symmetric_key)
                
                # Encrypt the file data
                encrypted_data = fernet.encrypt(file_data)
                encrypted_size = len(encrypted_data)
                
                # Log encryption details for debugging
                print(f"File encrypted successfully: {filename} ({len(file_data)} bytes → {encrypted_size} bytes)")
            except Exception as e:
                messagebox.showerror("Encryption Error", f"File encryption failed: {e}")
                self.status_label.config(style="Red.TLabel", text=f"Encryption failed: {e}")
                return

            # Request recipient's public key
            request = {'action': 'get_public_key', 'recipient': recipient}
            if self.send_request(request):
                response = self.receive_response()
                if response and response.get('status') == 'success':
                    try:
                        recipient_public_key = serialization.load_pem_public_key(response['public_key'].encode())
                    except Exception as e:
                        messagebox.showerror("Key Error", f"Unable to load recipient's public key: {e}")
                        return
                    
                    # Encrypt symmetric key with recipient's public key
                    try:
                        encrypted_symmetric_key = recipient_public_key.encrypt(
                            symmetric_key,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        encrypted_symmetric_key_hex = encrypted_symmetric_key.hex()
                    except Exception as e:
                        messagebox.showerror("Encryption Error", f"Unable to encrypt symmetric key: {e}")
                        return

                    # Send file metadata including hash for integrity verification
                    request = {
                        'action': 'send_file',
                        'recipient': recipient,
                        'filename': filename,
                        'file_size': encrypted_size,
                        'encrypted_key': encrypted_symmetric_key_hex,
                        'original_hash': original_file_hash  # Include hash for integrity verification
                    }
                    
                    if self.send_request(request):
                        response = self.receive_response()
                        if response and response.get('status') == 'ready':
                            try:
                                # Update status before sending
                                self.status_label.config(text=f"Sending encrypted file ({encrypted_size} bytes)...")
                                
                                # Send encrypted file data
                                self.client_socket.sendall(encrypted_data)
                                response = self.receive_response()
                                
                                if response and response.get('status') == 'success':
                                    messagebox.showinfo("Success", f"File '{filename}' has been sent to {recipient} with integrity verification")
                                    self.get_transfer_history()  # Update history
                                else:
                                    messagebox.showerror("Error", response.get('message', "File transfer failed"))
                            except Exception as e:
                                messagebox.showerror("Transfer Error", f"Error sending file data: {e}")
                        else:
                            messagebox.showerror("Error", response.get('message', "Server not ready to receive file"))
                else:
                    messagebox.showerror("Error", response.get('message', "Failed to get recipient's public key"))
        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error during file transfer: {e}")
            self.status_label.config(style="Red.TLabel", text=f"Error: {e}")

    def get_transfer_history(self):
        if self.logged_in:
            request = {'action': 'get_history'}
            if self.send_request(request):
                response = self.receive_response()
                if response and response.get('status') == 'success':
                    self.transfer_history = response.get('history', [])
                    self.populate_history_tree()
                elif response:
                    messagebox.showerror("History Error", response['message'])
                else:
                    messagebox.showerror("Connection Error", "Error communicating with server.")
        else:
            messagebox.showinfo("History", "Please log in to view transfer history.")
            self.notebook.select(0)

    def download_selected_file(self):
        """Downloads the selected file from the server."""
        if not self.logged_in:
            messagebox.showerror("Error", "Please log in before downloading files")
            return
            
        selected = self.history_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a file to download")
            return

        file_data = self.history_tree.item(selected, 'values')
        filename = file_data[0]

        try:
            # Create download directory if it doesn't exist
            os.makedirs("downloads", exist_ok=True)
        
            # Prompt user for download location
            download_path = filedialog.asksaveasfilename(
                initialdir="downloads",
                initialfile=filename,
                title="Save File As",
                filetypes=(("All Files", "*.*"),)
            )
            
            if not download_path:
                # User cancelled
            return
            
            # Request file from server
            request = {'action': 'download_file', 'filename': filename}
            if self.send_request(request):
        response = self.receive_response()
                
                if response and response.get('status') == 'error':
                    # Handle permission error
                    if "permission" in response.get('message', '').lower():
                        messagebox.showerror("Permission Denied", 
                            "You don't have permission to download this file. Please contact the file owner.")
                    else:
                        messagebox.showerror("Download Error", response.get('message', "Failed to download file"))
            return
            
                if response and response.get('status') == 'success':
        try:
                        # Get file size and symmetric key
            file_size = response.get('file_size')
            encrypted_key_hex = response.get('encrypted_key')
                        original_hash = response.get('original_hash')  # For integrity verification
                        
                        # Convert encrypted key from hex back to bytes
                        encrypted_key = bytes.fromhex(encrypted_key_hex)
                        
                        # Load private key from disk
                        with open(f"{self.logged_in_user}_private.enc", "r") as f:
                            encrypted_private_key_data = f.read()
                            
                        # Ask for password to decrypt the private key
                        password = askstring("Password Required", "Enter your password to decrypt the file:", show='*')
                        if not password:
                            return  # User cancelled
                            
                        # Decrypt private key
                        private_key = decrypt_private_key(encrypted_private_key_data, password)
                        if not private_key:
                            messagebox.showerror("Decryption Error", "Failed to decrypt your private key. Incorrect password?")
                            return
                            
                        # Decrypt symmetric key with private key
                        try:
                            symmetric_key = private_key.decrypt(
                                encrypted_key,
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None
                                )
                            )
                        except Exception as e:
                            messagebox.showerror("Decryption Error", f"Failed to decrypt file key: {e}")
                            return
                        
                        # Set a timeout for receiving the file
                        self.client_socket.settimeout(60)  # 60-second timeout
                        
                        try:
            # Receive encrypted file data
                            self.status_label.config(text=f"Downloading file ({file_size} bytes)...")
                            
            received_data = b""
            bytes_received = 0
            
                while bytes_received < file_size:
                    chunk = self.client_socket.recv(BUFFER_SIZE)
                    if not chunk:
                                    break
                    received_data += chunk
                    bytes_received += len(chunk)
            finally:
                # Reset socket timeout
                self.client_socket.settimeout(None)
                
                        # Verify received size
            if bytes_received != file_size:
                            messagebox.showerror("Download Error", f"Incomplete file: received {bytes_received}/{file_size} bytes")
                return
                
                        # Decrypt file with symmetric key
            try:
                            fernet = Fernet(symmetric_key)
                decrypted_data = fernet.decrypt(received_data)
                
                            # Verify integrity if hash was provided
            if original_hash:
                hash_obj = hashlib.sha256()
                hash_obj.update(decrypted_data)
                calculated_hash = hash_obj.hexdigest()
                
                if calculated_hash != original_hash:
                                    messagebox.showerror("Integrity Error", 
                                        "File hash verification failed! The file may have been tampered with.")
                                    # Continue anyway but warn the user
                    
            # Save the decrypted file
                            with open(download_path, 'wb') as f:
                        f.write(decrypted_data)
                                
                            messagebox.showinfo("Success", f"File downloaded and decrypted successfully to {download_path}")
                            self.status_label.config(style="Green.TLabel", text=f"File downloaded: {filename}")
                except Exception as e:
                            messagebox.showerror("Decryption Error", f"Failed to decrypt file: {e}")
                
        except Exception as e:
                        messagebox.showerror("Download Error", f"Error during download: {e}")
                        self.status_label.config(style="Red.TLabel", text=f"Download error: {e}")
                else:
                    messagebox.showerror("Error", "Failed to download file")
        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error: {e}")
            self.status_label.config(style="Red.TLabel", text=f"Error: {e}")

    def populate_history_tree(self):
        # Clear existing items
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)

        for record in self.transfer_history:
            self.history_tree.insert('', 'end', values=(
                record['filename'],
                record['sender'],
                record['recipient'],
                record['transfer_time'],
                record['file_size'],
                record['status']
            ))

    def on_closing(self):
        if self.client_socket:
            try:
                self.client_socket.shutdown(socket.SHUT_RDWR)
                self.client_socket.close()
            except socket.error:
                pass
        self.master.destroy()

    def create_admin_tab(self):
        """Creates the admin tab with user management functionality."""
        # Check if admin tab already exists
        if self.admin_frame:
            return
            
        # Create admin frame
        self.admin_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.admin_frame, text='Admin')
        
        # Create user management section
        user_management_frame = ttk.LabelFrame(self.admin_frame, text="User Management")
        user_management_frame.pack(padx=10, pady=10, fill='both', expand=True)
        
        # User list
        ttk.Label(user_management_frame, text="Users:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        
        # Create treeview for users
        self.users_tree = ttk.Treeview(
            user_management_frame,
            columns=('username', 'role', 'id'),
            show='headings',
            selectmode='browse'
        )
        self.users_tree.heading('username', text='Username')
        self.users_tree.heading('role', text='Role')
        self.users_tree.heading('id', text='ID')
        self.users_tree.column('username', width=150)
        self.users_tree.column('role', width=100)
        self.users_tree.column('id', width=50)
        self.users_tree.grid(row=1, column=0, padx=5, pady=5, sticky='nsew', columnspan=2)
        
        # Scrollbar for users tree
        users_scrollbar = ttk.Scrollbar(user_management_frame, orient='vertical', command=self.users_tree.yview)
        users_scrollbar.grid(row=1, column=2, sticky='ns')
        self.users_tree.configure(yscrollcommand=users_scrollbar.set)
        
        # Buttons frame
        buttons_frame = ttk.Frame(user_management_frame)
        buttons_frame.grid(row=2, column=0, columnspan=3, padx=5, pady=5, sticky='ew')
        
        # Refresh users button
        refresh_users_button = ttk.Button(buttons_frame, text="Refresh User List", command=self.get_users)
        refresh_users_button.pack(side='left', padx=5, pady=5)
        
        # Change user role button
        change_role_button = ttk.Button(buttons_frame, text="Change User Role", command=self.change_user_role)
        change_role_button.pack(side='left', padx=5, pady=5)
        
        # Permissions management section
        permissions_frame = ttk.LabelFrame(self.admin_frame, text="User Permissions")
        permissions_frame.pack(padx=10, pady=10, fill='both', expand=True)
        
        # User selection for permissions
        ttk.Label(permissions_frame, text="User:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.permission_user_combobox = ttk.Combobox(permissions_frame, state='readonly')
        self.permission_user_combobox.grid(row=0, column=1, padx=5, pady=5, sticky='ew')
        
        # Permission type selection
        ttk.Label(permissions_frame, text="Permission:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.permission_type_combobox = ttk.Combobox(permissions_frame, state='readonly', 
                                                  values=('read', 'write', 'manage_users', 'manage_files'))
        self.permission_type_combobox.grid(row=1, column=1, padx=5, pady=5, sticky='ew')
        
        # Buttons for permission management
        perm_buttons_frame = ttk.Frame(permissions_frame)
        perm_buttons_frame.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky='ew')
        
        grant_button = ttk.Button(perm_buttons_frame, text="Grant Permission", command=self.grant_permission)
        grant_button.pack(side='left', padx=5, pady=5)
        
        revoke_button = ttk.Button(perm_buttons_frame, text="Revoke Permission", command=self.revoke_permission)
        revoke_button.pack(side='left', padx=5, pady=5)
        
        # Load users immediately
        self.get_users()
        
    def get_users(self):
        """Retrieves the list of users from the server."""
        if not self.logged_in or self.user_role != 'admin':
            messagebox.showerror("Error", "You don't have permission to manage users")
            return
            
        request = {'action': 'get_users'}
        if self.send_request(request):
            response = self.receive_response()
            if response and response.get('status') == 'success':
                # Clear existing items
                for item in self.users_tree.get_children():
                    self.users_tree.delete(item)
                    
                # Populate with new data
                users = response.get('users', [])
                for user in users:
                    self.users_tree.insert('', 'end', values=(
                        user.get('username', ''),
                        user.get('role', ''),
                        user.get('id', '')
                    ))
                    
                # Update permission user combobox
                self.permission_user_combobox['values'] = [user.get('username', '') for user in users]
                
                self.status_label.config(text=f"Retrieved {len(users)} users")
            else:
                messagebox.showerror("Error", response.get('message', "Failed to retrieve users"))
                
    def change_user_role(self):
        """Changes the role of a selected user."""
        if not self.logged_in or self.user_role != 'admin':
            messagebox.showerror("Error", "You don't have permission to manage users")
            return
            
        selected = self.users_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a user")
            return
            
        user_values = self.users_tree.item(selected, 'values')
        username = user_values[0]
        current_role = user_values[1]
        
        # Don't allow changing own role
        if username == self.logged_in_user:
            messagebox.showerror("Error", "You cannot change your own role")
            return
            
        # Ask for new role
        new_role = simpledialog.askstring(
            "Change Role", 
            f"Enter new role for {username} (current: {current_role}):",
            initialvalue=current_role
        )
        
        if new_role and new_role != current_role:
            # New role selected, send request to server
            request = {
                'action': 'change_user_role',
                'target_username': username,
                'new_role': new_role
            }
            
            if self.send_request(request):
                response = self.receive_response()
                if response and response.get('status') == 'success':
                    messagebox.showinfo("Success", f"User {username} role changed to {new_role}")
                    self.get_users()  # Refresh user list
                else:
                    messagebox.showerror("Error", response.get('message', "Failed to change user role"))
                    
    def grant_permission(self):
        """Grants a permission to a user."""
        if not self.logged_in or self.user_role != 'admin':
            messagebox.showerror("Error", "You don't have permission to manage users")
            return
            
        username = self.permission_user_combobox.get()
        permission = self.permission_type_combobox.get()
        
        if not username or not permission:
            messagebox.showerror("Error", "Please select both user and permission")
            return
            
        request = {
            'action': 'grant_permission',
            'target_username': username,
            'permission': permission
        }
        
        if self.send_request(request):
            response = self.receive_response()
            if response and response.get('status') == 'success':
                messagebox.showinfo("Success", f"Permission '{permission}' granted to {username}")
            else:
                messagebox.showerror("Error", response.get('message', "Failed to grant permission"))
                
    def revoke_permission(self):
        """Revokes a permission from a user."""
        if not self.logged_in or self.user_role != 'admin':
            messagebox.showerror("Error", "You don't have permission to manage users")
            return
            
        username = self.permission_user_combobox.get()
        permission = self.permission_type_combobox.get()
        
        if not username or not permission:
            messagebox.showerror("Error", "Please select both user and permission")
            return
            
        request = {
            'action': 'revoke_permission',
            'target_username': username,
            'permission': permission
        }
        
        if self.send_request(request):
            response = self.receive_response()
            if response and response.get('status') == 'success':
                messagebox.showinfo("Success", f"Permission '{permission}' revoked from {username}")
            else:
                messagebox.showerror("Error", response.get('message', "Failed to revoke permission"))

    def manage_file_permissions(self):
        """Opens a dialog to manage file permissions."""
        if not self.logged_in:
            messagebox.showerror("Error", "Please log in to manage file permissions")
            return
            
        # Get selected file
        selected = self.history_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a file to manage permissions")
            return
            
        # Get file details
        file_data = self.history_tree.item(selected, 'values')
        filename = file_data[0]
        sender = file_data[1]
        
        # Check if user is owner or admin
        if sender != self.logged_in_user and self.user_role != 'admin':
            messagebox.showerror("Error", "You can only manage permissions for files you own")
            return
            
        # Create permissions dialog
        perm_dialog = tk.Toplevel(self.master)
        perm_dialog.title(f"File Permissions: {filename}")
        perm_dialog.geometry("400x400")
        perm_dialog.transient(self.master)
        perm_dialog.grab_set()
        
        # Display current permissions
        ttk.Label(perm_dialog, text=f"Manage permissions for: {filename}").pack(padx=10, pady=10)
        
        # Frame for permissions
        perm_frame = ttk.Frame(perm_dialog)
        perm_frame.pack(padx=10, pady=10, fill='both', expand=True)
        
        # Current permissions
        perm_tree = ttk.Treeview(
            perm_frame,
            columns=('username', 'permission'),
            show='headings',
            selectmode='browse'
        )
        perm_tree.heading('username', text='Username')
        perm_tree.heading('permission', text='Permission')
        perm_tree.column('username', width=150)
        perm_tree.column('permission', width=100)
        perm_tree.pack(padx=5, pady=5, fill='both', expand=True)
        
        # Get file permissions
        self.get_file_permissions(filename, perm_tree)
        
        # Frame for adding new permission
        add_frame = ttk.LabelFrame(perm_dialog, text="Add Permission")
        add_frame.pack(padx=10, pady=10, fill='x')
        
        # User selection
        ttk.Label(add_frame, text="User:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        user_entry = ttk.Entry(add_frame)
        user_entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')
        
        # Permission type
        ttk.Label(add_frame, text="Permission:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        perm_type = ttk.Combobox(add_frame, values=('read', 'write', 'manage'), state='readonly')
        perm_type.set('read')
        perm_type.grid(row=1, column=1, padx=5, pady=5, sticky='ew')
        
        # Public permission checkbox
        is_public_var = tk.BooleanVar()
        is_public = ttk.Checkbutton(add_frame, text="Make Public", variable=is_public_var)
        is_public.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky='w')
        
        # Buttons frame
        button_frame = ttk.Frame(perm_dialog)
        button_frame.pack(pady=10, fill='x')
        
        # Function to set permission
        def set_permission():
            target_user = user_entry.get()
            permission = perm_type.get()
            public = is_public_var.get()
            
            if not permission:
                messagebox.showerror("Error", "Please select a permission type")
                return
                
            if not target_user and not public:
                messagebox.showerror("Error", "Please enter a username or select 'Make Public'")
                return
                
            # Send set permission request
            request = {
                'action': 'set_file_permission',
                'filename': filename,
                'permission_type': permission,
                'is_public': public
            }
            
            # Add target username if specified
            if target_user:
                request['target_username'] = target_user
                
            if self.send_request(request):
                response = self.receive_response()
                if response and response.get('status') == 'success':
                    messagebox.showinfo("Success", "Permission set successfully")
                    # Refresh permissions list
                    self.get_file_permissions(filename, perm_tree)
                else:
                    messagebox.showerror("Error", response.get('message', "Failed to set permission"))
        
        # Function to remove permission
        def remove_permission():
            selected_item = perm_tree.selection()
            if not selected_item:
                messagebox.showerror("Error", "Please select a permission to remove")
                return
                
            perm_data = perm_tree.item(selected_item, 'values')
            target_user = perm_data[0]
            permission = perm_data[1]
            
            is_public = (target_user == "PUBLIC")
            
            # Send remove permission request
            request = {
                'action': 'remove_file_permission',
                'filename': filename,
                'permission_type': permission,
                'is_public': is_public
            }
            
            # Add target username if not public
            if not is_public:
                request['target_username'] = target_user
                
            if self.send_request(request):
                response = self.receive_response()
                if response and response.get('status') == 'success':
                    messagebox.showinfo("Success", "Permission removed successfully")
                    # Refresh permissions list
                    self.get_file_permissions(filename, perm_tree)
                else:
                    messagebox.showerror("Error", response.get('message', "Failed to remove permission"))
        
        # Add buttons
        add_button = ttk.Button(button_frame, text="Add Permission", command=set_permission)
        add_button.pack(side='left', padx=5, pady=5, fill='x', expand=True)
        
        remove_button = ttk.Button(button_frame, text="Remove Permission", command=remove_permission)
        remove_button.pack(side='left', padx=5, pady=5, fill='x', expand=True)
        
        close_button = ttk.Button(button_frame, text="Close", command=perm_dialog.destroy)
        close_button.pack(side='left', padx=5, pady=5, fill='x', expand=True)
        
    def get_file_permissions(self, filename, perm_tree=None):
        """Retrieves file permissions from the server."""
        request = {'action': 'get_file_permissions', 'filename': filename}
        
        if self.send_request(request):
            response = self.receive_response()
            if response and response.get('status') == 'success':
                permissions = response.get('permissions', {})
                
                # Clear the tree if provided
                if perm_tree:
                    for item in perm_tree.get_children():
                        perm_tree.delete(item)
                        
                    # Add user permissions
                    for perm in permissions.get('user_permissions', []):
                        perm_tree.insert('', 'end', values=(perm.get('username'), perm.get('permission')))
                        
                    # Add public permissions
                    for perm in permissions.get('public_permissions', []):
                        perm_tree.insert('', 'end', values=("PUBLIC", perm))
                        
                return permissions
            else:
                if perm_tree:
                    messagebox.showerror("Error", response.get('message', "Failed to retrieve file permissions"))
                return None
        return None

def main():
    root = tk.Tk()
    gui = FileTransferClientGUI(root)
    root.protocol("WM_DELETE_WINDOW", gui.on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()