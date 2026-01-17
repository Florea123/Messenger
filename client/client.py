import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import json
import base64
import os
import hashlib
import emoji
import io
from PIL import Image, ImageTk
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

HOST = '127.0.0.1'
PORT = 12345

class MessengerClient:
    def __init__(self):
        self.socket = None
        self.username = None
        self.running = False
        self.current_conversation = None 
        self.all_users = [] 
        
        self.private_key = None
        self.public_key = None
        self.public_keys_cache = {}  
        
        self.root = tk.Tk()
        self.root.title("Messenger")
        self.root.geometry("900x600")
        self.root.configure(bg="#f0f0f0")
        
        self.show_login_screen()
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    
    def show_login_screen(self):
        self.login_frame = tk.Frame(self.root, bg="#f0f0f0")
        self.login_frame.place(relx=0.5, rely=0.5, anchor="center")
        
        tk.Label(
            self.login_frame, 
            text="MESSENGER", 
            font=("Arial", 24, "bold"),
            bg="#f0f0f0",
            fg="#0a21ee"
        ).grid(row=0, column=0, columnspan=2, pady=20)
        
        tk.Label(
            self.login_frame, 
            text="Username:",
            font=("Arial", 11),
            bg="#f0f0f0"
        ).grid(row=1, column=0, sticky="e", padx=5, pady=10)
        
        self.username_entry = tk.Entry(self.login_frame, font=("Arial", 11), width=25)
        self.username_entry.grid(row=1, column=1, padx=5, pady=10)
        
        tk.Label(
            self.login_frame, 
            text="Parola:",
            font=("Arial", 11),
            bg="#f0f0f0"
        ).grid(row=2, column=0, sticky="e", padx=5, pady=10)
        
        self.password_entry = tk.Entry(self.login_frame, font=("Arial", 11), width=25, show="*")
        self.password_entry.grid(row=2, column=1, padx=5, pady=10)
        self.password_entry.bind('<Return>', lambda e: self.login())
        
        btn_frame = tk.Frame(self.login_frame, bg="#f0f0f0")
        btn_frame.grid(row=3, column=0, columnspan=2, pady=20)
        
        tk.Button(
            btn_frame,
            text="Login",
            command=self.login,
            bg="#0a21ee",
            fg="white",
            font=("Arial", 11, "bold"),
            width=12,
            cursor="hand2"
        ).pack(side=tk.LEFT, padx=5)
        
        tk.Button(
            btn_frame,
            text="Register",
            command=self.register,
            bg="#33df10",
            fg="white",
            font=("Arial", 11, "bold"),
            width=12,
            cursor="hand2"
        ).pack(side=tk.LEFT, padx=5)
    
    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            messagebox.showwarning("Eroare", "Completeaza toate campurile!")
            return
        
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((HOST, PORT))
            
            self.socket.sendall(f"LOGIN:{username}:{password}\n".encode())
            response = self.socket.recv(1024).decode().strip()
            
            if response.startswith("LOGIN_OK"):
                self.username = username
                
                self.load_or_generate_keys(password)
                
                self.send_public_key()
                
                self.login_frame.destroy()
                self.show_messenger_screen()
                self.start_receiving()
            elif response.startswith("LOGIN_FAIL"):
                error_msg = response.split(":", 1)[1]
                messagebox.showerror("Eroare", error_msg)
                self.socket.close()
        
        except Exception as e:
            messagebox.showerror("Eroare", "Nu se poate conecta la server")

    
    def get_key_filename(self):
        if not os.path.exists('keys'):
            os.makedirs('keys')
        return f'keys/{self.username}_private.key'
    
    def derive_key_from_password(self, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.username.encode(),
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    def save_private_key(self, password):
        try:
            private_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            key = self.derive_key_from_password(password)
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            padding_length = 16 - (len(private_pem) % 16)
            padded_data = private_pem + bytes([padding_length]) * padding_length
            
            encrypted = encryptor.update(padded_data) + encryptor.finalize()
            
            with open(self.get_key_filename(), 'wb') as f:
                f.write(iv + encrypted)
        except Exception as e:
            print(f"Eroare salvare cheie: {e}")
    
    def load_private_key(self, password):
        try:
            if not os.path.exists(self.get_key_filename()):
                return None
            
            with open(self.get_key_filename(), 'rb') as f:
                data = f.read()
            
            iv = data[:16]
            encrypted = data[16:]
            
            key = self.derive_key_from_password(password)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            padded_data = decryptor.update(encrypted) + decryptor.finalize()
            padding_length = padded_data[-1]
            private_pem = padded_data[:-padding_length]
            
            private_key = serialization.load_pem_private_key(
                private_pem,
                password=None,
                backend=default_backend()
            )
            return private_key
        except Exception as e:
            return None
    
    def load_or_generate_keys(self, password):
        loaded_key = self.load_private_key(password)
        
        if loaded_key:
            self.private_key = loaded_key
            self.public_key = self.private_key.public_key()
        else:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
            self.save_private_key(password)
    
    def send_public_key(self):
        try:
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            
            public_pem_oneline = public_pem.replace('\n', '\\n')
            
            self.socket.sendall(f"SEND_PUBLIC_KEY:{public_pem_oneline}\n".encode())
        except Exception as e:
            print("Eroare trimitere cheie publica")
    
    def get_public_key(self, username):
        if username in self.public_keys_cache:
            return self.public_keys_cache[username]
        
        try:
            self.socket.sendall(f"GET_PUBLIC_KEY:{username}\n".encode())
            return None
        except Exception as e:
            return None
    
    def encrypt_message(self, message, recipient_username):
        if recipient_username == self.username:
            recipient_public_key = self.public_key
        else:
            recipient_public_key = self.public_keys_cache.get(recipient_username)
        
        if not recipient_public_key:
            return None
        
        try:
            encrypted = recipient_public_key.encrypt(
                message.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            return None
    
    def decrypt_message(self, encrypted_message_b64):
        try:
            encrypted = base64.b64decode(encrypted_message_b64)
            
            decrypted = self.private_key.decrypt(
                encrypted,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted.decode()
        except Exception as e:
            return "Eroare decriptare"
    
    def encrypt_image(self, image_data, recipient_username):
        try:
            if recipient_username == self.username:
                recipient_public_key = self.public_key
            else:
                recipient_public_key = self.public_keys_cache.get(recipient_username)
            
            if not recipient_public_key:
                return None
            
            aes_key = os.urandom(32) 
            iv = os.urandom(16) 

            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            padding_length = 16 - (len(image_data) % 16)
            padded_data = image_data + bytes([padding_length]) * padding_length
            
            encrypted_image = encryptor.update(padded_data) + encryptor.finalize()
            
            encrypted_aes_key = recipient_public_key.encrypt(
                aes_key + iv, 
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            encrypted_image_b64 = base64.b64encode(encrypted_image).decode()
            encrypted_key_b64 = base64.b64encode(encrypted_aes_key).decode()
            
            combined = f"{encrypted_key_b64}|||{encrypted_image_b64}"
            
            return combined
        except Exception as e:
            print(f"Eroare criptare imagine: {e}")
            return None
    
    def decrypt_image(self, encrypted_combined):
        try:
            parts = encrypted_combined.split('|||', 1)
            if len(parts) != 2:
                return None
            
            encrypted_key_b64, encrypted_image_b64 = parts
            
            encrypted_key = base64.b64decode(encrypted_key_b64)
            aes_key_and_iv = self.private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            aes_key = aes_key_and_iv[:32]
            iv = aes_key_and_iv[32:]
            
            encrypted_image = base64.b64decode(encrypted_image_b64)
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            padded_data = decryptor.update(encrypted_image) + decryptor.finalize()

            padding_length = padded_data[-1]
            image_data = padded_data[:-padding_length]
            
            return image_data
        except Exception as e:
            print(f"Eroare decriptare imagine: {e}")
            return None
    
    def register(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            messagebox.showwarning("Eroare", "Completeaza toate campurile!")
            return
        
        if len(password) < 3:
            messagebox.showwarning("Eroare", "Parola trebuie sa aiba minim 3 caractere!")
            return
        
        try:
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            temp_socket.connect((HOST, PORT))

            temp_socket.sendall(f"REGISTER:{username}:{password}\n".encode())
            response = temp_socket.recv(1024).decode().strip()
            
            if response.startswith("REGISTER_OK"):
                messagebox.showinfo("Succes", "Cont creat! Acum te poti autentifica.")
                temp_socket.close()
            elif response.startswith("REGISTER_FAIL"):
                error_msg = response.split(":", 1)[1]
                messagebox.showerror("Eroare", error_msg)
                temp_socket.close()
        
        except Exception as e:
            messagebox.showerror("Eroare", "Nu se poate conecta la server")

    
    def show_messenger_screen(self):
        main_container = tk.Frame(self.root, bg="#f8f9fa")
        main_container.pack(fill=tk.BOTH, expand=True)
        
        left_panel = tk.Frame(main_container, bg="white", width=280, relief=tk.RIDGE, bd=1)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, padx=5, pady=5)
        left_panel.pack_propagate(False)
        
        header_frame = tk.Frame(left_panel, bg="#0a21ee", height=60)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        tk.Label(
            header_frame,
            text=f"{self.username}",
            font=("Arial", 13, "bold"),
            bg="#0a21ee",
            fg="white"
        ).pack(pady=15)
        
        search_frame = tk.Frame(left_panel, bg="white")
        search_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(
            search_frame,
            text="Selecteaza utilizator:",
            font=("Arial", 10),
            bg="white"
        ).pack(anchor="w")
        
        self.users_listbox = tk.Listbox(
            left_panel,
            font=("Arial", 11),
            bg="#b3b3b4",
            selectmode=tk.SINGLE,
            relief=tk.FLAT,
            highlightthickness=0
        )
        self.users_listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.users_listbox.bind('<<ListboxSelect>>', self.on_user_select)
        
        right_panel = tk.Frame(main_container, bg="white", relief=tk.RIDGE, bd=1)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.chat_header = tk.Frame(right_panel, bg="#0a21ee", height=60)
        self.chat_header.pack(fill=tk.X)
        self.chat_header.pack_propagate(False)
        
        self.chat_title = tk.Label(
            self.chat_header,
            text="Selecteaza o conversatie",
            font=("Arial", 14, "bold"),
            bg="#0a21ee",
            fg="white"
        )
        self.chat_title.pack(pady=15)
        
        messages_container = tk.Frame(right_panel, bg="white")
        messages_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.messages_area = scrolledtext.ScrolledText(
            messages_container,
            state='disabled',
            wrap=tk.WORD,
            font=("Arial", 10),
            bg="#afa8a2",
            relief=tk.FLAT
        )
        self.messages_area.pack(fill=tk.BOTH, expand=True)
        
        self.messages_area.tag_config("sent", justify="right", foreground="#005c4b", background="#d9fdd3", spacing1=5, spacing3=5, lmargin1=100, lmargin2=100)
        self.messages_area.tag_config("received", justify="left", foreground="black", background="white", spacing1=5, spacing3=5, rmargin=100)
        self.messages_area.tag_config("time_sent", justify="right", foreground="black", font=("Arial", 8), spacing3=10)
        self.messages_area.tag_config("time_received", justify="left", foreground="black", font=("Arial", 8), spacing3=10)
        
        input_frame = tk.Frame(right_panel, bg="white", height=60)
        input_frame.pack(fill=tk.X, padx=10, pady=10)
        input_frame.pack_propagate(False)
        
        self.message_entry = tk.Entry(
            input_frame,
            font=("Arial", 11),
            relief=tk.SOLID,
            bd=1
        )
        self.message_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        self.message_entry.bind('<Return>', lambda e: self.send_message())
        
        tk.Button(
            input_frame,
            text="🖼️",
            command=self.select_and_send_image,
            bg="#ffffff",
            fg="black",
            font=("Segoe UI Emoji", 16),
            cursor="hand2",
            relief=tk.FLAT,
            width=2,
            height=1
        ).pack(side=tk.RIGHT, padx=5)
        
        tk.Button(
            input_frame,
            text="😊",
            command=self.show_emoji_picker,
            bg="#ffd700",
            fg="black",
            font=("Arial", 14),
            cursor="hand2",
            relief=tk.FLAT,
            width=3
        ).pack(side=tk.RIGHT, padx=5)
        
        tk.Button(
            input_frame,
            text="Trimite",
            command=self.send_message,
            bg="#0a21ee",
            fg="white",
            font=("Arial", 10, "bold"),
            cursor="hand2",
            relief=tk.FLAT,
            width=12
        ).pack(side=tk.RIGHT)
        
        self.load_users_list()
    
    
    def start_receiving(self):
        self.running = True
        receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
        receive_thread.start()
    
    def receive_messages(self):
        buffer = ""
        
        while self.running:
            try:
                data = self.socket.recv(4096)
                if not data:
                    break
                
                buffer += data.decode()
                
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    message = line.strip()
                    
                    if not message:
                        continue
                    
                    if message.startswith("USERS_LIST:"):
                        users_json = message.split(":", 1)[1]
                        self.all_users = json.loads(users_json)
                        self.root.after(0, self.update_users_list)
                    
                    elif message.startswith("PUBLIC_KEY:"):
                        parts = message.split(":", 2)
                        if len(parts) == 3:
                            _, username, public_key_pem = parts
                            public_key_pem = public_key_pem.replace('\\n', '\n')
                            public_key = serialization.load_pem_public_key(
                                public_key_pem.encode(),
                                backend=default_backend()
                            )
                            self.public_keys_cache[username] = public_key
                    
                    elif message.startswith("HISTORY:"):
                        history_json = message.split(":", 1)[1]
                        history = json.loads(history_json)
                        self.root.after(0, lambda h=history: self.display_conversation_history(h))
                    
                    elif message.startswith("NEW_MSG:"):
                        parts = message.split(":", 3)
                        if len(parts) == 4:
                            _, sender, encrypted_msg, time = parts
                            
                            decrypted_msg = self.decrypt_message(encrypted_msg)
                            
                            if self.current_conversation == sender:
                                self.root.after(0, lambda m=decrypted_msg, t=time: self.add_message_to_chat(m, "received", t))
                    
                    elif message.startswith("NEW_IMAGE:"):
                        parts = message.split(":", 3)
                        if len(parts) == 4:
                            _, sender, encrypted_combined, time = parts
                            
                            image_bytes = self.decrypt_image(encrypted_combined)
                            
                            if image_bytes and self.current_conversation == sender:
                                self.root.after(0, lambda img=image_bytes, t=time: self.add_image_to_chat(img, "received", t))
            
            except Exception as e:
                if self.running:
                    print(f"Eroare primire: {e}")
                break
    
    def load_users_list(self):
        try:
            self.socket.sendall(b"GET_USERS\n")
        except Exception as e:
            messagebox.showerror("Eroare","Nu se poate încarca lista")
    
    def update_users_list(self):
        self.users_listbox.delete(0, tk.END)
        
        for user in self.all_users:
            if user != self.username:
                self.users_listbox.insert(tk.END, f"  {user}")
    
    def on_user_select(self, event):
        selection = self.users_listbox.curselection()
        if not selection:
            return
        
        selected_text = self.users_listbox.get(selection[0])
        username = selected_text.strip()
        
        self.current_conversation = username
        self.chat_title.config(text=f"Conversatie cu {username}")
        
        if username not in self.public_keys_cache:
            self.get_public_key(username)
        
        self.messages_area.config(state='normal')
        self.messages_area.delete(1.0, tk.END)
        self.messages_area.config(state='disabled')
        
        self.socket.sendall(f"GET_HISTORY:{username}\n".encode())
    
    def display_conversation_history(self, history):
        self.messages_area.config(state='normal')
        self.messages_area.delete(1.0, tk.END)
        
        if history:
            for msg in history:
                time = msg["timestamp"].split(" ")[1][:5] 
                msg_type = msg.get("type", "text")
                
                if msg_type == "image":
                    if msg["sender"] == self.username:
                        encrypted_combined = msg.get("image_sender", "")
                        image_bytes = self.decrypt_image(encrypted_combined)
                        if image_bytes:
                            self.add_image_to_chat(image_bytes, "sent", time)
                    else:
                        encrypted_combined = msg.get("image_receiver", "")
                        image_bytes = self.decrypt_image(encrypted_combined)
                        if image_bytes:
                            self.add_image_to_chat(image_bytes, "received", time)
                else:
                    if msg["sender"] == self.username:
                        encrypted_msg = msg.get("message_sender", msg.get("message", ""))
                        decrypted_msg = self.decrypt_message(encrypted_msg)
                        self.add_message_to_chat(decrypted_msg, "sent", time)
                    else:
                        encrypted_msg = msg.get("message_receiver", msg.get("message", ""))
                        decrypted_msg = self.decrypt_message(encrypted_msg)
                        self.add_message_to_chat(decrypted_msg, "received", time)
        
        self.messages_area.config(state='disabled')
        self.messages_area.see(tk.END)
    
    def add_message_to_chat(self, message, msg_type, time):
        self.messages_area.config(state='normal')
        
        if msg_type == "sent":
            self.messages_area.insert(tk.END, f"{message}\n", "sent")
            self.messages_area.insert(tk.END, f"{time}\n", "time_sent")
        elif msg_type == "received":
            self.messages_area.insert(tk.END, f"{message}\n", "received")
            self.messages_area.insert(tk.END, f"{time}\n", "time_received")
        
        self.messages_area.see(tk.END)
        self.messages_area.config(state='disabled')
    
    def send_message(self):
        if not self.current_conversation:
            messagebox.showwarning("Eroare", "Selecteaza un utilizator din lista!")
            return
        
        message_text = self.message_entry.get().strip()
        
        if not message_text:
            return
        
        if self.current_conversation not in self.public_keys_cache:
            messagebox.showwarning("Eroare", "La cheia de criptare")
            self.get_public_key(self.current_conversation)
            return
        
        encrypted_for_receiver = self.encrypt_message(message_text, self.current_conversation)
        
        if not encrypted_for_receiver:
            messagebox.showerror("Eroare", "Nu s-a criptat mesajul")
            return
        
        encrypted_for_sender = self.encrypt_message(message_text, self.username)
        
        if not encrypted_for_sender:
            messagebox.showerror("Eroare", "Nu s-a criptat mesajul")
            return
        
        try:
            self.socket.sendall(f"MSG:{self.current_conversation}:{encrypted_for_receiver}:{encrypted_for_sender}\n".encode())
            
            from datetime import datetime
            current_time = datetime.now().strftime("%H:%M")
            self.add_message_to_chat(message_text, "sent", current_time)
            
            self.message_entry.delete(0, tk.END)
        
        except Exception as e:
            messagebox.showerror("Eroare", f"Nu s-a trimis mesajul")
    
    def select_and_send_image(self):
        if not self.current_conversation:
            messagebox.showwarning("Eroare", "Selectează un utilizator din lista!")
            return
        
        if self.current_conversation not in self.public_keys_cache:
            messagebox.showwarning("Eroare", "Asteapta incarcarea cheii de criptare")
            self.get_public_key(self.current_conversation)
            return
        
        file_path = filedialog.askopenfilename(
            title="Selectează o imagine",
            filetypes=[
                ("Imagini", "*.png *.jpg *.jpeg *.gif *.bmp"),
                ("Toate fișierele", "*.*")
            ]
        )
        
        if not file_path:
            return
        
        try:
            img = Image.open(file_path)
            
            max_size = (800, 800)
            img.thumbnail(max_size, Image.Resampling.LANCZOS)
            
            img_byte_arr = io.BytesIO()
            img_format = img.format if img.format else 'PNG'
            img.save(img_byte_arr, format=img_format)
            image_bytes = img_byte_arr.getvalue()
            
            encrypted_for_receiver = self.encrypt_image(
                image_bytes, self.current_conversation
            )
            
            if not encrypted_for_receiver:
                messagebox.showerror("Eroare", "Nu s-a putut cripta imaginea")
                return
            
            encrypted_for_sender = self.encrypt_image(
                image_bytes, self.username
            )
            
            if not encrypted_for_sender:
                messagebox.showerror("Eroare", "Nu s-a putut cripta imaginea")
                return
            
            image_msg = f"IMAGE:{self.current_conversation}:{encrypted_for_receiver}:{encrypted_for_sender}\n"
            self.socket.sendall(image_msg.encode())
            
            from datetime import datetime
            current_time = datetime.now().strftime("%H:%M")
            self.add_image_to_chat(image_bytes, "sent", current_time)
            
        except Exception as e:
            messagebox.showerror("Eroare", f"Nu s-a putut trimite imaginea: {str(e)}")
    
    def add_image_to_chat(self, image_bytes, msg_type, time):
        try:
            self.messages_area.config(state='normal')
            
            img = Image.open(io.BytesIO(image_bytes))
            
            display_size = (300, 300)
            img.thumbnail(display_size, Image.Resampling.LANCZOS)
            
            photo = ImageTk.PhotoImage(img)
            

            if not hasattr(self, 'image_references'):
                self.image_references = []
            self.image_references.append(photo)
            
            if msg_type == "sent":
                self.messages_area.insert(tk.END, "\n")
                self.messages_area.image_create(tk.END, image=photo)
                self.messages_area.insert(tk.END, "\n")
                self.messages_area.insert(tk.END, f"{time}\n", "time_sent")
            else:
                self.messages_area.insert(tk.END, "\n")
                self.messages_area.image_create(tk.END, image=photo)
                self.messages_area.insert(tk.END, "\n")
                self.messages_area.insert(tk.END, f"{time}\n", "time_received")
            
            self.messages_area.see(tk.END)
            self.messages_area.config(state='disabled')
            
        except Exception as e:
            print(f"Eroare afișare imagine: {e}")
    
    def show_emoji_picker(self):
        emoji_window = tk.Toplevel(self.root)
        emoji_window.title("Selecteaza Emoji")
        emoji_window.geometry("340x220")
        emoji_window.configure(bg="#f0f0f0")
        emoji_window.transient(self.root)
        emoji_window.resizable(False, False)
        

        emoji_list = [
            "😀", "😃", "😄", "😁", "😆", "😂", "🤣", "😊", "😇", "🙂",
            "😉", "😍", "🥰", "😘", "😗", "😋", "😛", "😜", "🤪", "😎",
            "🤗", "🤔", "🤨", "😐", "😑", "😶", "🙄", "😬", "😌", "😔",
            "😢", "😭", "😤", "😠", "😡", "🤬", "😱", "😨", "😰", "😳",
        ]
        
        frame = tk.Frame(emoji_window, bg="#f0f0f0")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        row = 0
        col = 0
        for em in emoji_list:
            btn = tk.Button(
                frame,
                text=em,
                font=("Segoe UI Emoji", 16),
                command=lambda e=em, w=emoji_window: self.insert_emoji(e, w),
                relief=tk.FLAT,
                bg="#ffffff",
                activebackground="#e0e0e0",
                cursor="hand2",
                width=2,
                height=1,
                bd=0
            )
            btn.grid(row=row, column=col, padx=1, pady=1)
            
            col += 1
            if col >= 10:
                col = 0
                row += 1
    
    def insert_emoji(self, emoji_char, emoji_window):
        current_text = self.message_entry.get()
        cursor_position = self.message_entry.index(tk.INSERT)
        
        new_text = current_text[:cursor_position] + emoji_char + current_text[cursor_position:]
        
        self.message_entry.delete(0, tk.END)
        self.message_entry.insert(0, new_text)
        self.message_entry.icursor(cursor_position + len(emoji_char))
        
        self.message_entry.focus_set()
        emoji_window.destroy()
    
    def on_closing(self):
        self.running = False
        if self.socket:
            self.socket.close()
        self.root.destroy()
    
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    client = MessengerClient()
    client.run()
