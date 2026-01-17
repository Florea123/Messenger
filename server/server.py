import socket
import threading
import json
import os
import uuid
from datetime import datetime

HOST = '127.0.0.1'
PORT = 12345

clients = {}
lock = threading.Lock()

INFO_DIR = "info"
USERS_FILE = os.path.join(INFO_DIR, "users.json")
MESSAGES_FILE = os.path.join(INFO_DIR, "messages.json")
PUBLIC_KEYS_FILE = os.path.join(INFO_DIR, "public_keys.json")

if not os.path.exists(INFO_DIR):
    os.makedirs(INFO_DIR)


def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, indent=4, ensure_ascii=False)

def load_public_keys():
    if os.path.exists(PUBLIC_KEYS_FILE):
        with open(PUBLIC_KEYS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_public_key(username, public_key_pem):
    keys = load_public_keys()
    keys[username] = public_key_pem
    with open(PUBLIC_KEYS_FILE, 'w', encoding='utf-8') as f:
        json.dump(keys, f, indent=4, ensure_ascii=False)

def get_public_key(username):
    keys = load_public_keys()
    return keys.get(username, None)

def load_messages():
    if os.path.exists(MESSAGES_FILE):
        with open(MESSAGES_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def save_message(sender, receiver, encrypted_for_receiver, encrypted_for_sender):
    messages = load_messages()
    
    new_message = {
        "type": "text",
        "sender": sender,
        "receiver": receiver,
        "message_receiver": encrypted_for_receiver,
        "message_sender": encrypted_for_sender,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    messages.append(new_message)
    
    with open(MESSAGES_FILE, 'w', encoding='utf-8') as f:
        json.dump(messages, f, indent=4, ensure_ascii=False)

def save_image_message(sender, receiver, encrypted_for_receiver, encrypted_for_sender):
    messages = load_messages()
    
    new_message = {
        "type": "image",
        "sender": sender,
        "receiver": receiver,
        "image_receiver": encrypted_for_receiver,
        "image_sender": encrypted_for_sender,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    messages.append(new_message)
    
    with open(MESSAGES_FILE, 'w', encoding='utf-8') as f:
        json.dump(messages, f, indent=4, ensure_ascii=False)


def get_conversation_history(user1, user2):
    messages = load_messages()
    
    conversation = [
        msg for msg in messages
        if (msg["sender"] == user1 and msg["receiver"] == user2) or
           (msg["sender"] == user2 and msg["receiver"] == user1)
    ]
    
    return conversation


def broadcast_users_list():
    users_list = get_all_users()
    message = f"USERS_LIST:{json.dumps(users_list)}\n".encode()
    
    with lock:
        for username, conn in clients.items():
            try:
                conn.sendall(message)
            except:
                pass

def register_user(username, password):
    users = load_users()
    
    if username in users:
        return False, "Username-ul există deja!"
    
    existing_ids = {user_data["id"] for user_data in users.values() if "id" in user_data}
    
    while True:
        user_id = str(uuid.uuid4())
        if user_id not in existing_ids:
            break
    
    users[username] = {
        "id": user_id,
        "password": password,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    save_users(users)
    
    broadcast_users_list()
    
    return True, "Cont creat cu succes!"

def login_user(username, password):
    users = load_users()
    
    if username not in users:
        return False, "Username-ul nu există!"
    
    if users[username]["password"] != password:
        return False, "Parolă incorectă!"
    
    return True, "Autentificare reușită!"

def get_all_users():
    users = load_users()
    return list(users.keys())


def handle_client(conn, addr):
    username = None
    
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                return
            
            message = data.decode().strip()
            
            if message.startswith("REGISTER:"):
                parts = message.split(":", 2)
                if len(parts) == 3:
                    _, user, pwd = parts
                    success, msg = register_user(user, pwd)
                    if success:
                        conn.sendall(f"REGISTER_OK:{msg}\n".encode())
                    else:
                        conn.sendall(f"REGISTER_FAIL:{msg}\n".encode())
            
            elif message.startswith("LOGIN:"):
                parts = message.split(":", 2)
                if len(parts) == 3:
                    _, user, pwd = parts
                    success, msg = login_user(user, pwd)
                    if success:
                        with lock:
                            if user in clients:
                                conn.sendall(b"LOGIN_FAIL:Utilizatorul este deja conectat!\n")
                                continue
                            
                            clients[user] = conn
                            username = user
                        
                        conn.sendall(f"LOGIN_OK:{user}\n".encode())
                        
                        broadcast_users_list()
                        break
                    else:
                        conn.sendall(f"LOGIN_FAIL:{msg}\n".encode())
        
        users_list = get_all_users()
        conn.sendall(f"USERS_LIST:{json.dumps(users_list)}\n".encode())
        
        buffer = ""
        while True:
            data = conn.recv(8192) 
            if not data:
                break
            
            buffer += data.decode()
            
            while '\n' in buffer:
                message, buffer = buffer.split('\n', 1)
                message = message.strip()
                
                if not message:
                    continue
            
                if message.startswith("GET_HISTORY:"):
                    other_user = message.split(":", 1)[1]
                    history = get_conversation_history(username, other_user)
                    conn.sendall(f"HISTORY:{json.dumps(history)}\n".encode())
                
                elif message.startswith("SEND_PUBLIC_KEY:"):
                    public_key_pem = message.split(":", 1)[1]
                    save_public_key(username, public_key_pem)
                    conn.sendall(b"PUBLIC_KEY_SAVED\n")
                
                elif message.startswith("GET_PUBLIC_KEY:"):
                    requested_user = message.split(":", 1)[1]
                    public_key = get_public_key(requested_user)
                    if public_key:
                        conn.sendall(f"PUBLIC_KEY:{requested_user}:{public_key}\n".encode())
                    else:
                        conn.sendall(f"PUBLIC_KEY_NOT_FOUND:{requested_user}\n".encode())
                
                elif message.startswith("MSG:"):
                    parts = message.split(":", 3)
                    if len(parts) == 4:
                        _, recipient, encrypted_for_receiver, encrypted_for_sender = parts
                        
                        save_message(username, recipient, encrypted_for_receiver, encrypted_for_sender)
                        
                        with lock:
                            if recipient in clients:
                                forward_msg = f"NEW_MSG:{username}:{encrypted_for_receiver}:{datetime.now().strftime('%H:%M')}\n"
                                clients[recipient].sendall(forward_msg.encode())
                        
                        conn.sendall(b"MSG_SENT:OK\n")
                
                elif message.startswith("IMAGE:"):
                    parts = message.split(":", 3)
                    if len(parts) == 4:
                        _, recipient, encrypted_for_receiver, encrypted_for_sender = parts
                        
                        save_image_message(username, recipient, encrypted_for_receiver, encrypted_for_sender)
                        
                        with lock:
                            if recipient in clients:
                                forward_msg = f"NEW_IMAGE:{username}:{encrypted_for_receiver}:{datetime.now().strftime('%H:%M')}\n"
                                clients[recipient].sendall(forward_msg.encode())
                        
                        conn.sendall(b"IMAGE_SENT:OK\n")
                
                elif message == "GET_USERS":
                    users_list = get_all_users()
                    conn.sendall(f"USERS_LIST:{json.dumps(users_list)}\n".encode())
    
    except Exception as e:
        print(f"{username} s-a deconectat!")
    
    finally:
        if username:
            with lock:
                if username in clients:
                    del clients[username]
            
            broadcast_users_list()
        
        conn.close()

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    print("Running")
    start_server()
