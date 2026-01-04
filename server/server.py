import socket
import threading
import json
import os
from datetime import datetime

HOST = '127.0.0.1'
PORT = 12345

clients = {}
lock = threading.Lock()

USERS_FILE = "users.json"
MESSAGES_FILE = "messages.json"


def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, indent=4, ensure_ascii=False)

def load_messages():
    if os.path.exists(MESSAGES_FILE):
        with open(MESSAGES_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def save_message(sender, receiver, message_text):
    messages = load_messages()
    
    new_message = {
        "sender": sender,
        "receiver": receiver,
        "message": message_text,
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
    
    users[username] = {
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
        
        while True:
            data = conn.recv(1024)
            if not data:
                break
            
            message = data.decode().strip()
            
            if message.startswith("GET_HISTORY:"):
                other_user = message.split(":", 1)[1]
                history = get_conversation_history(username, other_user)
                conn.sendall(f"HISTORY:{json.dumps(history)}\n".encode())
            
            elif message.startswith("MSG:"):
                parts = message.split(":", 2)
                if len(parts) == 3:
                    _, recipient, msg_text = parts
                    
                    save_message(username, recipient, msg_text)
                    
                    with lock:
                        if recipient in clients:
                            forward_msg = f"NEW_MSG:{username}:{msg_text}:{datetime.now().strftime('%H:%M')}\n"
                            clients[recipient].sendall(forward_msg.encode())
                    
                    conn.sendall(b"MSG_SENT:OK\n")
            
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
