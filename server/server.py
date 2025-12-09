import socket
import threading

HOST = '127.0.0.1'
PORT = 12345

clients = {}
next_id = 1
lock = threading.Lock()

def handle_client(conn, addr):
    global next_id
    with lock:
        client_id = next_id
        next_id += 1
        clients[client_id] = conn
    print(f"Client {client_id} connected from {addr}")
    conn.sendall(f"ID:{client_id}".encode())
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            conn.sendall(data)
    finally:
        with lock:
            del clients[client_id]
        conn.close()
        print(f"Client {client_id} disconnected")

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server running on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start_server()
