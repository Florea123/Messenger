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
    conn.sendall(f"Id:{client_id}".encode())
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            message = data.decode()
            
            if message.startswith("Msg:"):
                parts = message.split(":", 2)
                if len(parts) == 3:
                    _, recipient_id_str, msg_text = parts
                    try:
                        recipient_id = int(recipient_id_str)
                        with lock:
                            if recipient_id in clients:
                                forward_msg = f"From:{client_id}:{msg_text}"
                                clients[recipient_id].sendall(forward_msg.encode())
                                print(f"{msg_text}")
                            else:
                                conn.sendall(f"Error:Client {recipient_id} not found".encode())
                    except ValueError:
                        conn.sendall(b"Error:Invalid recipient ID")
                else:
                    conn.sendall(b"Error:Invalid message format")
    except Exception as e:
        pass 
    finally:
        with lock:
            del clients[client_id]
        conn.close()
        print(f"Client {client_id} disconnected")

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server running")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start_server()
