import socket

HOST = '127.0.0.1'
PORT = 12345

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        client_id = s.recv(1024).decode()
        print(f"Connected to server. {client_id}")
        while True:
            msg = input("Message (or 'exit'): ")
            if msg == 'exit':
                break
            s.sendall(msg.encode())
            data = s.recv(1024)
            print(f"Echo: {data.decode()}")

if __name__ == "__main__":
    main()
