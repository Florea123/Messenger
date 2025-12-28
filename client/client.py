import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox

HOST = '127.0.0.1'
PORT = 12345

class MessengerClient:
    def __init__(self):
        self.socket = None
        self.client_id = None
        self.running = False
        self.root = tk.Tk()
        self.root.title("Messenger")
        self.root.geometry("600x600")
        
        self.root.grid_rowconfigure(1, weight=1)  
        self.root.grid_columnconfigure(0, weight=1)
        
        tk.Label(self.root, text="Messages:", font=("Arial", 10)).grid(row=0, column=0, pady=5, sticky="w", padx=10)
        
        self.messages_area = scrolledtext.ScrolledText(self.root, state='disabled', wrap=tk.WORD)
        self.messages_area.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")
        
        recipient_frame = tk.Frame(self.root)
        recipient_frame.grid(row=2, column=0, pady=5, sticky="ew")
        recipient_frame.grid_columnconfigure(1, weight=1)
        
        tk.Label(recipient_frame, text="Recipient Id:").grid(row=0, column=0, padx=5, sticky="w")
        self.recipient_entry = tk.Entry(recipient_frame)
        self.recipient_entry.grid(row=0, column=1, padx=5, sticky="ew")
        
        message_frame = tk.Frame(self.root)
        message_frame.grid(row=3, column=0, pady=5, sticky="ew")
        message_frame.grid_columnconfigure(1, weight=1)
        
        tk.Label(message_frame, text="Message:").grid(row=0, column=0, padx=5, sticky="w")
        self.message_entry = tk.Entry(message_frame)
        self.message_entry.grid(row=0, column=1, padx=5, sticky="ew")
        self.message_entry.bind('<Return>', lambda e: self.send_message())
        
        self.send_button = tk.Button(message_frame, text="Send", command=self.send_message, bg="#1FA324", fg="white")
        self.send_button.grid(row=0, column=2, padx=5)
        
        self.exit_button = tk.Button(self.root, text="Exit", command=self.on_closing, bg="#af1b10", fg="white")
        self.exit_button.grid(row=4, column=0, pady=10)
        
        self.connect_to_server()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def connect_to_server(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((HOST, PORT))
            
            id_msg = self.socket.recv(1024).decode()
            if id_msg.startswith("Id:"):
                self.client_id = id_msg.split(":")[1]
                self.add_message(f"Connected to server with ID: {self.client_id}", "SYSTEM")
            
            self.running = True
            receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            receive_thread.start()
            
        except Exception as e:
            messagebox.showerror("Connection Error", f"Could not connect to server: {e}")
            self.root.quit()
    
    def receive_messages(self):
        while self.running:
            try:
                data = self.socket.recv(1024)
                if not data:
                    break
                
                message = data.decode()
                
                if message.startswith("From:"):
                    parts = message.split(":", 2)
                    if len(parts) == 3:
                        _, sender_id, msg_text = parts
                        self.add_message(f"From Client {sender_id}: {msg_text}", "RECEIVED")
                elif message.startswith("Error:"):
                    error_msg = message.split(":", 1)[1]
                    self.add_message(f"Error: {error_msg}", "ERROR")
                    
            except Exception as e:
                if self.running:
                    self.add_message(f"Connection error: {e}", "ERROR")
                break
        
        if self.running:
            self.add_message("Disconnected from server", "SYSTEM")
    
    def send_message(self):
        recipient_id = self.recipient_entry.get().strip()
        message_text = self.message_entry.get().strip()
        
        if not recipient_id:
            messagebox.showwarning("Invalid Input", "Please enter a recipient ID")
            return
        
        if not message_text:
            messagebox.showwarning("Invalid Input", "Please enter a message")
            return
        
        try:
            msg = f"Msg:{recipient_id}:{message_text}"
            self.socket.sendall(msg.encode())
            self.add_message(f"To Client {recipient_id}: {message_text}", "SENT")
            self.message_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Send Error", f"Failed to send message: {e}")
    
    def add_message(self, message, msg_type):
        self.messages_area.config(state='normal')
        
        if msg_type == "SYSTEM":
            self.messages_area.insert(tk.END, f"[SYSTEM] {message}\n", "system")
            self.messages_area.tag_config("system", foreground="blue")
        elif msg_type == "SENT":
            self.messages_area.insert(tk.END, f"[SENT] {message}\n", "sent")
            self.messages_area.tag_config("sent", foreground="green")
        elif msg_type == "RECEIVED":
            self.messages_area.insert(tk.END, f"[RECEIVED] {message}\n", "received")
            self.messages_area.tag_config("received", foreground="purple")
        elif msg_type == "ERROR":
            self.messages_area.insert(tk.END, f"[ERROR] {message}\n", "error")
            self.messages_area.tag_config("error", foreground="red")
        else:
            self.messages_area.insert(tk.END, f"{message}\n")
        
        self.messages_area.see(tk.END)
        self.messages_area.config(state='disabled')
    
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
