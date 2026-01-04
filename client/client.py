import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
import json

HOST = '127.0.0.1'
PORT = 12345

class MessengerClient:
    def __init__(self):
        self.socket = None
        self.username = None
        self.running = False
        self.current_conversation = None 
        self.all_users = [] 
        
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
                self.login_frame.destroy()
                self.show_messenger_screen()
                self.start_receiving()
            elif response.startswith("LOGIN_FAIL"):
                error_msg = response.split(":", 1)[1]
                messagebox.showerror("Eroare", error_msg)
                self.socket.close()
        
        except Exception as e:
            messagebox.showerror("Eroare", "Nu se poate conecta la server")
    
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
        self.messages_area.tag_config("time_sent", justify="right", foreground="gray", font=("Arial", 8), spacing3=10)
        self.messages_area.tag_config("time_received", justify="left", foreground="gray", font=("Arial", 8), spacing3=10)
        
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
                    
                    elif message.startswith("HISTORY:"):
                        history_json = message.split(":", 1)[1]
                        history = json.loads(history_json)
                        self.root.after(0, lambda h=history: self.display_conversation_history(h))
                    
                    elif message.startswith("NEW_MSG:"):
                        parts = message.split(":", 3)
                        if len(parts) == 4:
                            _, sender, msg_text, time = parts
                            
                            if self.current_conversation == sender:
                                self.root.after(0, lambda m=msg_text, t=time: self.add_message_to_chat(m, "received", t))
            
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
                
                if msg["sender"] == self.username:
                    self.add_message_to_chat(msg["message"], "sent", time)
                else:
                    self.add_message_to_chat(msg["message"], "received", time)
        
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
        
        try:
            self.socket.sendall(f"MSG:{self.current_conversation}:{message_text}\n".encode())
            
            from datetime import datetime
            current_time = datetime.now().strftime("%H:%M")
            self.add_message_to_chat(message_text, "sent", current_time)
            
            self.message_entry.delete(0, tk.END)
        
        except Exception as e:
            messagebox.showerror("Eroare", f"Nu s-a putut trimite mesajul:\n{e}")
    
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
