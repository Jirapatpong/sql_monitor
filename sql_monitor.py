import customtkinter as ctk
import os
import subprocess
import threading
import json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from PIL import Image
import pystray
from pystray import MenuItem as item
from tkinter import filedialog, messagebox

CONFIG_FILE = "config.json"

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SQL Monitor Pro - Enterprise Edition")
        self.geometry("800x800")
        self.protocol('WM_DELETE_WINDOW', self.hide_window)

        # --- Variables (Default values) ---
        self.config_data = {
            "watch_dir": r"C:\Program Files\ISS3000_MBranchClient\MBranchClient_KA\Archive\SUCCESS",
            "sql_file": os.path.abspath("STP_FTH_POSAPICenter_UpdateBBYDuringTheDay.sql"),
            "server": "172.16.26.18",
            "db_name": "POSSDB_KA",
            "user": "sa",
            "auth_mode": "SQL Server"
        }
        self.load_settings()

        self.watch_dir = ctk.StringVar(value=self.config_data["watch_dir"])
        self.sql_file_path = ctk.StringVar(value=self.config_data["sql_file"])
        self.db_server = ctk.StringVar(value=self.config_data["server"])
        self.db_name = ctk.StringVar(value=self.config_data["db_name"])
        self.db_user = ctk.StringVar(value=self.config_data["user"])
        self.db_pass = ctk.StringVar()
        self.auth_mode = ctk.StringVar(value=self.config_data["auth_mode"])
        
        self.observer = None

        # --- UI Setup ---
        self.scroll_frame = ctk.CTkScrollableFrame(self, width=750, height=550)
        self.scroll_frame.pack(pady=10, padx=10, fill="both", expand=True)

        # Paths
        self.create_header(self.scroll_frame, "📁 Path Configuration")
        self.create_path_selector(self.scroll_frame, "JSON Folder:", self.watch_dir, self.browse_folder)
        self.create_path_selector(self.scroll_frame, "SQL Script:", self.sql_file_path, self.browse_sql_file)

        # Database
        self.create_header(self.scroll_frame, "🖥️ Database Connection")
        self.db_frame = ctk.CTkFrame(self.scroll_frame)
        self.db_frame.pack(pady=5, padx=20, fill="x")

        self.create_input(self.db_frame, "Server IP:", self.db_server)
        self.create_input(self.db_frame, "Database:", self.db_name)
        
        self.auth_switch = ctk.CTkSegmentedButton(self.db_frame, values=["Windows", "SQL Server"], 
                                                 variable=self.auth_mode, command=self.toggle_auth)
        self.auth_switch.pack(pady=10)

        self.user_entry = self.create_input(self.db_frame, "Username:", self.db_user)
        self.pass_entry = self.create_input(self.db_frame, "Password:", self.db_pass, show="*")
        self.toggle_auth(self.auth_mode.get())

        # Buttons
        btn_row = ctk.CTkFrame(self.db_frame, fg_color="transparent")
        btn_row.pack(pady=15)
        ctk.CTkButton(btn_row, text="Test Connection", fg_color="#17a2b8", command=self.test_connection).pack(side="left", padx=5)
        ctk.CTkButton(btn_row, text="Save Config", fg_color="#6c757d", command=self.save_settings).pack(side="left", padx=5)

        self.log_box = ctk.CTkTextbox(self, width=760, height=150)
        self.log_box.pack(pady=10, padx=20)

        self.btn_start = ctk.CTkButton(self, text="Start Monitoring", fg_color="#28a745", 
                                       command=self.toggle_monitoring, height=40, font=("Arial", 14, "bold"))
        self.btn_start.pack(pady=10)

    # --- Settings Logic ---
    def save_settings(self):
        data = {
            "watch_dir": self.watch_dir.get(),
            "sql_file": self.sql_file_path.get(),
            "server": self.db_server.get(),
            "db_name": self.db_name.get(),
            "user": self.db_user.get(),
            "auth_mode": self.auth_mode.get()
        }
        with open(CONFIG_FILE, "w") as f:
            json.dump(data, f)
        self.add_log("[SYSTEM] Settings saved to config.json")
        messagebox.showinfo("Saved", "Configuration saved successfully!")

    def load_settings(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as f:
                    self.config_data.update(json.load(f))
            except: pass

    # --- UI Helpers ---
    def create_header(self, parent, text):
        ctk.CTkLabel(parent, text=text, font=("Arial", 14, "bold"), text_color="orange").pack(anchor="w", padx=25, pady=(15, 5))

    def create_path_selector(self, parent, label_text, variable, command):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.pack(pady=2, padx=20, fill="x")
        ctk.CTkLabel(frame, text=label_text).pack(anchor="w", padx=10)
        inner = ctk.CTkFrame(frame, fg_color="transparent")
        inner.pack(fill="x")
        ctk.CTkEntry(inner, textvariable=variable, width=550).pack(side="left", padx=10)
        ctk.CTkButton(inner, text="Browse", width=80, command=command).pack(side="left")

    def create_input(self, parent, label_text, variable, show=""):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.pack(pady=2, padx=10, fill="x")
        ctk.CTkLabel(frame, text=label_text, width=100, anchor="w").pack(side="left", padx=5)
        entry = ctk.CTkEntry(frame, textvariable=variable, show=show, width=450)
        entry.pack(side="left", padx=5, pady=2)
        return entry

    def toggle_auth(self, mode):
        state = "normal" if mode == "SQL Server" else "disabled"
        self.user_entry.configure(state=state)
        self.pass_entry.configure(state=state)

    def add_log(self, message):
        self.log_box.insert("end", f"> {message}\n")
        self.log_box.see("end")

    # --- Execution Logic ---
    def get_sql_cmd(self, extra_args=None):
        cmd = ["sqlcmd", "-S", self.db_server.get(), "-d", self.db_name.get()]
        if self.auth_mode.get() == "Windows": cmd.append("-E")
        else: cmd.extend(["-U", self.db_user.get(), "-P", self.db_pass.get()])
        if extra_args: cmd.extend(extra_args)
        return cmd

    def test_connection(self):
        self.add_log("[DB] Testing connection...")
        cmd = self.get_sql_cmd(["-Q", "SELECT 1"])
        try:
            # ใช้ shell=True และรวม stderr เข้ามาเพื่อให้เห็น Error จริง
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, shell=True)
            self.add_log("[SUCCESS] Connection OK!")
            messagebox.showinfo("Success", "Connection established!")
        except subprocess.CalledProcessError as e:
            msg = e.stdout + e.stderr
            self.add_log(f"[DB ERROR] {msg.strip()}")
            messagebox.showerror("Error", f"Failed: {msg.strip()}")

    def run_sql(self, filename):
        self.add_log(f"[EVENT] New File: {filename}")
        cmd = self.get_sql_cmd(["-i", self.sql_file_path.get()])
        try:
            subprocess.run(cmd, capture_output=True, text=True, check=True, shell=True)
            self.add_log(f"[SUCCESS] SQL Executed for {filename}")
        except subprocess.CalledProcessError as e:
            # ดึง Error จริงจาก SQL Server มาแสดง
            self.add_log(f"[SQL ERROR] {e.stdout} {e.stderr}")

    def toggle_monitoring(self):
        if self.observer and self.observer.is_alive():
            self.observer.stop()
            self.btn_start.configure(text="Start Monitoring", fg_color="#28a745")
            self.add_log("[SYSTEM] Monitoring Stopped.")
        else:
            if not os.path.exists(self.watch_dir.get()):
                messagebox.showerror("Error", "Invalid Folder Path")
                return
            event_handler = Handler(self.run_sql)
            self.observer = Observer()
            self.observer.schedule(event_handler, self.watch_dir.get(), recursive=False)
            self.observer.start()
            self.btn_start.configure(text="Stop Monitoring", fg_color="#dc3545")
            self.add_log("[SYSTEM] Monitoring Started...")

    def hide_window(self):
        self.withdraw()
        image = Image.new('RGB', (64, 64), color=(0, 123, 255))
        menu = (item('Show', lambda i, j: self.after(0, self.deiconify) or i.stop()), item('Quit', lambda i, j: self.destroy() or i.stop()))
        icon = pystray.Icon("SQL_Monitor", image, "SQL Monitor", menu)
        threading.Thread(target=icon.run, daemon=True).start()

    def browse_folder(self):
        selected = filedialog.askdirectory()
        if selected: self.watch_dir.set(selected)

    def browse_sql_file(self):
        selected = filedialog.askopenfilename(filetypes=[("SQL files", "*.sql")])
        if selected: self.sql_file_path.set(selected)

class Handler(FileSystemEventHandler):
    def __init__(self, callback): self.callback = callback
    def on_created(self, event):
        if not event.is_directory and event.src_path.lower().endswith(".json"):
            self.callback(os.path.basename(event.src_path))

if __name__ == "__main__":
    app = App()
    app.mainloop()
