import customtkinter as ctk
import os
import subprocess
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from PIL import Image
import pystray
from pystray import MenuItem as item
from tkinter import filedialog, messagebox

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SQL Monitor Pro - Enterprise Edition")
        self.geometry("800x750")
        self.protocol('WM_DELETE_WINDOW', self.hide_window)

        # --- Variables ---
        self.watch_dir = ctk.StringVar(value=r"C:\Program Files\ISS3000_MBranchClient\MBranchClient_KA\Archive\SUCCESS")
        self.sql_file_path = ctk.StringVar(value=os.path.abspath("STP_FTH_POSAPICenter_UpdateBBYDuringTheDay.sql"))
        
        # Database Variables
        self.db_server = ctk.StringVar(value=".")
        self.db_name = ctk.StringVar(value="POSSDB_KA")
        self.db_user = ctk.StringVar(value="sa")
        self.db_pass = ctk.StringVar()
        self.auth_mode = ctk.StringVar(value="Windows") # Windows or SQL
        
        self.observer = None

        # --- UI Setup ---
        self.scroll_frame = ctk.CTkScrollableFrame(self, width=750, height=500)
        self.scroll_frame.pack(pady=10, padx=10, fill="both", expand=True)

        self.label = ctk.CTkLabel(self.scroll_frame, text="System Configuration", font=("Arial", 22, "bold"))
        self.label.pack(pady=10)

        # Section: Paths
        self.create_header(self.scroll_frame, "📁 Path Configuration")
        self.create_path_selector(self.scroll_frame, "JSON Folder:", self.watch_dir, self.browse_folder)
        self.create_path_selector(self.scroll_frame, "SQL Script:", self.sql_file_path, self.browse_sql_file)

        # Section: Database
        self.create_header(self.scroll_frame, "🖥️ Database Connection")
        self.db_frame = ctk.CTkFrame(self.scroll_frame)
        self.db_frame.pack(pady=5, padx=20, fill="x")

        self.create_input(self.db_frame, "Server:", self.db_server)
        self.create_input(self.db_frame, "Database:", self.db_name)
        
        self.auth_switch = ctk.CTkSegmentedButton(self.db_frame, values=["Windows", "SQL Server"], 
                                                 variable=self.auth_mode, command=self.toggle_auth)
        self.auth_switch.pack(pady=10)

        self.user_entry = self.create_input(self.db_frame, "Username:", self.db_user)
        self.pass_entry = self.create_input(self.db_frame, "Password:", self.db_pass, show="*")
        self.toggle_auth(self.auth_mode.get()) # Init state

        # Log Box (Fixed at bottom)
        self.log_box = ctk.CTkTextbox(self, width=760, height=150)
        self.log_box.pack(pady=10, padx=20)

        # Control
        self.btn_start = ctk.CTkButton(self, text="Start Monitoring", fg_color="#28a745", 
                                       command=self.toggle_monitoring, height=40, font=("Arial", 14, "bold"))
        self.btn_start.pack(pady=10)

    def create_header(self, parent, text):
        lbl = ctk.CTkLabel(parent, text=text, font=("Arial", 14, "bold"), text_color="orange")
        lbl.pack(anchor="w", padx=25, pady=(15, 5))

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

    def browse_folder(self):
        selected = filedialog.askdirectory()
        if selected: self.watch_dir.set(selected)

    def browse_sql_file(self):
        selected = filedialog.askopenfilename(filetypes=[("SQL files", "*.sql")])
        if selected: self.sql_file_path.set(selected)

    def add_log(self, message):
        self.log_box.insert("end", f"> {message}\n")
        self.log_box.see("end")

    def toggle_monitoring(self):
        if self.observer and self.observer.is_alive():
            self.stop_monitoring()
        else:
            self.start_monitoring()

    def start_monitoring(self):
        if not os.path.exists(self.watch_dir.get()):
            messagebox.showerror("Error", "Invalid JSON Folder Path")
            return
        
        event_handler = Handler(self.run_sql)
        self.observer = Observer()
        self.observer.schedule(event_handler, self.watch_dir.get(), recursive=False)
        self.observer.start()
        
        self.btn_start.configure(text="Stop Monitoring", fg_color="#dc3545")
        self.add_log("[SYSTEM] Monitoring Started...")

    def stop_monitoring(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
        self.btn_start.configure(text="Start Monitoring", fg_color="#28a745")
        self.add_log("[SYSTEM] Monitoring Stopped.")

    def run_sql(self, filename):
        self.add_log(f"[EVENT] New File: {filename}")
        
        # Build sqlcmd Command
        cmd = ["sqlcmd", "-S", self.db_server.get(), "-d", self.db_name.get()]
        
        if self.auth_mode.get() == "Windows":
            cmd.append("-E")
        else:
            cmd.extend(["-U", self.db_user.get(), "-P", self.db_pass.get()])
            
        cmd.extend(["-i", self.sql_file_path.get()])
        
        try:
            # ใช้ shell=True เพื่อช่วยแก้ปัญหา WinError 2 ในบางระบบ
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, shell=True)
            self.add_log(f"[SUCCESS] SQL Executed for {filename}")
        except subprocess.CalledProcessError as e:
            self.add_log(f"[SQL ERROR] {e.stderr}")
        except Exception as e:
            self.add_log(f"[CRITICAL ERROR] {str(e)}")

    def hide_window(self):
        self.withdraw()
        image = Image.new('RGB', (64, 64), color=(0, 123, 255))
        menu = (item('Show', lambda i, j: self.after(0, self.deiconify) or i.stop()), item('Quit', lambda i, j: self.destroy() or i.stop()))
        icon = pystray.Icon("SQL_Monitor", image, "SQL Monitor", menu)
        threading.Thread(target=icon.run, daemon=True).start()

class Handler(FileSystemEventHandler):
    def __init__(self, callback): self.callback = callback
    def on_created(self, event):
        if not event.is_directory and event.src_path.lower().endswith(".json"):
            self.callback(os.path.basename(event.src_path))

if __name__ == "__main__":
    app = App()
    app.mainloop()
