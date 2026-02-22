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
        self.title("SQL Monitor Pro - Configurable Edition")
        self.geometry("700x550")
        self.protocol('WM_DELETE_WINDOW', self.hide_window)

        # --- Variables (Paths) ---
        self.watch_dir = ctk.StringVar(value=r"C:\Program Files\ISS3000_MBranchClient\MBranchClient_KA\Archive\SUCCESS")
        self.sql_file_path = ctk.StringVar(value=os.path.abspath("STP_FTH_POSAPICenter_UpdateBBYDuringTheDay.sql"))
        self.observer = None

        # --- UI Setup ---
        self.label = ctk.CTkLabel(self, text="SQL Monitoring Configuration", font=("Arial", 22, "bold"))
        self.label.pack(pady=20)

        # Section 1: JSON Folder Monitoring
        self.create_path_selector("JSON Monitoring Folder:", self.watch_dir, self.browse_folder)

        # Section 2: SQL Script Path
        self.create_path_selector("SQL Script File (.sql):", self.sql_file_path, self.browse_sql_file)

        # Log Box
        self.log_box = ctk.CTkTextbox(self, width=650, height=180)
        self.log_box.pack(pady=15, padx=20)

        # Control Buttons
        self.btn_start = ctk.CTkButton(self, text="Start Monitoring", fg_color="#28a745", hover_color="#218838", 
                                       command=self.toggle_monitoring, height=40, font=("Arial", 14, "bold"))
        self.btn_start.pack(pady=10)

        self.status_var = ctk.StringVar(value="Status: Ready")
        self.status_label = ctk.CTkLabel(self, textvariable=self.status_var, text_color="#17a2b8")
        self.status_label.pack()

    def create_path_selector(self, label_text, variable, command):
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(pady=5, padx=20, fill="x")
        
        lbl = ctk.CTkLabel(frame, text=label_text, font=("Arial", 12))
        lbl.pack(anchor="w", padx=10)
        
        inner_frame = ctk.CTkFrame(frame, fg_color="transparent")
        inner_frame.pack(fill="x")
        
        entry = ctk.CTkEntry(inner_frame, textvariable=variable, width=520)
        entry.pack(side="left", padx=10, pady=5)
        
        btn = ctk.CTkButton(inner_frame, text="Browse", width=80, command=command)
        btn.pack(side="left", padx=2)

    def add_log(self, message):
        self.log_box.insert("end", f"> {message}\n")
        self.log_box.see("end")

    def browse_folder(self):
        selected = filedialog.askdirectory()
        if selected:
            self.watch_dir.set(selected)
            self.add_log(f"[CONFIG] JSON Path: {selected}")

    def browse_sql_file(self):
        selected = filedialog.askopenfilename(filetypes=[("SQL files", "*.sql"), ("All files", "*.*")])
        if selected:
            self.sql_file_path.set(selected)
            self.add_log(f"[CONFIG] SQL Path: {selected}")

    def toggle_monitoring(self):
        if self.observer and self.observer.is_alive():
            self.stop_monitoring()
        else:
            self.start_monitoring()

    def start_monitoring(self):
        json_path = self.watch_dir.get()
        sql_path = self.sql_file_path.get()

        # Validation
        if not os.path.exists(json_path):
            messagebox.showerror("Error", f"JSON Folder not found:\n{json_path}")
            return
        if not os.path.exists(sql_path):
            messagebox.showerror("Error", f"SQL File not found:\n{sql_path}")
            return

        event_handler = Handler(self.run_sql)
        self.observer = Observer()
        self.observer.schedule(event_handler, json_path, recursive=False)
        self.observer.start()
        
        self.btn_start.configure(text="Stop Monitoring", fg_color="#dc3545", hover_color="#c82333")
        self.status_var.set("Status: Monitoring Active...")
        self.add_log(f"[START] Monitoring JSON in: {json_path}")
        self.add_log(f"[START] Using SQL Script: {os.path.basename(sql_path)}")

    def stop_monitoring(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
        self.btn_start.configure(text="Start Monitoring", fg_color="#28a745", hover_color="#218838")
        self.status_var.set("Status: Stopped")
        self.add_log("[STOP] Monitoring stopped.")

    def run_sql(self, filename):
        sql_path = self.sql_file_path.get()
        self.status_var.set(f"Status: Executing SQL for {filename}...")
        self.add_log(f"[EVENT] New file: {filename}")
        
        # SQL Execution Command
        # ใช้พาธ SQL ที่ผู้ใช้เลือกมา
        command = ["sqlcmd", "-S", ".", "-d", "POSSDB_KA", "-E", "-i", sql_path]
        
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            self.add_log(f"[SUCCESS] SQL Executed successfully.")
            self.status_var.set("Status: Last Execution Successful")
        except Exception as e:
            self.add_log(f"[SQL ERROR] {str(e)}")
            self.status_var.set("Status: Execution Failed")

    def hide_window(self):
        self.withdraw()
        self.show_tray_icon()

    def show_window(self, icon, item):
        icon.stop()
        self.after(0, self.deiconify)

    def quit_app(self, icon, item):
        icon.stop()
        if self.observer:
            self.observer.stop()
        self.destroy()

    def show_tray_icon(self):
        image = Image.new('RGB', (64, 64), color=(0, 123, 255))
        menu = (item('Show', self.show_window), item('Quit', self.quit_app))
        icon = pystray.Icon("SQL_Monitor", image, "SQL Monitor Running", menu)
        threading.Thread(target=icon.run, daemon=True).start()

class Handler(FileSystemEventHandler):
    def __init__(self, callback):
        self.callback = callback
    def on_created(self, event):
        if not event.is_directory and event.src_path.lower().endswith(".json"):
            filename = os.path.basename(event.src_path)
            self.callback(filename)

if __name__ == "__main__":
    app = App()
    app.mainloop()
