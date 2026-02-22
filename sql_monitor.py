import customtkinter as ctk
import os
import subprocess
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from PIL import Image
import pystray
from pystray import MenuItem as item

# --- Config (ปรับตามพาธจริงของคุณ) ---
WATCH_DIR = r"C:\Program Files\ISS3000_MBranchClient\MBranchClient_KA\Archive\SUCCESS"
SQL_FILE = r"STP_FTH_POSAPICenter_UpdateBBYDuringTheDay.sql" # ไฟล์ที่อัปโหลด

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SQL File Monitor Pro")
        self.geometry("600x400")
        self.protocol('WM_DELETE_WINDOW', self.hide_window)

        # UI Setup
        self.label = ctk.CTkLabel(self, text="Monitoring Folder...", font=("Arial", 16, "bold"))
        self.label.pack(pady=10)

        self.log_box = ctk.CTkTextbox(self, width=550, height=250)
        self.log_box.pack(pady=10, padx=10)

        self.status_var = ctk.StringVar(value="Status: Waiting for files...")
        self.status_label = ctk.CTkLabel(self, textvariable=self.status_var, text_color="cyan")
        self.status_label.pack(pady=5)

        # Start Monitoring Thread
        self.start_monitoring()

    def add_log(self, message):
        self.log_box.insert("end", f"{message}\n")
        self.log_box.see("end")

    def run_sql(self, filename):
        self.status_var.set(f"Status: Processing {filename}...")
        self.add_log(f"[DETECTED] New file: {filename}")
        
        # คำสั่งรัน SQL
        command = ["sqlcmd", "-S", ".", "-d", "POSSDB_KA", "-E", "-i", SQL_FILE]
        
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            self.add_log(f"[SUCCESS] SQL Executed for {filename}")
            self.status_var.set("Status: SQL Run Successfully!")
        except Exception as e:
            self.add_log(f"[ERROR] Failed: {str(e)}")
            self.status_var.set("Status: Error Occurred")

    def start_monitoring(self):
        event_handler = Handler(self.run_sql)
        self.observer = Observer()
        self.observer.schedule(event_handler, WATCH_DIR, recursive=False)
        self.observer.start()

    def hide_window(self):
        self.withdraw()
        self.show_tray_icon()

    def show_window(self, icon, item):
        icon.stop()
        self.after(0, self.deiconify)

    def quit_app(self, icon, item):
        icon.stop()
        self.observer.stop()
        self.destroy()

    def show_tray_icon(self):
        # สร้างรูป icon เล็กๆ (หรือใช้ไฟล์ .ico ของคุณ)
        image = Image.new('RGB', (64, 64), color=(0, 150, 255))
        menu = (item('Show', self.show_window), item('Quit', self.quit_app))
        icon = pystray.Icon("name", image, "SQL Monitor", menu)
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
