import time
import os
import subprocess
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# --- การตั้งค่า (Configuration) ---
# พาธโฟลเดอร์ที่ต้องการ Monitor (อ้างอิงจากรูปภาพของคุณ)
WATCH_DIRECTORY = r"C:\Program Files\ISS3000_MBranchClient\MBranchClient_KA\Archive\SUCCESS"
# พาธไฟล์ SQL ที่คุณต้องการรัน
SQL_FILE_PATH = r"C:\path\to\your\STP_FTH_POSAPICenter_UpdateBBYDuringTheDay.sql"

# ข้อมูลการเชื่อมต่อ SQL Server
DB_SERVER = "Your_Server_Name"
DB_NAME = "POSSDB_KA"
DB_USER = "sa"          # ปล่อยว่างถ้าใช้ Windows Auth
DB_PASSWORD = "your_password" # ปล่อยว่างถ้าใช้ Windows Auth

# ตั้งค่า Logging เพื่อดูสถานะใน Console
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

class NewJsonHandler(FileSystemEventHandler):
    def on_created(self, event):
        # ตรวจสอบว่าเป็นไฟล์ และนามสกุล .json หรือไม่
        if not event.is_directory and event.src_path.lower().endswith(".json"):
            filename = os.path.basename(event.src_path)
            logging.info(f"Detected new file: {filename}")
            self.run_sql_script(filename)

    def run_sql_script(self, trigger_file):
        logging.info(f"Starting SQL Execution for: {trigger_file}...")
        
        # สร้างคำสั่ง sqlcmd
        # -E คือ Windows Authentication / ถ้าจะใช้ User ให้ใช้ -U {DB_USER} -P {DB_PASSWORD}
        command = [
            "sqlcmd",
            "-S", DB_SERVER,
            "-d", DB_NAME,
            "-E", 
            "-i", SQL_FILE_PATH
        ]

        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            logging.info(f"SQL Execution Success for {trigger_file}!")
            # หากต้องการรันคำสั่ง EXEC ต่อท้าย ให้ทำเพิ่มในสคริปต์ SQL หรือเพิ่มคำสั่งตรงนี้ได้
            print(result.stdout)
        except subprocess.CalledProcessError as e:
            logging.error(f"SQL Execution Failed!")
            logging.error(e.output)

if __name__ == "__main__":
    if not os.path.exists(WATCH_DIRECTORY):
        logging.error(f"Directory not found: {WATCH_DIRECTORY}")
        exit(1)

    event_handler = NewJsonHandler()
    observer = Observer()
    observer.schedule(event_handler, WATCH_DIRECTORY, recursive=False)
    
    logging.info(f"Monitoring started on: {WATCH_DIRECTORY}")
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        logging.info("Monitoring stopped.")
    observer.join()
