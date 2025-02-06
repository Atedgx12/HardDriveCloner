import sys
import os
import traceback
import tkinter as tk
from tkinter import messagebox, ttk
import logging
from datetime import datetime
import ctypes

def setup_logging():
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"disk_cloner_{timestamp}.log")
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    logging.info(f"Python Version: {sys.version}")
    logging.info(f"Platform: {sys.platform}")
    logging.info(f"Working Directory: {os.getcwd()}")

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception as e:
        logging.error(f"is_admin check failed: {e}", exc_info=True)
        return False

def auto_elevate():
    if is_admin():
        return True
    logging.info("Not running as admin. Attempting elevation...")
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable,
            " ".join(sys.argv),
            None, 1
        )
        sys.exit(0)  # The newly elevated process will start
    except Exception as e:
        logging.error(f"Elevation failed: {e}", exc_info=True)
        return False

def main():
    try:
        setup_logging()
        logging.info("Starting application")
        if not auto_elevate():
            logging.warning("User canceled elevation or failed. Exiting.")
            messagebox.showwarning("Insufficient Privileges",
                                   "Requires admin privileges. Exiting...")
            sys.exit(1)
        logging.debug("Importing GUI after admin check")
        from gui import DiskClonerApp  # GUI will import from disk_ops (the façade)
        logging.debug("Creating main Tk window")
        root = tk.Tk()
        root.title("Disk Cloner")
        style = ttk.Style()
        style.configure('TButton', padding=5)
        style.configure('TLabelframe', padding=5)
        logging.debug("Initializing DiskClonerApp")
        app = DiskClonerApp(root)
        def on_closing():
            logging.info("Application closing")
            app.cleanup()
            root.destroy()
        root.protocol("WM_DELETE_WINDOW", on_closing)
        logging.info("GUI initialized, entering main loop")
        root.mainloop()
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}\n\n{traceback.format_exc()}"
        logging.critical(error_msg)
        try:
            messagebox.showerror("Critical Error", error_msg)
        except:
            print(error_msg)
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        err_msg = f"Startup Error: {str(e)}\n\n{traceback.format_exc()}"
        print(err_msg)
        try:
            with open("startup_error.log", "w") as f:
                f.write(err_msg)
        except:
            pass
        sys.exit(1)