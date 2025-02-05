# main.py

import sys
import os
import traceback
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import logging
from datetime import datetime
import ctypes

def setup_logging():
    """Set up logging configuration."""
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
    
    # Log system info
    logging.info(f"Python Version: {sys.version}")
    logging.info(f"Platform: {sys.platform}")
    logging.info(f"Working Directory: {os.getcwd()}")

def is_admin() -> bool:
    """Return True if running as admin, False otherwise."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception as e:
        logging.error(f"is_admin check failed: {e}", exc_info=True)
        return False

def auto_elevate():
    """
    If not admin, try to relaunch with elevated privileges and exit the current process.
    Returns True if we are already admin or successfully relaunched, 
    or False if the user cancels or something fails.
    """
    if is_admin():
        return True
    
    logging.info("Not running as admin. Attempting to relaunch with runas...")
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            " ".join(sys.argv),
            None,
            1
        )
        # If ShellExecuteW doesn't raise an error, it means the UAC prompt was displayed.
        # We exit so the new elevated process can start fresh.
        sys.exit(0)
    except Exception as e:
        logging.error(f"Elevation failed: {e}", exc_info=True)
        return False

def main():
    """Main entry point for the disk cloning application."""
    try:
        # 1) Set up logging first
        setup_logging()
        logging.info("Starting application")
        
        # 2) Attempt auto-elevation
        if not auto_elevate():
            # user canceled or something failed
            logging.warning("User declined admin or elevation failed. Exiting.")
            messagebox.showwarning(
                "Insufficient Privileges",
                "This application requires administrator privileges to run properly. Exiting..."
            )
            sys.exit(1)
        
        # 3) Now we should be admin. Proceed with imports.
        logging.debug("Importing dependencies after admin check")
        from utils import ensure_dependencies
        from gui import DiskClonerApp
        
        # 4) Ensure required packages
        logging.debug("Checking dependencies")
        ensure_dependencies()
        
        # 5) Set up the root window
        logging.debug("Creating main window")
        root = tk.Tk()
        root.title("Disk Cloner")
        
        # Optional: set custom style
        logging.debug("Configuring styles")
        style = ttk.Style()
        style.configure('TButton', padding=5)
        style.configure('TLabelframe', padding=5)
        
        # 6) Initialize the application
        logging.debug("Initializing application (DiskClonerApp)")
        app = DiskClonerApp(root)
        
        def on_closing():
            logging.info("Application closing")
            app.cleanup()
            root.destroy()
            
        root.protocol("WM_DELETE_WINDOW", on_closing)
        
        # Log successful initialization
        logging.info("Application initialized successfully, entering main event loop")
        
        # 7) Run event loop
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
        # Catch any errors that occur before logging is set up
        error_msg = f"Startup Error: {str(e)}\n\n{traceback.format_exc()}"
        print(error_msg)
        try:
            with open("startup_error.log", "w") as f:
                f.write(error_msg)
        except:
            pass
        sys.exit(1)
