# utils.py

import sys
import os
import subprocess
import ctypes
import tkinter.messagebox as messagebox
import logging

def is_admin() -> bool:
    """Check if the current process has administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception as e:
        logging.error(f"Admin check error: {e}")
        return False

def request_admin(root=None) -> bool:
    """
    Request administrator privileges if not already running as admin.
    Returns True if already admin or user declined elevation,
    False if elevation is needed and accepted.
    """
    if is_admin():
        return True
        
    if root:
        answer = messagebox.askyesno(
            "Administrator Privileges Required",
            "This tool needs Administrator privileges for many operations.\n\n"
            "Click YES to relaunch with a UAC prompt.\n"
            "If you click NO, some operations may fail."
        )
        if not answer:
            return True  # User declined elevation
            
        try:
            script_path = os.path.abspath(sys.argv[0])
            args = ' '.join(sys.argv[1:])
            logging.info(f"Relaunching with admin: {script_path} {args}")
            
            # Launch new admin process
            ctypes.windll.shell32.ShellExecuteW(
                None, 
                "runas", 
                sys.executable,
                f'"{script_path}" {args}',
                None, 
                1
            )
            
            # Signal that we're elevating and should close current instance
            return False
            
        except Exception as e:
            logging.error(f"Elevation failed: {e}")
            messagebox.showwarning(
                "UAC Elevation Failed",
                f"Failed to relaunch as admin.\nError: {e}\nContinuing without admin..."
            )
            return True  # Continue without admin
    
    return True  # No root window provided

def ensure_dependencies():
    """Ensures all required packages are installed."""
    required_packages = ['tqdm', 'wmi', 'pywin32']
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            try:
                print(f"Installing '{package}' package...")
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            except Exception as e:
                print(f"Failed to install '{package}'. Error: {e}")
                sys.exit(1)