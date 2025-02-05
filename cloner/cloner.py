import sys
import os
import subprocess
import ctypes
import threading
import time
import json
import traceback
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import win32api
import win32file
import win32security
import pywintypes
import wmi
import pythoncom
import re
from typing import Tuple, List, Dict, Optional
import msvcrt
from concurrent.futures import ThreadPoolExecutor

##############################
# 1) CONSTANTS AND GLOBALS
##############################
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
SHADOW_COPY_TIMEOUT = 30  # seconds
MAX_SHADOW_COPIES = 64   # Windows default limit
CHUNK_SIZE = 1024 * 1024  # 1 MB for file operations

##############################
# 2) CUSTOM EXCEPTIONS
##############################
class DiskValidationError(Exception):
    """Custom exception for disk validation errors"""
    pass

class ShadowCopyError(Exception):
    """Custom exception for shadow copy operations"""
    pass

class DeviceAccessError(Exception):
    """Custom exception for device access errors"""
    pass

##############################
# 3) SELF-INSTALL DEPENDENCIES
##############################
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

ensure_dependencies()

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None
##############################
# 4) ADMIN PRIVILEGES HANDLING
##############################
def is_admin() -> bool:
    """
    Check if the current process has administrator privileges.
    Returns:
        bool: True if running as admin, False otherwise
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception as e:
        print(f"[DEBUG] is_admin error: {e}")
        return False

def request_admin(root=None):
    """
    Request administrator privileges if not already running as admin.
    Args:
        root: Optional root window for displaying message boxes
    """
    if not is_admin():
        if root:
            answer = messagebox.askyesno(
                "Administrator Privileges Required",
                "This tool needs Administrator privileges for many operations.\n\n"
                "Click YES to relaunch with a UAC prompt.\n"
                "If you click NO, some operations may fail."
            )
            if not answer:
                return
        try:
            print("[DEBUG] Relaunching with admin privileges...")
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
            sys.exit(0)
        except Exception as e:
            if root:
                messagebox.showwarning(
                    "UAC Elevation Failed",
                    f"Failed to relaunch as admin.\nError: {e}\nContinuing without admin..."
                )
            else:
                print(f"[WARNING] UAC Elevation failed: {e}")
##############################
# 5) DEVICE PATH HANDLING
##############################
def normalize_device_path(path: str) -> str:
    """
    Normalizes a device path to ensure proper format.
    Args:
        path: Raw device path string
    Returns:
        Normalized device path
    Raises:
        ValueError: If path format is invalid
    """
    path = path.replace('/', '\\')
    path = path.strip('\\')
    
    if path.startswith('PHYSICALDRIVE'):
        return '\\\\.\\' + path
    elif path.startswith('\\\\.\\PHYSICALDRIVE'):
        return path
    elif path.startswith('\\\\PHYSICALDRIVE'):
        return '\\\\.' + path
    else:
        parts = path.split('\\')
        for part in parts:
            if part.startswith('PHYSICALDRIVE'):
                return '\\\\.\\' + part
    
    raise ValueError(f"Invalid device path format: {path}")

def validate_device_path(path: str) -> bool:
    """
    Validates if a device path is properly formatted.
    Args:
        path: Device path to validate
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        normalized = normalize_device_path(path)
        return normalized.startswith('\\\\.\\PHYSICALDRIVE')
    except ValueError:
        return False

##############################
# 6) VOLUME INFORMATION
##############################
class VolumeInfo:
    """Class representing volume information and operations."""
    
    def __init__(self, letter: str):
        """
        Initialize volume information.
        Args:
            letter: Drive letter (e.g., 'C', 'D')
        Raises:
            ShadowCopyError: If volume information cannot be retrieved
        """
        self.letter = letter.upper().rstrip(':')
        self.path = f"{self.letter}:"
        self.volume_path = f"\\\\.\\{self.letter}:"
        self.guid_path = None
        self.fs_type = None
        self.total_size = 0
        self.free_space = 0
        self._get_volume_info()

    def _get_volume_info(self):
        """
        Retrieves detailed volume information.
        Raises:
            ShadowCopyError: If volume information cannot be retrieved
        """
        try:
            # Get volume GUID path
            buf = ctypes.create_unicode_buffer(1024)
            if ctypes.windll.kernel32.GetVolumeNameForVolumeMountPointW(
                f"{self.letter}:\\", buf, 1024):
                self.guid_path = buf.value.rstrip('\\')

            # Get filesystem info
            fs_info = win32api.GetVolumeInformation(f"{self.letter}:\\")
            self.fs_type = fs_info[4]

            # Get space info
            free_bytes = ctypes.c_ulonglong(0)
            total_bytes = ctypes.c_ulonglong(0)
            ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                f"{self.letter}:\\",
                None,
                ctypes.byref(total_bytes),
                ctypes.byref(free_bytes)
            )
            self.total_size = total_bytes.value
            self.free_space = free_bytes.value

        except Exception as e:
            raise ShadowCopyError(f"Failed to get volume information: {str(e)}")

##############################
# 7) SHADOW COPY OPERATIONS
##############################
def parse_wmic_output(output: str, key: str) -> Optional[str]:
    """
    Parse WMIC output for a specific key.
    Args:
        output: WMIC command output string
        key: Key to search for
    Returns:
        Optional[str]: Parsed value or None if not found
    """
    pattern = fr"{key}\s*=\s*(.+?)(?:;|$)"
    match = re.search(pattern, output)
    if match:
        value = match.group(1).strip().strip('"{}')
        return value if value != "00000000-0000-0000-0000-000000000000" else None
    return None

def wait_for_shadow_copy(shadow_id: str, timeout: int = SHADOW_COPY_TIMEOUT) -> bool:
    """
    Wait for shadow copy to be ready.
    Args:
        shadow_id: Shadow copy ID to wait for
        timeout: Maximum time to wait in seconds
    Returns:
        bool: True if ready, False if timeout or error
    """
    start_time = time.time()
    while (time.time() - start_time) < timeout:
        try:
            cmd = f'wmic shadowcopy where ID="{shadow_id}" get Status /format:list'
            output = subprocess.check_output(cmd, shell=True).decode(errors="ignore")
            status = parse_wmic_output(output, "Status")
            if status == "12":  # 12 means shadow copy is ready
                return True
            time.sleep(1)
        except Exception:
            pass
    return False

def list_existing_shadow_copies(volume_letter: str) -> List[Dict[str, str]]:
    """
    List existing shadow copies for a volume.
    Args:
        volume_letter: Drive letter to check
    Returns:
        List[Dict[str, str]]: List of shadow copy information dictionaries
    """
    volume_letter = volume_letter.rstrip(':\\')
    cmd = f'wmic shadowcopy where VolumeName="{volume_letter}:" get ID,InstallDate,DeviceObject /format:list'
    try:
        output = subprocess.check_output(cmd, shell=True).decode(errors="ignore")
        shadows = []
        current_shadow = {}
        
        for line in output.splitlines():
            line = line.strip()
            if not line:
                if current_shadow:
                    shadows.append(current_shadow)
                    current_shadow = {}
                continue
                
            if '=' in line:
                key, value = line.split('=', 1)
                current_shadow[key.strip()] = value.strip()
                
        if current_shadow:
            shadows.append(current_shadow)
            
        return shadows
    except Exception as e:
        print(f"[WARNING] Failed to list existing shadow copies: {e}")
        return []

def cleanup_old_shadow_copies(volume_letter: str, max_copies: int = MAX_SHADOW_COPIES) -> None:
    """
    Clean up old shadow copies if approaching limit.
    Args:
        volume_letter: Drive letter to clean up
        max_copies: Maximum number of shadow copies to maintain
    """
    try:
        shadows = list_existing_shadow_copies(volume_letter)
        if len(shadows) >= max_copies - 1:
            shadows.sort(key=lambda x: x.get('InstallDate', ''))
            while len(shadows) >= max_copies - 1:
                oldest = shadows.pop(0)
                try:
                    cmd = f'wmic shadowcopy where ID="{oldest["ID"]}" delete'
                    subprocess.check_call(cmd, shell=True)
                    print(f"[INFO] Deleted old shadow copy {oldest['ID']}")
                except Exception as e:
                    print(f"[WARNING] Failed to delete old shadow copy: {e}")
    except Exception as e:
        print(f"[WARNING] Shadow copy cleanup failed: {e}")

def create_shadow_copy(volume_letter: str, cleanup: bool = True, 
                      timeout: int = SHADOW_COPY_TIMEOUT) -> Tuple[bool, str, Optional[str]]:
    """
    Creates a volume shadow copy with comprehensive validation.
    Args:
        volume_letter: Drive letter to create shadow copy for
        cleanup: Whether to clean up old shadow copies
        timeout: Maximum time to wait for creation
    Returns:
        Tuple[bool, str, Optional[str]]: (success, message, device_object_path)
    """
    try:
        # Normalize and validate volume letter
        volume_letter = volume_letter.strip().rstrip(':\\')
        if not volume_letter or len(volume_letter) != 1 or not volume_letter.isalpha():
            return False, "Invalid volume letter format", None

        # Get volume information
        try:
            volume = VolumeInfo(volume_letter)
        except ShadowCopyError as e:
            return False, f"Volume validation failed: {str(e)}", None

        # Check filesystem type
        if volume.fs_type not in ['NTFS', 'ReFS']:
            return False, f"Unsupported filesystem type: {volume.fs_type}", None

        # Check if volume exists and is ready
        if not os.path.exists(f"{volume_letter}:"):
            return False, f"Volume {volume_letter}: does not exist", None

        # Clean up old shadow copies if requested
        if cleanup:
            cleanup_old_shadow_copies(volume_letter)

        # Create shadow copy
        vol_path = f"{volume_letter}:\\"
        cmd_create = f'wmic shadowcopy call create Volume="{vol_path}"'
        try:
            output = subprocess.check_output(cmd_create, shell=True, 
                                          stderr=subprocess.PIPE).decode(errors="ignore")
            print(f"[DEBUG] Shadow copy creation output:\n{output}")
        except subprocess.CalledProcessError as e:
            stderr = e.stderr.decode(errors="ignore")
            error_msg = f"WMIC command failed with code {e.returncode}: {stderr}"
            print(f"[ERROR] {error_msg}")
            return False, error_msg, None
        except Exception as e:
            return False, f"Shadow copy creation failed: {str(e)}", None

        # Parse return value and shadow ID
        return_value = parse_wmic_output(output, "ReturnValue")
        if return_value and return_value != "0":
            error_codes = {
                "1": "Access denied",
                "2": "Invalid argument",
                "3": "Specified volume not found",
                "4": "Insufficient storage space",
                "5": "Shadow copy creation already in progress",
                "6": "Volume is not supported",
                "7": "Maximum number of shadow copies reached",
                "8": "Another shadow copy operation is already in progress",
                "9": "Insufficient resources",
                "10": "Volume is not ready"
            }
            error_msg = error_codes.get(return_value, f"Unknown error code: {return_value}")
            return False, f"Shadow copy creation failed: {error_msg}", None

        shadow_id = parse_wmic_output(output, "ShadowID")
        if not shadow_id:
            return False, "Failed to get valid shadow copy ID", None

        # Wait for shadow copy to be ready
        if not wait_for_shadow_copy(shadow_id, timeout):
            return False, "Shadow copy creation timed out", None

        # Get device object path
        cmd_device = f'wmic shadowcopy where ID="{shadow_id}" get DeviceObject /format:list'
        try:
            output = subprocess.check_output(cmd_device, shell=True).decode(errors="ignore")
            device_object = parse_wmic_output(output, "DeviceObject")
            if not device_object:
                return False, "Shadow copy created but device object not found", None
        except Exception as e:
            return False, f"Failed to get device object: {str(e)}", None

        # Validate device object path
        try:
            handle = win32file.CreateFile(
                device_object,
                win32file.GENERIC_READ,
                win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
                None,
                win32file.OPEN_EXISTING,
                0,
                None
            )
            handle.Close()
        except pywintypes.error as e:
            return False, f"Created shadow copy is not accessible: {str(e)}", None

        return True, "Shadow copy created successfully", device_object

    except Exception as e:
        return False, f"Unexpected error in shadow copy creation: {str(e)}", None
        
        
##############################
# 8) DISK VALIDATION CLASS
##############################
class DiskValidator:
    def __init__(self):
        """Initialize disk validator with WMI connection."""
        pythoncom.CoInitialize()  # Initialize COM for the current thread
        self.wmi = wmi.WMI()

    def __del__(self):
        """Cleanup WMI connection."""
        try:
            pythoncom.CoUninitialize()
        except:
            pass

    def get_mounted_volumes(self, physical_drive: str) -> List[str]:
        """
        Returns a list of mounted volume letters for a physical drive.
        Args:
            physical_drive: Physical drive path
        Returns:
            List[str]: List of volume letters (e.g., ['C:', 'D:'])
        Raises:
            DiskValidationError: If drive format is invalid
        """
        drive_number = physical_drive.replace('\\\\.\\PHYSICALDRIVE', '')
        try:
            drive_number = int(drive_number)
        except ValueError:
            raise DiskValidationError(f"Invalid drive format: {physical_drive}")

        volumes = []
        try:
            for partition in self.wmi.Win32_DiskPartition(DiskIndex=drive_number):
                for logical_disk in partition.associates("Win32_LogicalDisk"):
                    volumes.append(logical_disk.DeviceID)
        except Exception as e:
            print(f"[WARNING] Error getting mounted volumes: {e}")
        
        return volumes

    def validate_source_destination(self, source: str, destination: str) -> Tuple[bool, str, Dict]:
        """
        Comprehensive validation of source and destination drives.
        Args:
            source: Source drive path
            destination: Destination drive path
        Returns:
            Tuple[bool, str, Dict]: (is_valid, message, details_dict)
        """
        validation_results = {
            'source_size': 0,
            'dest_size': 0,
            'source_volumes': [],
            'dest_volumes': [],
            'warnings': []
        }

        if source == destination:
            return False, "Source and destination cannot be the same drive", validation_results

        source_info = None
        dest_info = None
        
        for disk in self.wmi.Win32_DiskDrive():
            if f"\\\\.\\{disk.DeviceID}" == source:
                source_info = disk
            if f"\\\\.\\{disk.DeviceID}" == destination:
                dest_info = disk

        if not source_info:
            return False, f"Source drive {source} not found", validation_results
        if not dest_info:
            return False, f"Destination drive {destination} not found", validation_results

        try:
            source_size = int(source_info.Size)
            dest_size = int(dest_info.Size)
            validation_results['source_size'] = source_size
            validation_results['dest_size'] = dest_size

            if dest_size < source_size:
                return False, (
                    f"Destination drive too small. Source: {source_size / (1024**3):.2f} GB, "
                    f"Destination: {dest_size / (1024**3):.2f} GB"
                ), validation_results
        except Exception as e:
            return False, f"Error comparing drive sizes: {str(e)}", validation_results

        try:
            source_volumes = self.get_mounted_volumes(source)
            dest_volumes = self.get_mounted_volumes(destination)
            validation_results['source_volumes'] = source_volumes
            validation_results['dest_volumes'] = dest_volumes

            if source_volumes:
                validation_results['warnings'].append(
                    f"Source drive has mounted volumes: {', '.join(source_volumes)}"
                )
            if dest_volumes:
                validation_results['warnings'].append(
                    f"Destination drive has mounted volumes: {', '.join(dest_volumes)}"
                )
        except Exception as e:
            validation_results['warnings'].append(f"Error checking mounted volumes: {str(e)}")

        try:
            if source_info.MediaType and "Removable" in source_info.MediaType:
                validation_results['warnings'].append("Source is a removable drive")
            if dest_info.MediaType and "Removable" in dest_info.MediaType:
                validation_results['warnings'].append("Destination is a removable drive")
        except Exception as e:
            validation_results['warnings'].append(f"Error checking drive types: {str(e)}")

        return True, "Validation successful", validation_results

    def dismount_volume(self, volume: str) -> Tuple[bool, str]:
        """
        Safely dismount a volume.
        Args:
            volume: Volume letter to dismount (e.g., 'C:')
        Returns:
            Tuple[bool, str]: (success, message)
        """
        try:
            drive_letter = volume[0].upper()
            volume_path = f"\\\\.\\{drive_letter}:"
            
            handle = win32file.CreateFile(
                volume_path,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
                None,
                win32file.OPEN_EXISTING,
                0,
                None
            )
            
            try:
                # Lock volume
                win32file.DeviceIoControl(
                    handle, 
                    win32file.FSCTL_LOCK_VOLUME, 
                    None, 
                    None
                )
                
                # Dismount volume
                win32file.DeviceIoControl(
                    handle, 
                    win32file.FSCTL_DISMOUNT_VOLUME, 
                    None, 
                    None
                )
                
                return True, f"Successfully dismounted volume {volume}"
            finally:
                handle.Close()
                
        except Exception as e:
            return False, f"Failed to dismount volume {volume}: {str(e)}"

##############################
# 9) DISK VERIFICATION CLASS
##############################
class DiskVerifier:
    """Handles verification of disk cloning operations"""
    
    @staticmethod
    def verify_disks(source: str, destination: str, chunk_size: int = CHUNK_SIZE, 
                    progress_callback: Optional[callable] = None) -> Tuple[bool, str, List[Dict]]:
        """
        Verifies that destination disk matches source disk.
        Args:
            source: Source drive path
            destination: Destination drive path
            chunk_size: Size of chunks to read at a time
            progress_callback: Optional callback for progress updates
        Returns:
            Tuple[bool, str, List[Dict]]: (success, message, list_of_differences)
        """
        differences = []
        total_bytes = 0
        bytes_verified = 0
        
        try:
            with open_raw_device(source, GENERIC_READ) as src:
                with open_raw_device(destination, GENERIC_READ) as dst:
                    src.seek(0, 2)  # Seek to end
                    total_bytes = src.tell()
                    src.seek(0)  # Return to start
                    
                    while True:
                        src_chunk = src.read(chunk_size)
                        if not src_chunk:
                            break
                            
                        dst_chunk = dst.read(chunk_size)
                        if src_chunk != dst_chunk:
                            offset = bytes_verified
                            differences.append({
                                'offset': offset,
                                'length': len(src_chunk),
                                'source_sample': src_chunk[:16].hex(),
                                'dest_sample': dst_chunk[:16].hex() if dst_chunk else 'No data'
                            })
                            
                        bytes_verified += len(src_chunk)
                        if progress_callback:
                            progress_callback(bytes_verified, total_bytes)
                            
        except Exception as e:
            return False, f"Verification failed: {str(e)}", differences
            
        if differences:
            return False, f"Found {len(differences)} differences", differences
        return True, "Verification successful - disks match exactly", []

##############################
# 10) DISK CLONING OPERATIONS
##############################
def open_raw_device(path: str, access_flag: int):
    """
    Opens a raw device with proper access flags and error handling.
    Args:
        path: Device path
        access_flag: Access flag (GENERIC_READ or GENERIC_WRITE)
    Returns:
        File object for the device
    Raises:
        OSError: If device cannot be opened
        ValueError: If path is invalid
    """
    try:
        normalized_path = normalize_device_path(path)
        
        if not normalized_path.startswith('\\\\.\\PHYSICALDRIVE'):
            raise ValueError(f"Invalid device path format: {normalized_path}")
        
        handle = ctypes.windll.kernel32.CreateFileW(
            ctypes.c_wchar_p(normalized_path),
            access_flag,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            0,
            None
        )
        
        if handle == ctypes.c_void_p(-1).value:
            error_code = ctypes.get_last_error()
            if error_code == 5:  # Access Denied
                raise PermissionError(
                    f"Access denied to device {normalized_path}. "
                    "Run as administrator."
                )
            raise OSError(
                f"Failed to open device {normalized_path}. "
                f"Error code: {error_code}"
            )
            
        try:
            fd = msvcrt.open_osfhandle(handle, os.O_BINARY)
        except OSError as e:
            ctypes.windll.kernel32.CloseHandle(handle)
            raise OSError(f"Failed to create file descriptor: {e}")
            
        try:
            mode = "rb" if access_flag == GENERIC_READ else "wb"
            return os.fdopen(fd, mode, buffering=0)
        except Exception as e:
            os.close(fd)
            raise OSError(f"Failed to create file object: {e}")
            
    except Exception as e:
        print(f"[DEBUG] Error in open_raw_device: {str(e)}")
        raise

def clone_disk_with_callback(source: str, destination: str, total_size: int, chunk_size: int,
                           progress_callback: callable, error_callback: callable):
    """
    Clones a disk with progress updates and error handling.
    Args:
        source: Source drive path
        destination: Destination drive path
        total_size: Total size to copy
        chunk_size: Size of chunks to copy at a time
        progress_callback: Callback for progress updates
        error_callback: Callback for error handling
    """
    bytes_copied = 0
    src = None
    dst = None
    
    try:
        # Normalize paths before validation
        source = normalize_device_path(source)
        destination = normalize_device_path(destination)
        
        # Ensure COM is initialized for drive listing
        pythoncom.CoInitialize()
        
        # Validate devices exist
        drives = list_physical_drives()
        if not any(source.lower() == normalize_device_path(drive[0]).lower() 
                  for drive in drives):
            raise ValueError(f"Source device {source} not found in system")
        if not any(destination.lower() == normalize_device_path(drive[0]).lower() 
                  for drive in drives):
            raise ValueError(f"Destination device {destination} not found in system")
        
        print(f"[DEBUG] Opening source device: {source}")
        src = open_raw_device(source, GENERIC_READ)
        print(f"[DEBUG] Opening destination device: {destination}")
        dst = open_raw_device(destination, GENERIC_WRITE)
        
        print("[DEBUG] Starting disk clone operation")
        while True:
            chunk = src.read(chunk_size)
            if not chunk:
                break
            dst.write(chunk)
            bytes_copied += len(chunk)
            progress_callback(bytes_copied)
            
    except Exception as e:
        error_msg = f"Cloning failed: {str(e)}\nStack trace:\n{traceback.format_exc()}"
        print(f"[ERROR] {error_msg}")
        error_callback(error_msg)
    finally:
        if src:
            try:
                src.close()
            except Exception as e:
                print(f"Warning: Error closing source device: {e}")
        if dst:
            try:
                dst.close()
            except Exception as e:
                print(f"Warning: Error closing destination device: {e}")
        try:
            pythoncom.CoUninitialize()
        except:
            pass

##############################
# 11) DRIVE LISTING
##############################
def list_physical_drives() -> List[Tuple[str, str, int]]:
    """
    Lists all physical drives in the system.
    Returns:
        List[Tuple[str, str, int]]: List of (device_id, model, size) tuples
    """
    drives = []
    try:
        pythoncom.CoInitialize()
        wmi_obj = wmi.WMI()
        for disk in wmi_obj.Win32_DiskDrive():
            try:
                device_id = normalize_device_path(disk.DeviceID)
                model = disk.Model.strip() if disk.Model else "Unknown"
                size = int(disk.Size) if disk.Size else 0
                
                print(f"[DEBUG] Found drive: {device_id}, Model: {model}, Size: {size}")
                drives.append((device_id, model, size))
            except Exception as disk_error:
                print(f"[WARNING] Error processing disk {disk.DeviceID}: {disk_error}")
                continue
                
    except Exception as e:
        print(f"[ERROR] WMI drive listing failed: {e}")
    finally:
        try:
            pythoncom.CoUninitialize()
        except:
            pass
            
    return drives

##############################
# 12) DRIVE SELECTOR DIALOG
##############################
def drive_selector_dialog(parent, drives: List[Tuple[str, str, int]]) -> Tuple[Optional[str], Optional[str]]:
    """
    Creates a dialog for selecting a drive.
    Args:
        parent: Parent window
        drives: List of available drives
    Returns:
        Tuple[Optional[str], Optional[str]]: Selected (label, device) or (None, None)
    """
    selected = {"label": None, "device": None}
    
    def on_select(event=None):
        item = tree.focus()
        if item:
            values = tree.item(item, "values")
            selected["label"] = values[0]
            selected["device"] = values[1]
            dialog.destroy()
    
    # Create dialog window
    dialog = tk.Toplevel(parent)
    dialog.title("Select Drive")
    dialog.geometry("500x300")
    dialog.transient(parent)
    dialog.grab_set()
    
    # Create Treeview for drive selection
    tree = ttk.Treeview(dialog, columns=("Label", "Device"), show="headings", selectmode="browse")
    tree.heading("Label", text="Drive Info")
    tree.heading("Device", text="Device Path")
    tree.column("Label", width=300)
    tree.column("Device", width=150)
    tree.pack(fill="both", expand=True, padx=10, pady=10)
    
    # Populate drive list
    for dev, model, size in drives:
        gb_size = size / (1024**3) if size else 0
        dev_part = dev.split("\\")[-1]
        label = f"{dev_part} – {model[:30]} ({gb_size:.2f} GB)"
        tree.insert("", "end", values=(label, dev))
    
    # Create button frame
    btn_frame = ttk.Frame(dialog)
    btn_frame.pack(fill="x", padx=10, pady=5)
    
    # Add buttons
    ttk.Button(btn_frame, text="Select", command=on_select).pack(side="right", padx=5)
    ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(side="right", padx=5)
    
    # Bind double-click
    tree.bind("<Double-1>", on_select)
    
    # Wait for dialog
    parent.wait_window(dialog)
    return selected["label"], selected["device"]

##############################
# 11) MAIN APPLICATION CLASS
##############################
class DiskClonerApp:
    """Main application class for the disk cloner GUI."""
    
    def __init__(self, root):
        """
        Initialize the application.
        Args:
            root: Root window
        """
        self.root = root
        self.root.title("Python Disk Cloner (Advanced)")
        self.root.minsize(600, 400)
        
        # Request admin privileges
        request_admin(root)
        
        # Initialize validator
        self.validator = DiskValidator()

        # Get available drives
        self.drives = list_physical_drives()

        # Initialize variables
        self._init_variables()
        
        # Create GUI elements
        self.create_widgets()
        
        # Start periodic drive refresh
        self._start_drive_refresh()

    def _init_variables(self):
        """Initialize all tkinter variables."""
        # Drive selection variables
        self.source_drive_label = tk.StringVar()
        self.source_drive_device = None
        self.dest_drive_label = tk.StringVar()
        self.dest_drive_device = None

        # Operation options
        self.shadowcopy_var = tk.BooleanVar(value=False)
        self.verify_after_clone = tk.BooleanVar(value=True)
        self.show_adv_options = tk.BooleanVar(value=False)

        # Status and progress
        self.status_var = tk.StringVar(value="Ready")
        self.progress_var = tk.DoubleVar(value=0.0)
        self.cloning_in_progress = False

    def create_widgets(self):
        """Create and arrange all GUI widgets."""
        # Main container
        main_container = ttk.Frame(self.root, padding="10")
        main_container.pack(fill="both", expand=True)

        # Drive selection frame
        self._create_drive_selection_frame(main_container)
        
        # Options frame
        self._create_options_frame(main_container)
        
        # Progress frame
        self._create_progress_frame(main_container)
        
        # Action buttons frame
        self._create_action_buttons(main_container)

    def _create_drive_selection_frame(self, parent):
        """Create the drive selection section."""
        frame = ttk.LabelFrame(parent, text="Drive Selection", padding="5")
        frame.pack(fill="x", padx=5, pady=5)

        # Source drive
        src_frame = ttk.Frame(frame)
        src_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(src_frame, text="Source Drive:").pack(side="left")
        ttk.Entry(src_frame, textvariable=self.source_drive_label, 
                 state="readonly", width=50).pack(side="left", padx=5)
        ttk.Button(src_frame, text="Browse", 
                  command=self.browse_source).pack(side="left")

        # Destination drive
        dst_frame = ttk.Frame(frame)
        dst_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(dst_frame, text="Destination Drive:").pack(side="left")
        ttk.Entry(dst_frame, textvariable=self.dest_drive_label, 
                 state="readonly", width=50).pack(side="left", padx=5)
        ttk.Button(dst_frame, text="Browse", 
                  command=self.browse_destination).pack(side="left")

    def _create_options_frame(self, parent):
        """Create the options section."""
        frame = ttk.LabelFrame(parent, text="Options", padding="5")
        frame.pack(fill="x", padx=5, pady=5)

        # Shadow copy option
        ttk.Checkbutton(frame, text="Use Volume Shadow Copy (for locked volumes)",
                       variable=self.shadowcopy_var).pack(anchor="w")
        
        # Verify after clone option
        ttk.Checkbutton(frame, text="Verify after cloning",
                       variable=self.verify_after_clone).pack(anchor="w")

    def _create_progress_frame(self, parent):
        """Create the progress section."""
        frame = ttk.Frame(parent)
        frame.pack(fill="x", padx=5, pady=5)

        # Status label
        self.status_label = ttk.Label(frame, textvariable=self.status_var)
        self.status_label.pack(side="left")

        # Progress bar
        self.progress_bar = ttk.Progressbar(frame, variable=self.progress_var, 
                                          maximum=100, length=300)
        self.progress_bar.pack(side="right", fill="x", expand=True)

    def _create_action_buttons(self, parent):
        """Create the action buttons section."""
        frame = ttk.Frame(parent)
        frame.pack(fill="x", padx=5, pady=5)

        # Clone button
        self.clone_button = ttk.Button(frame, text="Start Clone",
                                     command=self.on_clone_clicked)
        self.clone_button.pack(side="right")

        # Refresh button
        self.refresh_button = ttk.Button(frame, text="Refresh Drives",
                                       command=self.refresh_drives)
        self.refresh_button.pack(side="right", padx=5)

    def _start_drive_refresh(self):
        """Start periodic drive refresh."""
        def refresh():
            if not self.cloning_in_progress:
                self.refresh_drives()
            self.root.after(30000, refresh)  # Refresh every 30 seconds
        self.root.after(30000, refresh)

    def refresh_drives(self):
        """Refresh the list of available drives."""
        self.drives = list_physical_drives()
        if not self.cloning_in_progress:
            self.status_var.set("Drives refreshed")

    def browse_source(self):
        """Handle source drive selection."""
        label, device = drive_selector_dialog(self.root, self.drives)
        if label and device:
            self.source_drive_label.set(label)
            self.source_drive_device = device

    def browse_destination(self):
        """Handle destination drive selection."""
        label, device = drive_selector_dialog(self.root, self.drives)
        if label and device:
            self.dest_drive_label.set(label)
            self.dest_drive_device = device

    def on_clone_clicked(self):
        """Handle clone button click."""
        if self.cloning_in_progress:
            messagebox.showinfo("Busy", "A clone operation is already in progress")
            return

        if not self.validate_clone_operation():
            return

        # Start cloning process
        self.start_clone_operation()

    def validate_clone_operation(self) -> bool:
        """
        Validate the clone operation parameters.
        Returns:
            bool: True if validation successful, False otherwise
        """
        if not self.source_drive_device or not self.dest_drive_device:
            messagebox.showerror("Error", "Please select both source and destination drives")
            return False

        if self.source_drive_device.lower() == self.dest_drive_device.lower():
            messagebox.showerror("Error", "Source and destination must be different drives")
            return False

        # Validate drives using DiskValidator
        is_valid, message, details = self.validator.validate_source_destination(
            self.source_drive_device,
            self.dest_drive_device
        )

        if not is_valid:
            messagebox.showerror("Validation Error", message)
            return False

        # Show warnings if any
        if details['warnings']:
            warning_msg = "\n".join([
                "The following warnings were detected:",
                "",
                *details['warnings'],
                "",
                "Do you want to continue anyway?"
            ])
            if not messagebox.askyesno("Warnings", warning_msg):
                return False

        # Final confirmation
        confirm_msg = (
            f"Source Drive: {self.source_drive_label.get()}\n"
            f"Destination Drive: {self.dest_drive_label.get()}\n\n"
            "WARNING: ALL DATA ON THE DESTINATION DRIVE WILL BE OVERWRITTEN!\n\n"
            "Are you sure you want to proceed?"
        )
        return messagebox.askyesno("Confirm Clone Operation", confirm_msg)

    def start_clone_operation(self):
        """Start the cloning operation."""
        src_device = self.source_drive_device

        # Handle shadow copy if enabled
        if self.shadowcopy_var.get():
            vol_letter = simpledialog.askstring(
                "Shadow Copy",
                "Enter volume letter to snapshot (e.g. C):",
                parent=self.root
            )
            if vol_letter:
                success, msg, sc_path = create_shadow_copy(vol_letter)
                if success and sc_path:
                    messagebox.showinfo(
                        "Shadow Copy Created",
                        f"Shadow copy created at:\n{sc_path}"
                    )
                    src_device = sc_path
                else:
                    if not messagebox.askyesno(
                        "Shadow Copy Failed",
                        f"Shadow copy creation failed: {msg}\n\n"
                        "Do you want to proceed with the original source?"
                    ):
                        return

        # Get total size for progress tracking
        total_size = 0
        for dev, model, size in self.drives:
            if dev.lower() == self.source_drive_device.lower():
                total_size = size
                break

        # Prepare UI for cloning
        self.clone_button.config(state="disabled")
        self.status_var.set("Starting clone operation...")
        self.progress_var.set(0)
        self.cloning_in_progress = True

        # Start cloning thread
        threading.Thread(
            target=self.clone_thread,
            args=(src_device, self.dest_drive_device, total_size),
            daemon=True
        ).start()

    def clone_thread(self, src_device: str, dst_device: str, total_size: int):
        """
        Thread function for clone operation.
        Args:
            src_device: Source device path
            dst_device: Destination device path
            total_size: Total size to clone
        """
        def progress_callback(copied):
            percent = (copied / total_size) * 100 if total_size > 0 else 0
            self.root.after(0, self.update_progress, copied, total_size, percent)

        def error_callback(msg):
            self.root.after(0, self.clone_error, msg)

        try:
            clone_disk_with_callback(
                src_device, dst_device, total_size,
                CHUNK_SIZE, progress_callback, error_callback
            )
            self.root.after(0, self.clone_complete)
        except Exception as e:
            error_callback(str(e))

    def update_progress(self, copied_bytes: int, total_size: int, percent: float):
        """Update progress display."""
        self.progress_var.set(percent)
        if total_size > 0:
            self.status_var.set(
                f"Cloning... {copied_bytes}/{total_size} bytes ({percent:.2f}%)"
            )
        else:
            self.status_var.set(
                f"Cloning... {copied_bytes} bytes copied (unknown total)"
            )

    def clone_error(self, err_msg: str):
        """Handle clone operation error."""
        messagebox.showerror("Clone Error", f"An error occurred:\n\n{err_msg}")
        self.clone_button.config(state="normal")
        self.status_var.set("Clone failed")
        self.cloning_in_progress = False

    def clone_complete(self):
        """Handle clone operation completion."""
        if not self.cloning_in_progress:
            return

        self.cloning_in_progress = False
        
        # Check if verification is requested
        if self.verify_after_clone.get():
            if messagebox.askyesno(
                "Clone Complete",
                "Cloning completed successfully. Proceed with verification?"
            ):
                self.start_verification()
                return

        # No verification, just complete
        self.status_var.set("Clone complete")
        self.clone_button.config(state="normal")
        self.progress_var.set(100)
        messagebox.showinfo("Success", "Cloning operation completed successfully!")

    def start_verification(self):
        """Start the verification process."""
        self.status_var.set("Starting verification...")
        self.progress_var.set(0)
        
        threading.Thread(
            target=self.verify_thread,
            args=(self.source_drive_device, self.dest_drive_device),
            daemon=True
        ).start()

    def verify_thread(self, source: str, destination: str):
        """
        Thread function for verification process.
        Args:
            source: Source device path
            destination: Destination device path
        """
        def progress_callback(verified: int, total: int):
            percent = (verified / total) * 100 if total > 0 else 0
            self.root.after(0, self.update_verify_progress, verified, total, percent)

        success, message, differences = DiskVerifier.verify_disks(
            source, destination, CHUNK_SIZE, progress_callback
        )

        self.root.after(0, self.verify_complete, success, message, differences)

    def update_verify_progress(self, verified_bytes: int, total_bytes: int, percent: float):
        """
        Update verification progress display.
        Args:
            verified_bytes: Number of bytes verified
            total_bytes: Total bytes to verify
            percent: Completion percentage
        """
        self.progress_var.set(percent)
        self.status_var.set(
            f"Verifying... {verified_bytes}/{total_bytes} bytes ({percent:.2f}%)"
        )

    def verify_complete(self, success: bool, message: str, differences: List[Dict]):
        """
        Handle verification completion.
        Args:
            success: Whether verification was successful
            message: Status message
            differences: List of differences found
        """
        self.clone_button.config(state="normal")
        
        if success:
            self.status_var.set("Verification complete - Disks match")
            messagebox.showinfo(
                "Verification Complete",
                "Verification completed successfully. The disks match exactly."
            )
        else:
            self.status_var.set("Verification complete - Differences found")
            
            # Prepare detailed differences report
            detail = f"Message: {message}\n\n"
            if differences:
                detail += "First few differences:\n"
                for i, diff in enumerate(differences[:5]):
                    detail += (
                        f"Offset {diff['offset']}: "
                        f"Source={diff['source_sample']}, "
                        f"Dest={diff['dest_sample']}\n"
                    )
                if len(differences) > 5:
                    detail += f"\n... and {len(differences) - 5} more differences"
            
            # Show error dialog
            messagebox.showerror("Verification Failed", detail)

    def cleanup(self):
        """Perform cleanup operations before application exit."""
        try:
            if hasattr(self, 'validator'):
                del self.validator  # This will trigger __del__ and cleanup WMI
        except:
            pass

##############################
# MAIN ENTRY POINT
##############################
def main():
    """Main entry point for the application."""
    try:
        # Set up the root window
        root = tk.Tk()
        root.title("Disk Cloner")
        
        # Set window icon if available
        try:
            # You could add your own icon here
            # root.iconbitmap("diskcloner.ico")
            pass
        except:
            pass

        # Configure style
        style = ttk.Style()
        style.configure('TButton', padding=5)
        style.configure('TLabelframe', padding=5)
        
        # Create application instance
        app = DiskClonerApp(root)
        
        # Set up cleanup on window close
        def on_closing():
            app.cleanup()
            root.destroy()
        root.protocol("WM_DELETE_WINDOW", on_closing)
        
        # Start the application
        root.mainloop()
        
    except Exception as e:
        # Handle any unexpected errors
        error_msg = f"Unexpected error: {str(e)}\n\n{traceback.format_exc()}"
        try:
            messagebox.showerror("Error", error_msg)
        except:
            print(error_msg)
        sys.exit(1)

if __name__ == "__main__":
    main()