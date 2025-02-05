import os
import ctypes
import msvcrt
import logging
from typing import Any
from errors import DeviceAccessError
from constants import GENERIC_READ, GENERIC_WRITE

FILE_FLAG_NO_BUFFERING = 0x20000000
FILE_FLAG_WRITE_THROUGH = 0x80000000

def normalize_device_path(path: str) -> str:
    """
    Normalize a device path to Windows format.
    
    Args:
        path (str): The device path to normalize (e.g., "PHYSICALDRIVE0" or "\\.\PHYSICALDRIVE0")
        
    Returns:
        str: Normalized path (e.g., "\\.\PHYSICALDRIVE0")
        
    Raises:
        ValueError: If path is invalid or empty
    """
    if not isinstance(path, str) or not path.strip():
        raise ValueError("Path must be a non-empty string")
        
    path = path.replace('/', '\\').strip('\\')
    path_upper = path.upper()
    logging.debug(f"Normalizing device path: {path}")
    
    if path_upper.startswith('PHYSICALDRIVE'):
        normalized = '\\\\.\\' + path
    elif path_upper.startswith('\\\\.\\PHYSICALDRIVE'):
        normalized = path
    elif path_upper.startswith('\\\\PHYSICALDRIVE'):
        normalized = '\\\\.' + path[1:]
    else:
        parts = path.split('\\')
        for part in parts:
            if part.upper().startswith('PHYSICALDRIVE'):
                normalized = '\\\\.\\' + part
                break
        else:
            raise ValueError(f"Invalid device path format: {path}")
    
    logging.debug(f"Normalized device path: {normalized}")
    return normalized

def open_raw_device_fd(path: str, access_flag: int) -> int:
    """
    Opens a raw device and returns its file descriptor.
    
    Args:
        path (str): The device path (e.g., "\\.\PHYSICALDRIVE8")
        access_flag (int): GENERIC_READ or GENERIC_WRITE
    
    Returns:
        int: File descriptor for the device
    
    Raises:
        DeviceAccessError: If device cannot be opened
    """
    logging.debug(f"open_raw_device_fd: path={path}, access_flag={access_flag}")
    normalized_path = normalize_device_path(path)
    if not normalized_path.upper().startswith('\\\\.\\PHYSICALDRIVE'):
        raise DeviceAccessError(f"Invalid device path: {normalized_path}")
    if os.name != 'nt':
        raise DeviceAccessError("open_raw_device_fd is only supported on Windows platforms.")
    
    kernel32 = ctypes.windll.kernel32
    # For write operations, combine NO_BUFFERING with WRITE_THROUGH.
    if access_flag == GENERIC_WRITE:
        flags = FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH
    else:
        flags = FILE_FLAG_NO_BUFFERING
    
    handle = kernel32.CreateFileW(
        ctypes.c_wchar_p(normalized_path),
        access_flag,
        0x00000001 | 0x00000002,  # FILE_SHARE_READ | FILE_SHARE_WRITE
        None,
        3,  # OPEN_EXISTING
        flags,
        None
    )
    if handle == ctypes.c_void_p(-1).value:
        err_code = ctypes.get_last_error()
        if err_code == 5:
            raise DeviceAccessError(f"Access denied to {normalized_path}. Run as admin.")
        raise DeviceAccessError(f"Failed to open {normalized_path}: {ctypes.WinError(err_code)}")
    try:
        fd = msvcrt.open_osfhandle(handle, os.O_BINARY)
    except OSError as e:
        kernel32.CloseHandle(handle)
        raise DeviceAccessError(f"Failed to create file descriptor: {e}")
    
    logging.debug(f"Opened raw device file descriptor: {fd}")
    return fd

class RawDevice:
    """
    Context manager for raw device file descriptors.
    This class opens a raw device and returns its file descriptor.
    It keeps the device open until the context is exited, ensuring that the FD
    remains valid during long operations like cloning.
    """
    def __init__(self, path: str, access_flag: int):
        self.path = path
        self.access_flag = access_flag
        self.fd = None

    def __enter__(self):
        self.fd = open_raw_device_fd(self.path, self.access_flag)
        logging.debug(f"RawDevice opened with FD: {self.fd}")
        return self.fd

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.fd is not None:
            try:
                os.close(self.fd)
                logging.debug(f"RawDevice FD {self.fd} closed.")
            except Exception as e:
                logging.error(f"Error closing RawDevice FD {self.fd}: {e}")
        self.fd = None
        return False