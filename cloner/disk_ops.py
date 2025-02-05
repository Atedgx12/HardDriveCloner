# disk_ops.py

import sys
import os
import time
import subprocess
import ctypes
import re
import traceback
import msvcrt
import logging
from typing import Tuple, List, Dict, Optional

# Custom error classes
from errors import DiskValidationError, ShadowCopyError, DeviceAccessError

from constants import (
    GENERIC_READ, GENERIC_WRITE, OPEN_EXISTING, FILE_SHARE_READ, FILE_SHARE_WRITE,
    SHADOW_COPY_TIMEOUT, MAX_SHADOW_COPIES, CHUNK_SIZE
)

###################################
# A) Logging Configuration
###################################
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('disk_cloner.log'),
        logging.StreamHandler(sys.stdout)
    ]
)


###################################
# 0) HELPER: Run PowerShell
###################################
def _run_powershell(command: str) -> str:
    """
    Runs a PowerShell command (string) and returns stdout as a decoded string.
    Raises ShadowCopyError if the command fails (for shadow operations).
    """
    try:
        output = subprocess.check_output(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
            stderr=subprocess.STDOUT
        )
        return output.decode(errors="ignore")
    except subprocess.CalledProcessError as e:
        err_out = e.output.decode(errors="ignore") if e.output else str(e)
        raise ShadowCopyError(f"PowerShell command failed:\n{err_out}")


def _parse_ps_keyvalue_output(output: str, key: str) -> Optional[str]:
    """
    Helper to parse lines like:
        ReturnValue : 0
        ShadowID    : {GUID}
    Returns the string after the colon if the line starts with 'key'.
    """
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*:\s*(.+)$", re.IGNORECASE)
    for line in output.splitlines():
        match = pattern.search(line.strip())
        if match:
            return match.group(1).strip().strip('"{}')
    return None


###################################
# 1) Listing Physical Drives via PowerShell
###################################
def list_physical_drives_powershell() -> List[Tuple[str, str, int]]:
    """
    Lists all physical drives using PowerShell (Win32_DiskDrive).
    Returns a list of (device_id, model, size) like:
        [("\\\\.\\PHYSICALDRIVE0", "Model XYZ", 500107862016), ...]
    """
    ps_script = r"""
    $drives = Get-WmiObject Win32_DiskDrive
    foreach ($d in $drives) {
        # DeviceID usually looks like '\\.\PHYSICALDRIVE0'
        Write-Host "$($d.DeviceID);$($d.Model);$($d.Size)"
    }
    """
    try:
        output = subprocess.check_output(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_script])
    except subprocess.CalledProcessError as e:
        msg = e.output.decode(errors="ignore") if e.output else str(e)
        logging.error(f"Failed to list drives via PowerShell: {msg}")
        return []

    lines = output.decode(errors="ignore").splitlines()
    results = []
    for line in lines:
        parts = line.split(";")
        if len(parts) == 3:
            dev_id, model, size_str = parts
            dev_id = dev_id.strip()
            model = model.strip()
            try:
                size = int(size_str.strip()) if size_str.strip().isdigit() else 0
            except:
                size = 0

            # Ensure consistent format, e.g. '\\\\.\\PHYSICALDRIVE0'
            # Some older Windows can return '\\.\PHYSICALDRIVE0'
            if not dev_id.upper().startswith('\\\\.\\PHYSICALDRIVE'):
                # Normalize
                dev_id = dev_id.replace('\\.', '\\\\.\\')
            results.append((dev_id, model, size))

    return results


###################################
# 2) Validate Source & Destination
###################################
def validate_source_destination_powershell(source: str, destination: str) -> Dict:
    """
    Validates source & destination by enumerating them via PowerShell (Win32_DiskDrive).
    Raises DiskValidationError on fatal issues.
    Returns a dict with keys: 'source_size', 'dest_size', 'warnings' (list of strings).
    For demonstration, 'source_volumes' and 'dest_volumes' are left empty or partially implemented.
    """
    if source == destination:
        raise DiskValidationError("Source and destination cannot be the same drive")

    # List all drives from PowerShell
    drives = list_physical_drives_powershell()
    # Convert to a dict for easy lookup
    # Key = normalized device_id (lowercase), Value = (model, size)
    drive_map = {}
    for (dev_id, model, sz) in drives:
        drive_map[dev_id.lower()] = (model, sz)

    # Check for existence
    if source.lower() not in drive_map:
        raise DiskValidationError(f"Source drive not found: {source}")
    if destination.lower() not in drive_map:
        raise DiskValidationError(f"Destination drive not found: {destination}")

    source_model, source_size = drive_map[source.lower()]
    dest_model, dest_size = drive_map[destination.lower()]

    # Compare sizes
    if dest_size < source_size:
        raise DiskValidationError(
            f"Destination drive too small.\n"
            f"Source: {source_size / (1024**3):.2f} GB\n"
            f"Destination: {dest_size / (1024**3):.2f} GB"
        )

    # Build results dict
    results = {
        'source_size': source_size,
        'dest_size': dest_size,
        'warnings': [],
        'source_volumes': [],
        'dest_volumes': []
    }

    # Optional: try to detect removable drives via Model or Size==0
    # (You could also do a more advanced check with Win32_DiskDrive.MediaType)
    if "USB" in source_model.upper():
        results['warnings'].append("Source drive appears to be USB/removable")
    if "USB" in dest_model.upper():
        results['warnings'].append("Destination drive appears to be USB/removable")

    # If you want to gather volume letters, you can do a separate PowerShell call
    # that enumerates partitions & logical disks. But that's advanced & optional.
    # For now, we skip it or just leave warnings empty.

    logging.info("Disk validation (PowerShell-based) successful.")
    return results


###################################
# 3) Shadow Copy Operations
###################################
def list_existing_shadow_copies(volume_letter: str) -> List[Dict[str, str]]:
    """
    Lists existing shadow copies for a given volume letter using PowerShell.
    """
    volume_letter = volume_letter.rstrip(':\\')
    if not volume_letter or len(volume_letter) != 1 or not volume_letter.isalpha():
        raise ShadowCopyError(f"Invalid volume letter: {volume_letter}")

    ps_script = f"""
        $all = Get-WmiObject Win32_ShadowCopy -EnableAllPrivileges |
               Where-Object {{ $_.VolumeName -eq '{volume_letter}:\\' }}
        $all | ForEach-Object {{
            Write-Host "ID : $($_.ID)"
            Write-Host "InstallDate : $($_.InstallDate)"
            Write-Host "DeviceObject : $($_.DeviceObject)"
            Write-Host ""
        }}
    """
    output = _run_powershell(ps_script)

    shadows = []
    current = {}
    for line in output.splitlines():
        line = line.strip()
        if not line:
            if current:
                shadows.append(current)
                current = {}
            continue
        if ':' in line:
            key, val = line.split(':', 1)
            current[key.strip()] = val.strip()

    if current:
        shadows.append(current)
    return shadows


def cleanup_old_shadow_copies(volume_letter: str, max_copies: int = MAX_SHADOW_COPIES) -> None:
    """
    Deletes older shadow copies if total count >= max_copies - 1
    """
    try:
        shadows = list_existing_shadow_copies(volume_letter)
        if len(shadows) >= max_copies - 1:
            # Sort by InstallDate
            shadows.sort(key=lambda x: x.get('InstallDate', ''))
            while len(shadows) >= max_copies - 1:
                oldest = shadows.pop(0)
                shadow_id = oldest.get("ID")
                if shadow_id:
                    ps_delete = f"""
                        Get-WmiObject Win32_ShadowCopy -EnableAllPrivileges |
                        Where-Object {{ $_.ID -eq '{shadow_id}' }} |
                        ForEach-Object {{ $_.Delete() }}
                    """
                    try:
                        _run_powershell(ps_delete)
                        logging.info(f"Deleted old shadow copy {shadow_id}")
                    except ShadowCopyError as e:
                        logging.warning(f"Failed to delete old shadow copy: {e}")
    except Exception as e:
        logging.warning(f"Shadow copy cleanup failed: {e}")


def wait_for_shadow_copy(shadow_id: str, timeout: int = SHADOW_COPY_TIMEOUT) -> bool:
    """
    Wait for shadow copy to be ready (Status = 12) up to `timeout` seconds.
    """
    start = time.time()
    while (time.time() - start) < timeout:
        try:
            ps_script = f"""
                $sc = Get-WmiObject Win32_ShadowCopy -EnableAllPrivileges |
                      Where-Object {{ $_.ID -eq '{shadow_id}' }}
                if ($sc) {{
                    Write-Host "Status : $($sc.Status)"
                }}
            """
            output = _run_powershell(ps_script)
            status = _parse_ps_keyvalue_output(output, "Status")
            if status == "12":  # Shadow copy ready
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def create_shadow_copy(volume_letter: str,
                       cleanup: bool = True,
                       timeout: int = SHADOW_COPY_TIMEOUT) -> str:
    """
    Creates a volume shadow copy for `volume_letter`: e.g. "C"
    Returns the DeviceObject path. Raises ShadowCopyError on failure.
    """
    volume_letter = volume_letter.strip().rstrip(':\\')
    if not volume_letter or len(volume_letter) != 1 or not volume_letter.isalpha():
        raise ShadowCopyError("Invalid volume letter format")

    if cleanup:
        cleanup_old_shadow_copies(volume_letter)

    vol_path = f"{volume_letter}:\\"
    create_script = f"""
        $res = (Get-WmiObject -List Win32_ShadowCopy -EnableAllPrivileges).Create('{vol_path}')
        if ($res) {{
            $res | ForEach-Object {{
                Write-Host "ReturnValue : $($_.ReturnValue)"
                Write-Host "ShadowID    : $($_.ShadowID)"
            }}
        }}
    """
    output = _run_powershell(create_script)

    return_val = _parse_ps_keyvalue_output(output, "ReturnValue")
    shadow_id = _parse_ps_keyvalue_output(output, "ShadowID")
    if not return_val or return_val != "0":
        raise ShadowCopyError(f"Shadow copy creation failed. ReturnValue={return_val or 'Unknown'}")
    if not shadow_id:
        raise ShadowCopyError("Failed to parse valid ShadowID from shadow copy creation.")

    # Wait for readiness
    if not wait_for_shadow_copy(shadow_id, timeout):
        raise ShadowCopyError(f"Shadow copy (ID={shadow_id}) not ready within {timeout}s.")

    # Grab DeviceObject
    dev_script = f"""
        $sc = Get-WmiObject Win32_ShadowCopy -EnableAllPrivileges |
              Where-Object {{ $_.ID -eq '{shadow_id}' }}
        if ($sc) {{
            Write-Host "DeviceObject : $($sc.DeviceObject)"
        }}
    """
    dev_out = _run_powershell(dev_script)
    device_object = _parse_ps_keyvalue_output(dev_out, "DeviceObject")
    if not device_object:
        raise ShadowCopyError("Shadow copy created but DeviceObject not found.")

    # Basic check to ensure it opens
    import win32file, pywintypes
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
        raise ShadowCopyError(f"Shadow copy not accessible: {e}")

    logging.info(f"Shadow copy created successfully: {shadow_id}")
    return device_object


###################################
# 4) Disk Verification
###################################
class DiskVerifier:
    """
    Handles byte-for-byte verification after cloning,
    returning (success, message, differences).
    """
    @staticmethod
    def verify_disks(source: str,
                     destination: str,
                     chunk_size: int = CHUNK_SIZE,
                     progress_callback: Optional[callable] = None
                     ) -> Tuple[bool, str, List[Dict]]:
        """
        Byte-for-byte comparison. Returns (success, message, differences).
        """
        differences = []
        total_bytes = 0
        bytes_verified = 0

        try:
            with open_raw_device(source, GENERIC_READ) as src, \
                 open_raw_device(destination, GENERIC_READ) as dst:

                # Get total size from source
                src.seek(0, os.SEEK_END)
                total_bytes = src.tell()
                src.seek(0)

                while True:
                    src_chunk = src.read(chunk_size)
                    if not src_chunk:
                        break
                    dst_chunk = dst.read(len(src_chunk))
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
            msg = f"Verification failed: {e}"
            logging.error(msg, exc_info=True)
            return (False, msg, differences)

        if differences:
            msg = f"Found {len(differences)} differences"
            logging.warning(msg)
            return (False, msg, differences)

        success_msg = "Verification successful - disks match exactly"
        logging.info(success_msg)
        return (True, success_msg, [])


###################################
# 5) Cloning with Progress Callbacks
###################################
def clone_disk_with_callback(source: str,
                             destination: str,
                             total_size: int,
                             chunk_size: int,
                             progress_callback: callable,
                             error_callback: callable):
    """
    Performs raw disk cloning with progress updates.
    Catches exceptions, logs them, and calls error_callback on failure.
    """
    bytes_copied = 0
    src = None
    dst = None

    try:
        logging.info(f"Starting clone operation: {source} -> {destination}")

        # Normalize device paths
        source = normalize_device_path(source)
        destination = normalize_device_path(destination)
        logging.debug(f"Normalized paths: Source={source}, Dest={destination}")

        # Check that both drives exist
        all_drives = list_physical_drives_powershell()
        drive_paths = {d[0].lower() for d in all_drives}
        if source.lower() not in drive_paths:
            raise DeviceAccessError(f"Source device {source} not found in system")
        if destination.lower() not in drive_paths:
            raise DeviceAccessError(f"Destination device {destination} not found in system")

        logging.info("Opening source device")
        src = open_raw_device(source, GENERIC_READ)

        logging.info("Opening destination device")
        dst = open_raw_device(destination, GENERIC_WRITE)

        logging.info("Begin copying data...")
        while True:
            chunk = src.read(chunk_size)
            if not chunk:
                break
            dst.write(chunk)
            bytes_copied += len(chunk)
            if progress_callback:
                progress_callback(bytes_copied)

        logging.info("Clone operation completed successfully.")

    except Exception as e:
        err_msg = f"Cloning failed: {e}\nStack trace:\n{traceback.format_exc()}"
        logging.error(err_msg)
        error_callback(err_msg)
    finally:
        if src:
            try:
                src.close()
                logging.debug("Source device closed.")
            except Exception as e:
                logging.error(f"Error closing source device: {e}")
        if dst:
            try:
                dst.close()
                logging.debug("Destination device closed.")
            except Exception as e:
                logging.error(f"Error closing destination device: {e}")


###################################
# 6) Raw Device Open
###################################
def open_raw_device(path: str, access_flag: int):
    """
    Opens a raw device path (\\.\PhysicalDriveN) with the given access flag
    (GENERIC_READ or GENERIC_WRITE). Returns a file-like object.
    Raises DeviceAccessError on failure.
    """
    logging.debug(f"open_raw_device called with path={path}, access_flag={access_flag}")
    try:
        normalized_path = normalize_device_path(path)
        if not normalized_path.upper().startswith('\\\\.\\PHYSICALDRIVE'):
            raise DeviceAccessError(f"Invalid device path format: {normalized_path}")

        # CreateFileW call
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.CreateFileW(
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
                raise DeviceAccessError(
                    f"Access denied to device {normalized_path}. "
                    "Please run as administrator."
                )
            raise DeviceAccessError(
                f"Failed to open device {normalized_path}. Error code: {error_code}"
            )

        # Convert Windows handle to a Python file descriptor
        try:
            fd = msvcrt.open_osfhandle(handle, os.O_BINARY)
        except OSError as e:
            kernel32.CloseHandle(handle)
            raise DeviceAccessError(f"Failed to create file descriptor: {e}")

        # Wrap in a Python file object
        mode = 'rb' if access_flag == GENERIC_READ else 'wb'
        try:
            return os.fdopen(fd, mode, buffering=0)
        except Exception as e:
            os.close(fd)
            raise DeviceAccessError(f"Failed to create file object: {e}")

    except DeviceAccessError:
        raise
    except Exception as e:
        raise DeviceAccessError(f"Error in open_raw_device: {e}")
