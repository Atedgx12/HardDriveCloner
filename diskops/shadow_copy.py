import textwrap
import re
import logging
import time
from typing import List, Dict, Optional
from datetime import datetime
from .powershell_helpers import _run_powershell, _parse_ps_keyvalue_output
from errors import ShadowCopyError
from constants import MAX_SHADOW_COPIES, SHADOW_COPY_TIMEOUT

def list_existing_shadow_copies(volume_letter: str) -> List[Dict[str, str]]:
    """
    Retrieve existing shadow copies for a given volume letter.

    This function queries WMI via PowerShell for shadow copies on a specified volume.
    It returns a list of dictionaries containing keys such as "ID", "InstallDate", and "DeviceObject".

    Args:
        volume_letter (str): The drive letter (e.g., 'C').

    Returns:
        List[Dict[str, str]]: List of dictionaries representing shadow copy information.

    Raises:
        ShadowCopyError: If the volume letter is invalid.
    """
    # Normalize and validate the volume letter.
    volume_letter = volume_letter.strip().rstrip(':\\')
    if not volume_letter or len(volume_letter) != 1 or not volume_letter.isalpha():
        raise ShadowCopyError(f"Invalid volume letter: {volume_letter}")

    # Build the PowerShell script.
    ps_script = textwrap.dedent(f"""
        $all = Get-WmiObject Win32_ShadowCopy -EnableAllPrivileges |
               Where-Object {{ $_.VolumeName -eq '{volume_letter}:\\' }}
        $all | ForEach-Object {{
            Write-Output "ID : $($_.ID)"
            Write-Output "InstallDate : $($_.InstallDate)"
            Write-Output "DeviceObject : $($_.DeviceObject)"
            Write-Output ""
        }}
    """)
    try:
        output = _run_powershell(ps_script)
    except Exception as e:
        logging.error("Failed to list shadow copies: %s", e, exc_info=True)
        raise ShadowCopyError("Error retrieving shadow copy information.") from e

    shadows: List[Dict[str, str]] = []
    current: Dict[str, str] = {}
    pattern = re.compile(r'^(?P<key>\w+)\s*:\s*(?P<value>.+)$')
    for line in output.splitlines():
        line = line.strip()
        if not line:
            if current:
                shadows.append(current)
                current = {}
            continue
        match = pattern.match(line)
        if match:
            key = match.group("key")
            value = match.group("value").strip().strip('"')
            current[key] = value
        else:
            logging.debug("Line did not match expected pattern: %s", line)
    if current:
        shadows.append(current)
    logging.debug("Found %d shadow copies on volume %s.", len(shadows), volume_letter)
    return shadows

def parse_install_date(date_str: str) -> datetime:
    """
    Parse the WMI InstallDate string into a datetime object.

    The expected format is "YYYYMMDDHHMMSS..." (we use the first 14 characters).

    Args:
        date_str (str): The WMI date string.

    Returns:
        datetime: The parsed datetime. If parsing fails, returns datetime.min.
    """
    try:
        return datetime.strptime(date_str[:14], "%Y%m%d%H%M%S")
    except Exception as e:
        logging.debug("Failed to parse InstallDate '%s': %s", date_str, e)
        return datetime.min

def cleanup_old_shadow_copies(volume_letter: str, max_copies: int = MAX_SHADOW_COPIES) -> None:
    """
    Clean up old shadow copies on the specified volume if the count exceeds max_copies - 1.

    Shadow copies are sorted by their InstallDate (oldest first) and deleted until the count is below the threshold.

    Args:
        volume_letter (str): The drive letter (e.g., 'C').
        max_copies (int): The maximum allowed shadow copies (default is MAX_SHADOW_COPIES).

    Raises:
        ShadowCopyError: If deletion fails for any shadow copy.
    """
    try:
        shadows = list_existing_shadow_copies(volume_letter)
        logging.debug("Cleanup: %d shadow copies found for volume %s.", len(shadows), volume_letter)
        if len(shadows) >= max_copies - 1:
            shadows.sort(key=lambda x: parse_install_date(x.get('InstallDate', "")))
            while len(shadows) >= max_copies - 1:
                oldest = shadows.pop(0)
                sid = oldest.get("ID")
                if sid:
                    ps_delete = textwrap.dedent(f"""
                        Get-WmiObject Win32_ShadowCopy -EnableAllPrivileges |
                        Where-Object {{ $_.ID -eq '{sid}' }} |
                        ForEach-Object {{ $_.Delete() }}
                    """)
                    try:
                        _run_powershell(ps_delete)
                        logging.info(f"Deleted old shadow copy {sid}")
                    except ShadowCopyError as e:
                        logging.warning(f"Failed to delete old shadow copy {sid}: {e}")
    except Exception as e:
        logging.warning(f"Shadow copy cleanup failed: {e}")

def wait_for_shadow_copy(shadow_id: str, timeout: int = SHADOW_COPY_TIMEOUT) -> bool:
    """
    Poll for a shadow copy to become ready.

    It repeatedly queries the shadow copy status via PowerShell until the status is "12" (indicating readiness)
    or the specified timeout is reached.

    Args:
        shadow_id (str): The identifier of the shadow copy.
        timeout (int): Maximum seconds to wait (default is SHADOW_COPY_TIMEOUT).

    Returns:
        bool: True if the shadow copy becomes ready within the timeout; otherwise, False.
    """
    start = time.time()
    while (time.time() - start) < timeout:
        try:
            ps_script = textwrap.dedent(f"""
                $sc = Get-WmiObject Win32_ShadowCopy -EnableAllPrivileges |
                      Where-Object {{ $_.ID -eq '{shadow_id}' }}
                if ($sc) {{
                    Write-Output "Status : $($sc.Status)"
                }}
            """)
            output = _run_powershell(ps_script)
            status: Optional[str] = _parse_ps_keyvalue_output(output, "Status")
            if status == "12":
                logging.debug("Shadow copy %s is ready (Status: %s).", shadow_id, status)
                return True
            else:
                logging.debug("Shadow copy %s status: %s", shadow_id, status)
        except Exception as e:
            logging.debug("Exception while checking status for shadow copy %s: %s", shadow_id, e)
        time.sleep(1)
    logging.warning("Timeout reached: shadow copy %s not ready within %d seconds.", shadow_id, timeout)
    return False

def get_volume_letter_for_physical_drive(physical_drive: str) -> str:
    """
    Automatically determine the volume letter associated with the given physical drive.

    This function extracts the disk number from the physical drive (e.g., "\\.\PHYSICALDRIVE8")
    and uses PowerShell's Get-Partition cmdlet to retrieve the first partition with an assigned drive letter.

    Args:
        physical_drive (str): The physical drive path.

    Returns:
        str: The drive letter (e.g., "C").

    Raises:
        ValueError: If the drive number cannot be extracted or no drive letter is found.
    """
    m = re.search(r'PHYSICALDRIVE(\d+)', physical_drive, re.IGNORECASE)
    if not m:
        raise ValueError("Invalid physical drive format")
    disk_number = m.group(1)
    ps_script = textwrap.dedent(f"""
        $part = Get-Partition -DiskNumber {disk_number} | Where-Object {{$_.DriveLetter -ne $null}} | Select-Object -First 1
        if ($part) {{
            Write-Output "DriveLetter : $($part.DriveLetter)"
        }}
    """)
    output = _run_powershell(ps_script)
    letter = _parse_ps_keyvalue_output(output, "DriveLetter")
    if not letter:
        raise ValueError("Could not determine volume letter for physical drive")
    return letter

def create_shadow_copy(source: str,
                       cleanup: bool = True,
                       timeout: int = SHADOW_COPY_TIMEOUT) -> str:
    """
    Create a shadow copy for the source drive automatically.

    The function determines the volume letter associated with the source drive, cleans up
    old shadow copies if necessary, and then creates a new shadow copy. It waits until the
    shadow copy is ready and returns the DeviceObject path.

    Args:
        source (str): The source device (e.g., "\\.\PHYSICALDRIVE8").
        cleanup (bool): Whether to clean up old shadow copies before creation.
        timeout (int): Maximum seconds to wait for the shadow copy to become ready.

    Returns:
        str: The DeviceObject path of the created shadow copy.

    Raises:
        ShadowCopyError: If shadow copy creation fails or the shadow copy is not ready.
    """
    try:
        volume_letter = get_volume_letter_for_physical_drive(source)
    except Exception as e:
        raise ShadowCopyError(f"Could not determine volume letter for source drive: {e}")
    
    vol_path = f"{volume_letter}:\\"  # e.g., "C:\\"
    
    if cleanup:
        cleanup_old_shadow_copies(volume_letter)
    
    create_script = textwrap.dedent(f"""
        $shadowClass = [wmiclass]"\\.\root\cimv2:Win32_ShadowCopy"
        $res = $shadowClass.Create("{vol_path}")
        Write-Output "ReturnValue : $($res.ReturnValue)"
        Write-Output "ShadowID    : $($res.ShadowID)"
    """)
    
    output = _run_powershell(create_script)
    ret_val: Optional[str] = _parse_ps_keyvalue_output(output, "ReturnValue")
    shadow_id: Optional[str] = _parse_ps_keyvalue_output(output, "ShadowID")
    
    if not ret_val or ret_val != "0":
        raise ShadowCopyError(f"Shadow copy creation failed. ReturnValue={ret_val or 'Unknown'}")
    if not shadow_id:
        raise ShadowCopyError("Failed to parse a valid ShadowID from shadow copy creation.")
    
    logging.info("Shadow copy creation initiated. ShadowID: %s", shadow_id)
    
    if not wait_for_shadow_copy(shadow_id, timeout):
        raise ShadowCopyError(f"Shadow copy (ID={shadow_id}) not ready within {timeout} seconds.")
    
    dev_script = textwrap.dedent(f"""
        $sc = Get-WmiObject Win32_ShadowCopy -EnableAllPrivileges |
              Where-Object {{ $_.ID -eq '{shadow_id}' }}
        if ($sc) {{
            Write-Output "DeviceObject : $($sc.DeviceObject)"
        }}
    """)
    dev_out = _run_powershell(dev_script)
    device_object: Optional[str] = _parse_ps_keyvalue_output(dev_out, "DeviceObject")
    if not device_object:
        raise ShadowCopyError("Shadow copy created but DeviceObject not found.")
    
    try:
        import win32file
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
    except Exception as e:
        raise ShadowCopyError(f"Created shadow copy is not accessible: {e}")
    
    logging.info("Shadow copy created successfully: %s", shadow_id)
    return device_object
