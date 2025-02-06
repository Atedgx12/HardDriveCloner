import subprocess
import logging
from typing import List, Tuple
import textwrap
from constants import OPEN_EXISTING  # If OPEN_EXISTING is needed elsewhere.
from errors import ShadowCopyError  # (Ensure this error is defined appropriately.)

def list_physical_drives_powershell(timeout: int = 30) -> List[Tuple[str, str, int]]:
    """
    List physical drives using PowerShell and return a list of tuples (device ID, model, size).

    This function runs a PowerShell script to query disk drives via CIM.
    It outputs each drive as a semicolon-separated string: DeviceID;Model;Size.
    Drives with an empty or zero size are skipped.

    Args:
        timeout (int): Maximum seconds to wait for the command execution.

    Returns:
        List[Tuple[str, str, int]]: A list of tuples containing:
            - device ID (str): The physical drive identifier in normalized format.
            - model (str): The drive model.
            - size (int): The drive size in bytes.
    """
    try:
        # Use Get-CimInstance instead of Get-WmiObject for better performance on modern systems.
        ps_script = textwrap.dedent("""
            $drives = Get-CimInstance -ClassName Win32_DiskDrive
            foreach ($d in $drives) {
                # Only output if Size is available
                if ($d.Size -ne $null) {
                    Write-Output "$($d.DeviceID);$($d.Model);$($d.Size)"
                }
            }
        """)
        logging.debug("Executing PowerShell script for drive enumeration:\n%s", ps_script)
        
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=True,
            text=True
        )
        output = result.stdout
        if not output.strip():
            logging.warning("PowerShell command returned empty output for drive enumeration.")
            return []

        results: List[Tuple[str, str, int]] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(";")
            if len(parts) != 3:
                logging.debug("Unexpected line format in drive enumeration: %s", line)
                continue
            dev_id, model, size_str = (part.strip() for part in parts)
            if not size_str:
                logging.warning("Empty size for drive %s. Skipping drive.", dev_id)
                continue
            try:
                size = int(size_str)
            except ValueError:
                logging.warning("Could not convert size '%s' to int for drive %s. Skipping drive.", size_str, dev_id)
                continue
            if size == 0:
                logging.warning("Drive %s has a size of 0 bytes. Skipping drive.", dev_id)
                continue
            # Normalize the device path to ensure it follows the "\\.\PHYSICALDRIVE" format.
            if not dev_id.upper().startswith('\\\\.\\PHYSICALDRIVE'):
                dev_id = dev_id.replace('\\.', '\\\\.\\')
            results.append((dev_id, model, size))
        
        logging.info("Found %d physical drives after filtering.", len(results))
        return results

    except subprocess.CalledProcessError as e:
        msg = e.output if e.output else str(e)
        logging.error("Failed to list drives via PowerShell: %s", msg)
        return []
    except subprocess.TimeoutExpired:
        logging.error("PowerShell command timed out after %d seconds.", timeout)
        return []
    except Exception as e:
        logging.error("Unexpected error during drive enumeration: %s", e, exc_info=True)
        return []
