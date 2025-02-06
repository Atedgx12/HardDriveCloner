 import textwrap
import logging
from typing import Optional
from diskops.powershell_helpers import _run_powershell, _parse_ps_keyvalue_output
from errors import DeviceAccessError

def _extract_disk_number(normalized_dest: str) -> Optional[int]:
    """
    Try to extract the disk number from a normalized physical drive path.
    E.g., '\\\\.\\PHYSICALDRIVE6' -> 6.
    
    Args:
        normalized_dest (str): Normalized device path.
    
    Returns:
        Optional[int]: The disk number if found, or None.
    """
    try:
        # The expected format is '\\.\PHYSICALDRIVE<number>'
        # We split on 'PHYSICALDRIVE' and parse the remainder.
        parts = normalized_dest.upper().split("PHYSICALDRIVE")
        if len(parts) == 2:
            disk_num = int(parts[1])
            return disk_num
    except Exception as e:
        logging.debug("Failed to extract disk number from %s: %s", normalized_dest, e)
    return None

def prepare_destination_partition(destination: str, source_size: int) -> str:
    """
    Prepare the destination disk by creating a partition that exactly matches the source size.
    
    This function uses PowerShell to:
      - Identify the destination disk based on the provided drive path.
      - Optionally, remove existing partitions (this operation will erase data).
      - Create a new partition with a size equal to the source disk.
      - Assign a drive letter to the new partition and return its device path.
    
    Args:
        destination (str): The destination physical drive (e.g., "\\.\PHYSICALDRIVE6").
        source_size (int): The size (in bytes) of the source disk.
    
    Returns:
        str: The device path of the newly created partition (e.g., "E:\").
    
    Raises:
        DeviceAccessError: If the partition creation fails or if the destination disk is not found.
    """
    # Validate source_size is a positive integer.
    if not isinstance(source_size, int) or source_size <= 0:
        raise ValueError("source_size must be a positive integer")
    
    # Import the raw_access module here to avoid circular dependencies.
    from .raw_access import normalize_device_path
    normalized_dest = normalize_device_path(destination)
    logging.debug("Normalized destination: %s", normalized_dest)
    
    # Attempt to extract disk number directly from the normalized destination.
    disk_number = _extract_disk_number(normalized_dest)
    
    # Build a robust PowerShell script.
    # If a disk number was extracted, filter by that; otherwise, filter on FriendlyName.
    if disk_number is not None:
        disk_filter = f"$disk = Get-Disk -Number {disk_number}"
    else:
        # Fall back to filtering by FriendlyName using a wildcard match.
        disk_filter = f"$disk = Get-Disk | Where-Object {{ $_.FriendlyName -like '*{normalized_dest}*' }} | Select-Object -First 1"
    
    ps_script = textwrap.dedent(f"""
        {disk_filter}
        if (-not $disk) {{
            Write-Output "Error: Destination disk not found"
            exit 1
        }}

        # Clear all partitions on the disk.
        try {{
            Clear-Disk -Number $disk.Number -RemoveData -Confirm:$false -ErrorAction Stop
        }} catch {{
            Write-Output "Error: Failed to clear disk partitions - $($_.Exception.Message)"
            exit 1
        }}

        # Create a new partition with the specified size.
        try {{
            $newPartition = New-Partition -DiskNumber $disk.Number -Size {source_size} -AssignDriveLetter -ErrorAction Stop
        }} catch {{
            Write-Output "Error: Failed to create new partition - $($_.Exception.Message)"
            exit 1
        }}

        if (-not $newPartition) {{
            Write-Output "Error: Partition creation returned null"
            exit 1
        }}

        # Output the drive letter path of the new partition.
        Write-Output "PartitionPath : $($newPartition.AccessPaths[0])"
    """)
    
    logging.debug("Executing PowerShell script for partition preparation...")
    try:
        output = _run_powershell(ps_script, timeout=120)
        logging.debug("PowerShell output: %s", output)
        
        # Check if output contains an error.
        if "Error:" in output:
            raise DeviceAccessError(f"PowerShell error: {output.strip()}")

        partition_path = _parse_ps_keyvalue_output(output, "PartitionPath")
        if not partition_path:
            raise DeviceAccessError("Failed to create destination partition; no partition path returned.")

        logging.info("Destination partition prepared successfully: %s", partition_path)
        return partition_path
    except Exception as e:
        logging.error("Error preparing destination partition: %s", e, exc_info=True)
        raise DeviceAccessError(f"Error preparing destination partition: {e}")