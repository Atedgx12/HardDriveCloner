#!/usr/bin/env python
"""
expand_partition.py

This module provides functionality to expand a partition using PowerShell's 
Expand-Partition cmdlet. It validates the drive letter, clears the necessary 
data, and expands the partition to fill the available space. If any error occurs, 
a DeviceAccessError is raised.

Note: This operation will erase all data on the destination disk.
"""

import textwrap
import logging
from typing import Optional
from diskops.powershell_helpers import _run_powershell, _parse_ps_keyvalue_output
from errors import DeviceAccessError

def expand_partition(volume_letter: str) -> None:
    """
    Expand the partition on the given volume letter to fill available space.

    This function uses PowerShell's Expand-Partition cmdlet to expand the partition.
    It validates the input volume letter, executes the command, logs the output,
    and raises an exception if the command fails.

    Args:
        volume_letter (str): The drive letter (e.g., "E").

    Raises:
        ValueError: If the provided volume letter is invalid.
        DeviceAccessError: If the PowerShell command fails to execute or returns an error.
    """
    # Clean up the volume letter: remove any trailing colon or backslashes, then uppercase.
    volume_letter = volume_letter.strip().rstrip(':').upper()
    if not volume_letter or len(volume_letter) != 1 or not volume_letter.isalpha():
        raise ValueError(f"Invalid volume letter for partition expansion: '{volume_letter}'")
    
    # Prepare the PowerShell command using textwrap.dedent for clean formatting.
    ps_script = textwrap.dedent(f"""
        Expand-Partition -DriveLetter {volume_letter} -Confirm:$false
    """)
    
    logging.debug("Executing partition expansion for drive letter: %s", volume_letter)
    logging.debug("PowerShell script:\n%s", ps_script)
    
    try:
        # Execute the command with a timeout (e.g., 60 seconds).
        output = _run_powershell(ps_script, timeout=60).strip()
        
        if output:
            logging.info("Partition on drive %s expanded successfully. Output: %s", volume_letter, output)
        else:
            logging.info("Expand-Partition command executed for drive %s with no output.", volume_letter)
    except Exception as e:
        logging.error("Failed to expand partition on drive %s: %s", volume_letter, e, exc_info=True)
        raise DeviceAccessError(f"Failed to expand partition on drive {volume_letter}: {e}") from e

if __name__ == "__main__":
    # For testing purposes, run this module directly.
    import sys
    logging.basicConfig(level=logging.DEBUG)
    try:
        if len(sys.argv) < 2:
            print("Usage: python expand_partition.py <VolumeLetter>")
            sys.exit(1)
        vol = sys.argv[1]
        expand_partition(vol)
        print("Partition expanded successfully.")
    except Exception as ex:
        print(f"Error: {ex}")
