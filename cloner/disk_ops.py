#!/usr/bin/env python
"""
disk_ops.py - A façade module for disk cloning operations.

This module re-exports functions from the diskops package so that other modules
can continue to import from disk_ops without any changes. Additionally, each function
is wrapped with error handling and logging to trace issues and manage errors centrally.
"""

import logging

# Import functions and classes from the internal submodules (using the package name)
from diskops.powershell_helpers import _run_powershell, _parse_ps_keyvalue_output
from diskops.drive_enumeration import list_physical_drives_powershell as _list_physical_drives_powershell
from diskops.validation import validate_source_destination_powershell as _validate_source_destination_powershell
from diskops.shadow_copy import (
    list_existing_shadow_copies as _list_existing_shadow_copies,
    cleanup_old_shadow_copies as _cleanup_old_shadow_copies,
    wait_for_shadow_copy as _wait_for_shadow_copy,
    get_volume_letter_for_physical_drive as _get_volume_letter_for_physical_drive,
    create_shadow_copy as _create_shadow_copy
)
from diskops.verification import DiskVerifier as _DiskVerifier
from diskops.cloning import clone_disk_with_callback as _clone_disk_with_callback
from diskops.raw_access import normalize_device_path as _normalize_device_path, open_raw_device_fd as _open_raw_device_fd
from diskops.partition_expansion import expand_partition as _expand_partition
from diskops.sector_info import get_sector_size as _get_sector_size

# Re-export constants as well.
from constants import (
    GENERIC_READ, GENERIC_WRITE, OPEN_EXISTING,
    FILE_SHARE_READ, FILE_SHARE_WRITE, SHADOW_COPY_TIMEOUT,
    MAX_SHADOW_COPIES, CHUNK_SIZE
)

def wrap_function(func):
    """
    Wrap a function to add error handling and logging.
    
    If an error occurs, the function's name and error are logged with a traceback,
    then the exception is re-raised.
    """
    def wrapped(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logging.error("Error in %s: %s", func.__name__, e, exc_info=True)
            raise
    return wrapped

# Wrap functions with our error handling helper.
list_physical_drives_powershell = wrap_function(_list_physical_drives_powershell)
validate_source_destination_powershell = wrap_function(_validate_source_destination_powershell)
list_existing_shadow_copies = wrap_function(_list_existing_shadow_copies)
cleanup_old_shadow_copies = wrap_function(_cleanup_old_shadow_copies)
wait_for_shadow_copy = wrap_function(_wait_for_shadow_copy)
get_volume_letter_for_physical_drive = wrap_function(_get_volume_letter_for_physical_drive)
create_shadow_copy = wrap_function(_create_shadow_copy)
clone_disk_with_callback = wrap_function(_clone_disk_with_callback)
normalize_device_path = wrap_function(_normalize_device_path)
open_raw_device_fd = wrap_function(_open_raw_device_fd)
expand_partition = wrap_function(_expand_partition)
get_sector_size = wrap_function(_get_sector_size)

# Re-export DiskVerifier without wrapping the class itself. (If you need method-level wrapping,
# you can modify the class methods inside its module.)
DiskVerifier = _DiskVerifier
