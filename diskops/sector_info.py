# sector_info.py
import ctypes
from ctypes import byref, c_ulong, Structure, c_uint, c_longlong, c_void_p, get_last_error, WinError
import logging
from .raw_access import normalize_device_path
from errors import DeviceAccessError

# Windows IoControl codes for storage devices
IOCTL_DISK_BASE = 0x0007
IOCTL_STORAGE_BASE = 0x002D
METHOD_BUFFERED = 0
FILE_ANY_ACCESS = 0

IOCTL_DISK_GET_DRIVE_GEOMETRY = (IOCTL_DISK_BASE << 16) | (0x0000 << 2) | METHOD_BUFFERED | (FILE_ANY_ACCESS << 14)
IOCTL_STORAGE_QUERY_PROPERTY = (IOCTL_STORAGE_BASE << 16) | (0x0500 << 2) | METHOD_BUFFERED | (FILE_ANY_ACCESS << 14)

# Storage property query types and IDs
STORAGE_QUERY_TYPE_STANDARD = 0
STORAGE_ACCESS_ALIGNMENT_PROPERTY = 6
STORAGE_DEVICE_SEEK_PENALTY_PROPERTY = 7

# Storage property query structures
class STORAGE_PROPERTY_QUERY(Structure):
    _fields_ = [
        ("PropertyId", c_uint),
        ("QueryType", c_uint),
        ("AdditionalParameters", c_uint * 1)
    ]

class DEVICE_SEEK_PENALTY_DESCRIPTOR(Structure):
    _fields_ = [
        ("Version", c_uint),
        ("Size", c_uint),
        ("IncursSeekPenalty", c_uint)
    ]

class DISK_GEOMETRY(Structure):
    _fields_ = [
        ("Cylinders", c_longlong),
        ("MediaType", c_uint),
        ("TracksPerCylinder", c_uint),
        ("SectorsPerTrack", c_uint),
        ("BytesPerSector", c_uint)
    ]

class STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR(Structure):
    _fields_ = [
        ("Version", c_uint),
        ("Size", c_uint),
        ("BytesPerCacheLine", c_uint),
        ("BytesOffsetForCacheAlignment", c_uint),
        ("BytesPerLogicalSector", c_uint),
        ("BytesPerPhysicalSector", c_uint),
        ("BytesOffsetForSectorAlignment", c_uint)
    ]

def get_drive_characteristics(device: str) -> dict:
    """
    Get comprehensive drive characteristics including optimal transfer sizes.

    Args:
        device (str): Device path (e.g., "\\\\.\\PHYSICALDRIVE0").

    Returns:
        dict: Contains:
            - 'sector_size': Logical sector size in bytes.
            - 'physical_sector_size': Physical sector size in bytes.
            - 'alignment_offset': Required alignment offset in bytes.
            - 'is_ssd': Boolean indicating if the device is an SSD.
            - 'optimal_transfer_size': Recommended transfer size in bytes.

    Raises:
        DeviceAccessError: If unable to access the device or query properties.
    """
    try:
        normalized_path = normalize_device_path(device)
        logging.debug("Getting drive characteristics for: %s", normalized_path)
        
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.CreateFileW(
            ctypes.c_wchar_p(normalized_path),
            0x80000000,  # GENERIC_READ
            0x00000001 | 0x00000002,  # FILE_SHARE_READ | FILE_SHARE_WRITE
            None,
            3,  # OPEN_EXISTING
            0,  # No extra flags for property queries
            None
        )
        
        if handle == c_void_p(-1).value:
            error = f"Failed to open {normalized_path}: {WinError(get_last_error())}"
            logging.error(error)
            raise DeviceAccessError(error)
        
        try:
            # Retrieve basic drive geometry.
            geometry = DISK_GEOMETRY()
            bytes_returned = c_ulong(0)
            if not kernel32.DeviceIoControl(
                handle,
                IOCTL_DISK_GET_DRIVE_GEOMETRY,
                None,
                0,
                byref(geometry),
                ctypes.sizeof(geometry),
                byref(bytes_returned),
                None
            ):
                error = f"Failed to get geometry for {normalized_path}: {WinError(get_last_error())}"
                logging.error(error)
                raise DeviceAccessError(error)
            
            # Query alignment information.
            alignment_desc = STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR()
            alignment_query = STORAGE_PROPERTY_QUERY()
            alignment_query.PropertyId = STORAGE_ACCESS_ALIGNMENT_PROPERTY
            alignment_query.QueryType = STORAGE_QUERY_TYPE_STANDARD
            
            alignment_success = kernel32.DeviceIoControl(
                handle,
                IOCTL_STORAGE_QUERY_PROPERTY,
                byref(alignment_query),
                ctypes.sizeof(alignment_query),
                byref(alignment_desc),
                ctypes.sizeof(alignment_desc),
                byref(bytes_returned),
                None
            )
            if not alignment_success:
                logging.warning("Failed to get alignment info for %s, using defaults", normalized_path)
                physical_sector_size = geometry.BytesPerSector
                alignment_offset = 0
            else:
                physical_sector_size = alignment_desc.BytesPerPhysicalSector or geometry.BytesPerSector
                alignment_offset = alignment_desc.BytesOffsetForSectorAlignment
            
            # Determine if the drive is an SSD using the seek penalty query.
            seek_desc = DEVICE_SEEK_PENALTY_DESCRIPTOR()
            seek_query = STORAGE_PROPERTY_QUERY()
            seek_query.PropertyId = STORAGE_DEVICE_SEEK_PENALTY_PROPERTY
            seek_query.QueryType = STORAGE_QUERY_TYPE_STANDARD
            
            is_ssd = None
            if kernel32.DeviceIoControl(
                handle,
                IOCTL_STORAGE_QUERY_PROPERTY,
                byref(seek_query),
                ctypes.sizeof(seek_query),
                byref(seek_desc),
                ctypes.sizeof(seek_desc),
                byref(bytes_returned),
                None
            ):
                is_ssd = not bool(seek_desc.IncursSeekPenalty)
                logging.debug("Device %s determined to be %s via seek penalty query.",
                              normalized_path, "SSD" if is_ssd else "HDD")
            else:
                logging.warning("Could not determine drive type via seek penalty query for %s.", normalized_path)
                # Fallback heuristic: use WMI to inspect the drive's model.
                try:
                    import wmi
                    c = wmi.WMI()
                    drives = c.Win32_DiskDrive(DeviceID=normalized_path)
                    if drives:
                        model = drives[0].Model.upper()
                        if "SSD" in model:
                            is_ssd = True
                        elif "USB" in model:
                            # Optionally, treat USB drives as non-SSD for performance reasons.
                            is_ssd = False
                        else:
                            is_ssd = False
                        logging.debug("Heuristic based on drive model '%s': %s", model, "SSD" if is_ssd else "HDD")
                    else:
                        logging.warning("No drive found via WMI for %s; defaulting to HDD.", normalized_path)
                        is_ssd = False
                except Exception as ex:
                    logging.warning("WMI heuristic failed for %s: %s; defaulting to HDD.", normalized_path, ex)
                    is_ssd = False
            
            # Calculate the optimal transfer size.
            if is_ssd:
                optimal_transfer = max(
                    physical_sector_size * 2048,  # e.g., ~1MB minimum for SSDs.
                    (alignment_desc.BytesPerCacheLine * 1024) if alignment_success and alignment_desc.BytesPerCacheLine else 1048576
                )
            else:
                optimal_transfer = max(
                    physical_sector_size * 256,  # e.g., ~128KB minimum for HDDs.
                    (alignment_desc.BytesPerCacheLine * 128) if alignment_success and alignment_desc.BytesPerCacheLine else 131072
                )
            
            # Ensure that the optimal transfer size is properly aligned.
            if alignment_offset:
                optimal_transfer = (optimal_transfer + alignment_offset - 1) & ~(alignment_offset - 1)
            
            characteristics = {
                'sector_size': geometry.BytesPerSector,
                'physical_sector_size': physical_sector_size,
                'alignment_offset': alignment_offset,
                'is_ssd': is_ssd,
                'optimal_transfer_size': optimal_transfer
            }
            
            logging.debug("Drive characteristics for %s: %s", normalized_path, characteristics)
            logging.debug("Leaving handle open for persistent use.")
            return characteristics
        
        finally:
            # For persistent usage, the handle is intentionally left open.
            # If you cache the handle for extended operations, ensure that you eventually close it.
            pass
            
    except Exception as e:
        logging.error("Error getting drive characteristics: %s", str(e))
        # Return safe defaults if properties cannot be determined.
        return {
            'sector_size': 512,
            'physical_sector_size': 512,
            'alignment_offset': 0,
            'is_ssd': False,
            'optimal_transfer_size': 1048576  # Default 1MB transfer size.
        }

def get_sector_size(device: str) -> int:
    """
    Get the logical sector size for a device.
    
    Args:
        device (str): Device path (e.g., "\\\\.\\PHYSICALDRIVE0")
        
    Returns:
        int: Logical sector size in bytes.
    
    Raises:
        DeviceAccessError: If unable to query the device.
    """
    characteristics = get_drive_characteristics(device)
    return characteristics['sector_size']