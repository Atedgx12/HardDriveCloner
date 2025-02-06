import ctypes
from ctypes import byref, c_ulong, Structure, c_uint, c_ulonglong, c_longlong, c_void_p, get_last_error, WinError
import logging
from .raw_access import normalize_device_path
from errors import DeviceAccessError

# Windows IoControl codes
IOCTL_DISK_GET_DRIVE_GEOMETRY = 0x70000
IOCTL_STORAGE_QUERY_PROPERTY = 0x2D1400

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
        device (str): Device path (e.g., "\\\\.\\PHYSICALDRIVE0")
        
    Returns:
        dict containing:
            - sector_size: Logical sector size
            - physical_sector_size: Physical sector size
            - alignment_offset: Required alignment offset
            - is_ssd: Whether device is an SSD
            - optimal_transfer_size: Recommended transfer size
    """
    normalized_path = normalize_device_path(device)
    logging.debug(f"Getting drive characteristics for: {normalized_path}")
    
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.CreateFileW(
        ctypes.c_wchar_p(normalized_path),
        0x80000000,  # GENERIC_READ
        0x00000001 | 0x00000002,  # FILE_SHARE_READ | FILE_SHARE_WRITE
        None,
        3,  # OPEN_EXISTING
        0,  # No flags for property queries
        None
    )
    
    if handle == c_void_p(-1).value:
        error = f"Failed to open {normalized_path}: {WinError(get_last_error())}"
        logging.error(error)
        raise DeviceAccessError(error)
    
    try:
        # Get basic geometry
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
            raise DeviceAccessError(f"Failed to get geometry: {WinError(get_last_error())}")
            
        # Get alignment info
        alignment_query = STORAGE_PROPERTY_QUERY()
        alignment_query.PropertyId = 6  # StorageAccessAlignmentProperty
        alignment_query.QueryType = 0   # PropertyStandardQuery
        
        alignment_desc = STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR()
        
        if not kernel32.DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            byref(alignment_query),
            ctypes.sizeof(alignment_query),
            byref(alignment_desc),
            ctypes.sizeof(alignment_desc),
            byref(bytes_returned),
            None
        ):
            logging.warning("Failed to get alignment info, using defaults")
            alignment_desc.BytesPerPhysicalSector = geometry.BytesPerSector
            alignment_desc.BytesOffsetForSectorAlignment = 0
            
        # Check if device is SSD (no seek penalty)
        seek_query = STORAGE_PROPERTY_QUERY()
        seek_query.PropertyId = 7  # StorageDeviceSeekPenaltyProperty
        seek_desc = DEVICE_SEEK_PENALTY_DESCRIPTOR()
        
        is_ssd = False
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
        
        # Calculate optimal transfer size
        physical_sector = alignment_desc.BytesPerPhysicalSector or geometry.BytesPerSector
        
        if is_ssd:
            # For SSDs, use larger transfers
            optimal_transfer = max(
                physical_sector * 2048,  # ~1MB minimum
                alignment_desc.BytesPerCacheLine * 1024 if alignment_desc.BytesPerCacheLine else 1048576
            )
        else:
            # For HDDs, use moderate transfers
            optimal_transfer = max(
                physical_sector * 256,  # ~128KB minimum
                alignment_desc.BytesPerCacheLine * 128 if alignment_desc.BytesPerCacheLine else 131072
            )
        
        characteristics = {
            'sector_size': geometry.BytesPerSector,
            'physical_sector_size': physical_sector,
            'alignment_offset': alignment_desc.BytesOffsetForSectorAlignment,
            'is_ssd': is_ssd,
            'optimal_transfer_size': optimal_transfer
        }
        
        logging.debug(f"Drive characteristics: {characteristics}")
        return characteristics
        
    finally:
        kernel32.CloseHandle(handle)

def get_sector_size(device: str) -> int:
    """
    Legacy function to get sector size. Uses new characteristics function.
    """
    try:
        return get_drive_characteristics(device)['sector_size']
    except Exception as e:
        logging.error(f"Failed to get sector size: {e}")
        raise