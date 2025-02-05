# errors.py

class DiskValidationError(Exception):
    """Custom exception for disk validation errors."""
    pass

class ShadowCopyError(Exception):
    """Custom exception for shadow copy operations."""
    pass

class DeviceAccessError(Exception):
    """Custom exception for device access errors."""
    pass
