class DiskOpsError(Exception):
    """Base exception for disk operations errors."""
    def __init__(self, message: str = "Disk operations error occurred"):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"DiskOpsError: {self.message}"


class DiskValidationError(DiskOpsError):
    """Exception raised for disk validation errors."""
    def __init__(self, message: str = "Disk validation error occurred"):
        super().__init__(message)

    def __str__(self):
        return f"DiskValidationError: {self.message}"


class ShadowCopyError(DiskOpsError):
    """Exception raised for errors during shadow copy operations."""
    def __init__(self, message: str = "Shadow copy operation error occurred"):
        super().__init__(message)

    def __str__(self):
        return f"ShadowCopyError: {self.message}"


class DeviceAccessError(DiskOpsError):
    """Exception raised for errors in accessing a device."""
    def __init__(self, message: str = "Device access error occurred"):
        super().__init__(message)

    def __str__(self):
        return f"DeviceAccessError: {self.message}"
