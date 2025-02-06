# errors.py
class DiskValidationError(Exception):
    pass

class ShadowCopyError(Exception):
    pass

class DeviceAccessError(Exception):
    pass

# Optionally, add a base exception for your disk operations:
class DiskOpsError(Exception):
    pass
