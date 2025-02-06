import pythoncom
import wmi

pythoncom.CoInitialize()
c = wmi.WMI()
for disk in c.Win32_DiskDrive():
    print(disk.DeviceID, disk.Size)
pythoncom.CoUninitialize()
