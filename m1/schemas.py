import ctypes
from ctypes import c_int, c_void_p, c_ubyte, c_ushort, c_ulong, POINTER

dll = ctypes.WinDLL("./hfrdapi.dll")
HID_DEVICE = c_void_p

# ---- Sys ----
dll.Sys_Open.argtypes = [POINTER(c_void_p), c_ulong, c_ushort, c_ushort]
dll.Sys_Open.restype = c_int

dll.Sys_Close.argtypes = [POINTER(c_void_p)]
dll.Sys_Close.restype = c_int

dll.Sys_InitType.argtypes = [HID_DEVICE, c_ubyte]
dll.Sys_InitType.restype = c_int

dll.Sys_SetAntenna.argtypes = [HID_DEVICE, c_ubyte]
dll.Sys_SetAntenna.restype = c_int

# ---- ISO14443A ----
dll.TyA_Request.argtypes = [HID_DEVICE, c_ubyte, POINTER(c_ushort)]
dll.TyA_Request.restype = c_int

dll.TyA_Anticollision.argtypes = [HID_DEVICE, c_ubyte, POINTER(c_ubyte), POINTER(c_ubyte)]
dll.TyA_Anticollision.restype = c_int

dll.TyA_Select.argtypes = [HID_DEVICE, POINTER(c_ubyte), c_ubyte, POINTER(c_ubyte)]
dll.TyA_Select.restype = c_int

dll.TyA_Halt.argtypes = [HID_DEVICE]
dll.TyA_Halt.restype = c_int

# ---- Mifare Classic ----
dll.TyA_CS_Authentication2.argtypes = [HID_DEVICE, c_ubyte, c_ubyte, POINTER(c_ubyte)]
dll.TyA_CS_Authentication2.restype = c_int

dll.TyA_CS_Read.argtypes = [HID_DEVICE, c_ubyte, POINTER(c_ubyte), POINTER(c_ubyte)]
dll.TyA_CS_Read.restype = c_int

dll.TyA_CS_Write.argtypes = [HID_DEVICE, c_ubyte, POINTER(c_ubyte)]
dll.TyA_CS_Write.restype = c_int
