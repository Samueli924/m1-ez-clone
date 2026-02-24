ERROR_CODE_MAP = {
    0x00: "SUCCESS",
    # ---- 通用 / 卡操作 ----
    0x0A: "GENERAL_ERROR",
    0x0B: "COMMAND_NOT_SUPPORTED",
    0x0C: "INVALID_PARAMETER",
    0x0D: "NO_CARD",
    0x0E: "RF_BASE_STATION_DAMAGED",
    0x14: "REQUEST_CARD_FAILED",
    0x15: "CARD_RESET_FAILED",
    0x16: "KEY_AUTH_FAILED",
    0x17: "READ_CARD_FAILED",
    0x18: "WRITE_CARD_FAILED",
    # ---- Flash ----
    0x51: "FLASH_BLOCK_ERROR",
    0x52: "FLASH_OFFSET_ERROR",
    0x53: "FLASH_LENGTH_ERROR",
    0x54: "FLASH_READ_FAILED",
    0x55: "FLASH_WRITE_FAILED",
    0x56: "FLASH_ERASE_FAILED",
    # ---- HID Device ----
    0xC0: "HID_DEVICE_FAILED",
    0xC1: "HID_DEVICE_NOT_FOUND",
    0xC2: "HID_DEVICE_NOT_OPENED",
    0xC3: "HID_DEVICE_ALREADY_OPENED",
    0xC4: "HID_DEVICE_TRANSFER_TIMEOUT",
    0xC5: "HID_DEVICE_TRANSFER_FAILED",
    0xC6: "HID_DEVICE_CANNOT_GET_HID_INFO",
    0xC7: "HID_DEVICE_HANDLE_ERROR",
    0xC8: "HID_DEVICE_INVALID_BUFFER_SIZE",
    0xC9: "HID_DEVICE_SYSTEM_CODE",
    0xCA: "HID_DEVICE_UNKNOWN_ERROR",
    # ---- Library ----
    0xE0: "LIB_FAILED",
    0xE1: "LIB_CHECKDATA_FAILED",
    0xE2: "LIB_LENGTH_FAILED",
    0xE3: "LIB_PARAMETER_FAILED",
}


class HidError(Exception):
    pass


class HidCallError(HidError):
    def __init__(self, func, code):
        name = ERROR_CODE_MAP.get(code, "UNKNOWN_ERROR")
        msg = f"[0x{code:02X}] {name}"
        if func:
            msg = f"{func}: {msg}"
        super().__init__(msg)
        
class NtagError(Exception):
    """Base class for all NTAG / HID related errors."""

    def __init__(self, code: int, func: str = None):
        self.code = code
        self.func = func
        name = ERROR_CODE_MAP.get(code, "UNKNOWN_ERROR")
        msg = f"[0x{code:02X}] {name}"
        if func:
            msg = f"{func}: {msg}"
        super().__init__(msg)


class DeviceError(NtagError):
    pass


class CardError(NtagError):
    pass


class FlashError(NtagError):
    pass


class LibraryError(NtagError):
    pass


ERROR_CATEGORY_MAP = {
    # Card / RF
    0x0A: CardError,
    0x0B: CardError,
    0x0C: CardError,
    0x0D: CardError,
    0x0E: DeviceError,
    0x14: CardError,
    0x15: CardError,
    0x16: CardError,
    0x17: CardError,
    0x18: CardError,
    # Flash
    0x51: FlashError,
    0x52: FlashError,
    0x53: FlashError,
    0x54: FlashError,
    0x55: FlashError,
    0x56: FlashError,
    # HID
    0xC0: DeviceError,
    0xC1: DeviceError,
    0xC2: DeviceError,
    0xC3: DeviceError,
    0xC4: DeviceError,
    0xC5: DeviceError,
    0xC6: DeviceError,
    0xC7: DeviceError,
    0xC8: DeviceError,
    0xC9: DeviceError,
    0xCA: DeviceError,
    # Library
    0xE0: LibraryError,
    0xE1: LibraryError,
    0xE2: LibraryError,
    0xE3: LibraryError,
}


def check_status(ret: int, func: str = None):
    """
    Check return code from DLL call.
    Raise exception if ret != 0x00.
    """
    if ret == 0x00:
        return

    exc_cls = ERROR_CATEGORY_MAP.get(ret, NtagError)

    raise exc_cls(ret, func)
