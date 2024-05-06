from ae64 import AE64
from ..connect import context
from pwn import asm, shellcraft

__all__ = [
    "ae64",
]

ae64 = AE64()

shellcode = asm(shellcraft.sh())
enc_shellcode = AE64().encode(shellcode)
