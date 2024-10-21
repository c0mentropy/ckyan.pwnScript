from typing import Union

from ..connect import *
from pwn import Timeout, p8, p16, p32, p64, u8, u16, u32, u64
from pwnlib.timeout import TimeoutDefault

default_timeout = Timeout.default


def s(buf: Union[bytes, str]):
    if type(buf) == str:
        buf = buf.encode()

    return connect_io.conn.send(buf)


def sl(buf: Union[bytes, str]):
    if type(buf) == str:
        buf = buf.encode()

    return connect_io.conn.sendline(buf)


def sa(delim: Union[bytes, str], buf: Union[bytes, str], timeout: TimeoutDefault = default_timeout):
    if type(delim) == str:
        delim = delim.encode()
    if type(buf) == str:
        buf = buf.encode()

    return connect_io.conn.sendafter(delim, buf, timeout=timeout)


def sla(delim: Union[bytes, str], buf: Union[bytes, str], timeout: TimeoutDefault = default_timeout):
    if type(delim) == str:
        delim = delim.encode()
    if type(buf) == str:
        buf = buf.encode()

    return connect_io.conn.sendlineafter(delim, buf, timeout=timeout)


def uu64(buf: Union[bytes, str]):
    if type(buf) == str:
        buf = buf.encode()
    return u64(buf.ljust(8, b'\x00'))


def uu32(buf: Union[bytes, str]):
    if type(buf) == str:
        buf = buf.encode()
    return u32(buf.ljust(4, b'\x00'))


def r(n: int = None, timeout: TimeoutDefault = default_timeout):
    return connect_io.conn.recv(n, timeout=timeout)


def ru(delim: Union[bytes, str], drop: bool = False, timeout: TimeoutDefault = default_timeout):
    if type(delim) == str:
        delim = delim.encode()

    return connect_io.conn.recvuntil(delim, drop, timeout=timeout)


def ra(timeout: TimeoutDefault = default_timeout):
    return connect_io.conn.recvall(timeout=timeout)


# recvpred(self, pred, timeout = default):
def rp(pred, timeout: TimeoutDefault = default_timeout):
    return connect_io.conn.recvpred(pred, timeout)


def r7f(timeout: TimeoutDefault = default_timeout):
    return uu64(connect_io.conn.recvuntil(b"\x7f", timeout=timeout)[-6:])


def rf7(timeout: TimeoutDefault = default_timeout):
    return uu32(connect_io.conn.recvuntil(b"\xf7", timeout=timeout)[-4:])


def sh():
    return connect_io.conn.interactive()


def ia():
    return sh()


def trs(addr: int):
    return connect_io.libc.address + addr


def gadget(ins: Union[bytes, str]):
    if type(ins) == bytes:
        ins = ins.decode()
    return next(connect_io.libc.search(asm(ins), executable=True))


def elf_gadget(ins: Union[bytes, str]):
    if type(ins) == bytes:
        ins = ins.decode()
    return next(connect_io.elf.search(asm(ins), executable=True))


def srh(buf: Union[bytes, str]):
    if type(buf) == str:
        buf = buf.encode()
    return next(connect_io.libc.search(buf))


def elf_srh(buf: Union[bytes, str]):
    if type(buf) == str:
        buf = buf.encode()
    return next(connect_io.elf.search(buf))


def to_hex(buf: Union[bytes, str]):
    if type(buf) == bytes:
        buf = buf.decode()
    return b"".join(b"\\x%02x" % ord(_) for _ in buf)


def log_addr(func_name: str, addr: int):
    success(f"{func_name} => 0x%x" % addr)


def lg(func_name: str, addr: int):
    return log_addr(func_name, addr)


def set_libc_base_and_log(addr: int):
    # 0x7f397bbd3000
    if addr % 0x1000 == 0:
        connect_io.libc.address = addr
        log_addr("libc_base", addr)
        return connect_io.libc
    else:
        warning("Warning! The libc base address may be wrong!")
        warning(f"libc_base => 0x%x" % addr)


def set_elf_base_and_log(addr: int):
    if addr % 0x1000 == 0:
        connect_io.elf.address = addr
        log_addr("elf_base", addr)
        return connect_io.elf
    else:
        warning("Warning! The elf base address may be wrong!")
        warning(f"elf_base => 0x%x" % addr)


def log_heap_base_addr(addr: int):
    if addr % 0x1000 == 0:
        return log_addr("heap_base", addr)
    else:
        warning("Warning! The heap base address may be wrong!")
        warning(f"heap_base => 0x%x" % addr)


def log_stack_base_addr(addr: int):
    if addr % 0x1000 == 0:
        return log_addr("stack_base", addr)
    else:
        warning("Warning! The stack base address may be wrong!")
        warning(f"stack_base => 0x%x" % addr)


def log_leak_addr(addr: int):
    return log_addr("leak_addr", addr)


def log_canary(addr: int):
    if addr % 0x100 == 0:
        log_addr("canary", addr)
    else:
        warning("Warning! The canary value may be wrong!")
        warning(f"canary => 0x%x" % addr)


def recv_canary_and_log(timeout: TimeoutDefault = default_timeout) -> int:
    try:
        ru(b'0x', timeout=timeout)
        canary = int(r(16), 16)
        log_canary(canary)
        return canary
    except Exception as ex1:
        error(f"Error: Can't recv until '0x' --> {str(ex1)}")
        try:
            canary = u64(r(8))
            log_canary(canary)
            return canary
        except Exception as ex2:
            error(f"Error: Can't recv 8 bytes --> {str(ex2)}")
            try:
                canary = uu64(r(7))
                log_canary(canary)
                return canary
            except Exception as ex3:
                error(f"Error: Can't recv 7 bytes --> {str(ex3)}")
