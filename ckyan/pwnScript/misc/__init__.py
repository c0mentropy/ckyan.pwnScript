from ..connect import *
from pwn import p8, p16, p32, p64, u8, u16, u32, u64


def s(buf: bytes or str):
    if type(buf) == str:
        buf = buf.encode()

    return connect_io.conn.send(buf)


def sl(buf: bytes or str):
    if type(buf) == str:
        buf = buf.encode()

    return connect_io.conn.sendline(buf)


def sa(delim: bytes or str, buf: bytes or str):
    if type(delim) == str:
        delim = delim.encode()
    if type(buf) == str:
        buf = buf.encode()

    return connect_io.conn.sendafter(delim, buf)


def sla(delim: bytes or str, buf: bytes or str):
    if type(delim) == str:
        delim = delim.encode()
    if type(buf) == str:
        buf = buf.encode()

    return connect_io.conn.sendlineafter(delim, buf)


def uu64(buf: bytes or str):
    if type(buf) == str:
        buf = buf.encode()
    return u64(buf.ljust(8, b'\x00'))


def uu32(buf: bytes or str):
    if type(buf) == str:
        buf = buf.encode()
    return u32(buf.ljust(4, b'\x00'))


def r(n: int = None, timeout: int = 2):
    return connect_io.conn.recv(n, timeout=timeout)


def ru(delim: bytes or str, timeout: int = 2):
    if type(delim) == str:
        delim = delim.encode()

    return connect_io.conn.recvuntil(delim, timeout=timeout)


def ra():
    return connect_io.conn.recvall()


def r7f(timeout: int = 2):
    return uu64(connect_io.conn.recvuntil(b"\x7f", timeout=timeout)[-6:])


def rf7(timeout: int = 2):
    return uu32(connect_io.conn.recvuntil(b"\xf7", timeout=timeout)[-4:])


def sh():
    return connect_io.conn.interactive()


def ia():
    return sh()


def trs(addr: int):
    return connect_io.libc.address + addr


def gadget(ins: bytes or str):
    if type(ins) == bytes:
        ins = ins.decode()
    return next(connect_io.libc.search(asm(ins), executable=True))


def elf_gadget(ins: bytes or str):
    if type(ins) == bytes:
        ins = ins.decode()
    return next(connect_io.elf.search(asm(ins), executable=True))


def srh(buf: bytes or str):
    if type(buf) == str:
        buf = buf.encode()
    return next(connect_io.libc.search(buf))


def elf_srh(buf: bytes or str):
    if type(buf) == str:
        buf = buf.encode()
    return next(connect_io.elf.search(buf))


def tohex(buf: bytes or str):
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


def log_canary(addr: int):
    if addr % 0x100 == 0:
        log_addr("canary", addr)
    else:
        warning("Warning! The canary value may be wrong!")
        warning(f"canary => 0x%x" % addr)


def log_leak_addr(addr: int):
    return log_addr("leak_addr", addr)


def recv_canary_and_log() -> int:
    try:
        ru(b'0x', timeout=2)
        canary = int(r(16), 16)
        log_canary(canary)
        return canary
    except Exception as ex:
        error(f"Error: Can't recv until '0x' --> {str(ex)}")
        try:
            canary = u64(r(8))
            log_canary(canary)
            return canary
        except Exception as ex:
            error(f"Error: Can't recv 8 bytes --> {str(ex)}")
            try:
                canary = uu64(r(7))
                log_canary(canary)
                return canary
            except Exception as ex:
                error(f"Error: Can't recv 7 bytes --> {str(ex)}")

