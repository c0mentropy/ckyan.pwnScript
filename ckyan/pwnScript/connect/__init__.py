from pwn import *

from ..args_parser import *
from ..log4ck import *
from ..exception_message import exception_message


class ConnectIO:
    def __init__(self, local: bool = True,
                 binary_path: str = "",
                 ip: str = "127.0.0.1",
                 port: int = 9999,
                 remote_libc_path: str = "",
                 tmux: bool = False,
                 ssl: bool = False):

        self.ropper_attack = None
        self.local = local
        self.binary_path = binary_path
        self.ip = ip
        self.port = port
        self.remote_libc_path = remote_libc_path

        self.ssl = ssl

        self.tmux = tmux

        self.elf = None
        self.libc = None

        self.conn = None

    # 这两个函数set和update，逻辑可以改一下。现在能跑但是有点乱 (over)
    def set_connect_parameter(self):
        if self.local:
            if self.binary_path is not None and self.binary_path != "":
                if os.path.exists(self.binary_path):

                    try:
                        self.elf = ELF(self.binary_path)
                        self.libc = self.elf.libc
                        context.binary = self.binary_path
                    except Exception as elf_ex:
                        error(f"{str(elf_ex) = }")

                    self.conn = process([self.binary_path])
                else:
                    error(exception_message.file_not_exist)
            else:
                error(exception_message.missing_key_documents)
        else:
            if self.binary_path is not None and self.binary_path != "":
                if os.path.exists(self.binary_path):
                    self.elf = ELF(self.binary_path)
                    self.libc = self.elf.libc
                    context.binary = self.binary_path
            if self.remote_libc_path is not None and self.remote_libc_path != "":
                self.libc = ELF(self.remote_libc_path)

            try:
                self.conn = remote(self.ip, self.port, ssl=self.ssl)
            except Exception as ex:
                if self.ip == "127.0.0.1" or self.port == "9999":
                    error(exception_message.remote_unreachable)
                else:
                    error(str(ex))

    def update_connect_parameter(self, local: bool = True,
                                 binary_path: str = "",
                                 ip: str = "127.0.0.1",
                                 port: int = 9999,
                                 remote_libc_path: str = ""):

        self.local = local
        self.binary_path = binary_path
        self.ip = ip
        self.port = port
        self.remote_libc_path = remote_libc_path

        # 这里好像直接调就可以了。。。不知道之前怎么想的
        self.set_connect_parameter()

        '''
        if self.local:
            self.elf = ELF(self.binary_path)
            self.libc = self.elf.libc

            context.binary = self.binary_path
            self.conn = process(self.binary_path)
        else:
            # 设置攻击远程时的elf文件，因为可能存在brop，即没有elf文件
            if self.binary_path is not None and self.binary_path != "":
                if os.path.exists(self.binary_path):
                    self.elf = ELF(self.binary_path)
                    self.libc = self.elf.libc

                    context.binary = self.binary_path

            # 设置攻击远程时的libc
            if self.remote_libc_path != "":
                self.libc = ELF(self.remote_libc_path)

            self.conn = remote(self.ip, self.port)
        '''

    def init_script(self):
        from ..stack import Amd64RopperAttack, I386RopperAttack

        self.set_connect_parameter()

        if context.arch == "amd64":
            self.ropper_attack = Amd64RopperAttack()
        elif context.arch == "i386":
            self.ropper_attack = I386RopperAttack()

    def update_script(self, local: bool = True,
                      binary_path: str = "",
                      ip: str = "127.0.0.1",
                      port: int = 9999,
                      remote_libc_path: str = ""):
        from ..stack import Amd64RopperAttack, I386RopperAttack

        self.update_connect_parameter(local, binary_path, ip, port, remote_libc_path)

        if context.arch == "amd64":
            self.ropper_attack = Amd64RopperAttack()
        elif context.arch == "i386":
            self.ropper_attack = I386RopperAttack()


context.log_level = "debug"
context.terminal = ['tmux', 'splitw', '-h']

cli_parser = args_init()

connect_io = ConnectIO(cli_parser.local,
                       cli_parser.binary_path,
                       cli_parser.ip,
                       cli_parser.port,
                       cli_parser.remote_libc_path,
                       cli_parser.tmux,
                       cli_parser.ssl)

pandora_box = connect_io

# connect_io.set_connect_parameter()
if 'pwnScript' in sys.argv[0]:
    print(PWN_SCRIPT_NAME)
    if cli_parser.local and cli_parser.binary_path is not None:
        try:
            connect_io.init_script()
            if cli_parser.tmux:
                gdb.attach(connect_io.conn)
                pause()
            connect_io.conn.interactive()
        except Exception as ex:
            error(f"{str(ex) = }")
            exit()

    elif not cli_parser.local and cli_parser.ip is not None and cli_parser.port is not None:
        try:
            connect_io.init_script()
            connect_io.conn.interactive()
        except Exception as ex:
            error(f"{str(ex) = }")
            exit()
