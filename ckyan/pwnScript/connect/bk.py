from pwn import *
from ..args_parser import *
from ..log4ck import *
from ..exception_message import exception_message


class ConnectIO:
    def __init__(self, local: bool = True,
                 binary_path: str = "",
                 ip: str = "127.0.0.1",
                 port: int = 9999,
                 remote_libc_path: str = ""):

        self.local = local
        self.binary_path = binary_path
        self.ip = ip
        self.port = port
        self.remote_libc_path = remote_libc_path

        self.elf = None
        self.libc = None

        self.conn = None

    def set_connect_parameter(self):
        if self.local:
            if self.binary_path != "":
                if os.path.exists(self.binary_path):

                    self.elf = ELF(self.binary_path)
                    self.libc = self.elf.libc

                    context.binary = self.binary_path
                    self.conn = process(self.binary_path)
                else:
                    error(exception_message.file_not_exist)
            else:
                error(exception_message.missing_key_documents)
        else:
            if self.remote_libc_path is not None and self.remote_libc_path != "":
                self.libc = ELF(self.remote_libc_path)
            else:
                if os.path.exists(self.binary_path):
                    self.elf = ELF(self.binary_path)
                    self.libc = self.elf.libc
                    context.binary = self.binary_path

            try:
                self.conn = remote(self.ip, self.port)
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

        self.elf = ELF(self.binary_path)

        if self.local:
            self.libc = self.elf.libc
            self.conn = process(self.binary_path)
        else:
            if self.remote_libc_path != "":
                self.libc = ELF(self.remote_libc_path)
            else:
                self.libc = self.elf.libc
            
            self.conn = remote(self.ip, self.port)
    
    def init_script(self):
        return self.set_connect_parameter()
    
    def update_script(self, local: bool = True,
                binary_path: str = "",
                ip: str = "127.0.0.1",
                port: int = 9999,
                remote_libc_path: str = ""):
        
        return self.update_connect_parameter(local, binary_path, ip, port, remote_libc_path)
        

context.log_level = "debug"

connect_io = ConnectIO(cli_parser.local,
                       cli_parser.binary_path,
                       cli_parser.ip,
                       cli_parser.port,
                       cli_parser.remote_libc_path)

# connect_io.set_connect_parameter()