import argparse

from ..log4ck import *


class CliParser:
    def __init__(self):
        self.local = True
        self.binary_path = ""
        self.ip = ""
        self.port = 0
        self.remote_libc_path = ""
        self.tmux = False

        self.set_parse_arguments()

    def set_parse_arguments(self):

        VERSION = "PwnScript: version 2.1.3\n" \
                  "Author: Comentropy Ckyan\n" \
                  "Email:  comentropy@foxmail.com\n" \
                  "GitHub: https://github.com/c0mentropy/ckyan.pwnScript\n"

        parser = argparse.ArgumentParser(prog="pwnScript",
                                         description="Description: "
                                                     "pwnScript is a tools for exploiting vuln in ELF files.",
                                         formatter_class=argparse.RawDescriptionHelpFormatter)

        parser.add_argument('-V', '--version', action='version', version=VERSION, help='Show the version and exit.')

        subparsers = parser.add_subparsers(dest='Commands', help='Available Commands')

        # 添加 "run" 命令
        auto_parser = subparsers.add_parser('auto', aliases=['run'], help='Automatically detect attacks')

        # 添加 "debug" 命令
        de_parser = subparsers.add_parser('debug', aliases=['de'], help='Attack locally')
        de_parser.add_argument('-f', '--file', type=str, help='File to debug')
        de_parser.add_argument('-t', '--tmux', action='store_true', help="Use tmux to gdb-debug or not.")

        # 添加 "remote" 命令
        re_parser = subparsers.add_parser('remote', aliases=['re'], help='Attack remotely')
        re_parser.add_argument('-u', '--url', type=str, nargs="*",
                               help="URL address of remote server")
        re_parser.add_argument('-i', '--ip', type=str,
                               help='IP address of remote server')
        re_parser.add_argument('-p', '--port', type=int,
                               help='Port number of remote server')
        re_parser.add_argument('-f', '--file', type=str, help='File to debug')
        re_parser.add_argument('-l', '--libc', type=str, help='File to debug')

        # 添加 "blasting" 命令
        bl_parser = subparsers.add_parser('blasting', aliases=['bl'], help='Attack blow up')

        # 解析命令行参数
        args = parser.parse_args()

        # 如果没有提供任何参数，则输出帮助信息并退出
        if vars(args) == {'Commands': None}:
            parser.print_help()
            exit()

        # 根据子命令进行不同的处理
        if args.Commands in ['de', 'debug']:
            self.local = True
            self.binary_path = args.file

            if args.tmux is not None and args.tmux:
                self.tmux = True
            else:
                self.tmux = False

        elif args.Commands in ['re', 'remote']:
            self.local = False
            self.remote_libc_path = args.libc
            self.binary_path = args.file

            if args.url is None and args.ip is None and args.port is None:
                re_parser.print_help()
                exit()

            # 这里的逻辑有些问题，如果是空格的隔开ip和port的话，就是两个参数了。如果这样写只能用引号 (over)
            if args.url is not None and args.url[0] != "":
                args_url = args.url[0]
                if ":" in args_url:
                    url_list = args_url.split(":")
                    try:
                        self.ip = url_list[0]
                        self.port = int(url_list[1])
                    except Exception as ex:
                        error(str(ex))
                elif " " in args_url:
                    url_list = args_url.split()
                    try:
                        self.ip = url_list[0]
                        self.port = int(url_list[1])
                    except Exception as ex:
                        error(str(ex))
            else:
                try:
                    self.binary_path = args.file
                    self.ip = args.ip
                    self.port = int(args.port)
                except Exception as ex:
                    error(str(ex))

    def get_parse_arguments(self):
        return self.local, self.binary_path, self.ip, self.port, self.remote_libc_path


cli_parser = CliParser()
