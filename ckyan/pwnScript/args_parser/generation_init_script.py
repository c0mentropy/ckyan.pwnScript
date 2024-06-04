def generation_script(*, file_path: str = './', file_name: str = "exp.py", author_name: str = 'ckyan'):
    import os
    from datetime import datetime
    from ..log4ck import success

    if file_name is None:
        file_name = "exp.py"

    if author_name is None:
        author_name = 'ckyan'

    script_format = f'''
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Author: {author_name}
Generation date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""

"""
GitHub:
    https://github.com/c0mentropy/ckyan.pwnScript
Help: 
    python3 exp.py --help
    python3 exp.py debug --help
    python3 exp.py remote --help
Local:
    python3 exp.py debug --file ./pwn
Remote:
    python3 exp.py remote --ip 127.0.0.1 --port 9999 [--file ./pwn] [--libc ./libc.so.6]
    python3 exp.py remote --url 127.0.0.1:9999 [--file ./pwn] [--libc ./libc.so.6]
"""

# ./exp.py de -f ./pwn
# ./exp.py re -f ./pwn -u ""

from ckyan.pwnScript import *

def exp():
    pandora_box.init_script()

    elf = pandora_box.elf
    libc = pandora_box.libc
    p = pandora_box.conn


if __name__ == '__main__':
    exp()
    '''.strip()

    result_file = os.path.join(file_path, file_name)

    # 打开文件并写入字符串
    with open(result_file, "w") as file:
        file.write(script_format + "\n")

    success("File generated.")

    exit()

