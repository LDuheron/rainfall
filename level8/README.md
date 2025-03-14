## Walkthrough

We list the files in the current home directory.

```bash
level8@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 level8 level8   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level8 level8  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level8 level8 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level9 users  6057 Mar  6  2016 level8
-rw-r--r--+ 1 level8 level8   65 Sep 23  2015 .pass
-rw-r--r--  1 level8 level8  675 Apr  3  2012 .profile
level8@RainFall:~$ file level8
level8: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x3067a180acabc94d328ab89f0a5a914688bf67ab, not stripped

```

The file is owned by **level9** and has the **setuid** bit.

We list the functions inside the executable and analyze their assembly code with **GDB**.

```nasm
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x080483c4  _init
0x08048410  printf
0x08048410  printf@plt
0x08048420  free
0x08048420  free@plt
0x08048430  strdup
0x08048430  strdup@plt
0x08048440  fgets
0x08048440  fgets@plt
0x08048450  fwrite
0x08048450  fwrite@plt
0x08048460  strcpy
0x08048460  strcpy@plt
0x08048470  malloc
0x08048470  malloc@plt
0x08048480  system
0x08048480  system@plt
0x08048490  __gmon_start__
0x08048490  __gmon_start__@plt
0x080484a0  __libc_start_main
0x080484a0  __libc_start_main@plt
0x080484b0  _start
0x080484e0  __do_global_dtors_aux
0x08048540  frame_dummy
0x08048564  main
0x08048740  __libc_csu_init
0x080487b0  __libc_csu_fini
0x080487b2  __i686.get_pc_thunk.bx
0x080487c0  __do_global_ctors_aux
0x080487ec  _fini
```

There is only a `main()` :

```nasm
(gdb) disas main
Dump of assembler code for function main:
   0x08048564 <+0>:	push   ebp
   0x08048565 <+1>:	mov    ebp,esp
   0x08048567 <+3>:	push   edi
   0x08048568 <+4>:	push   esi
   0x08048569 <+5>:	and    esp,0xfffffff0
   0x0804856c <+8>:	sub    esp,0xa0
   0x08048572 <+14>:	jmp    0x8048575 <main+17>
   0x08048574 <+16>:	nop
   0x08048575 <+17>:	mov    ecx,DWORD PTR ds:0x8049ab0
   0x0804857b <+23>:	mov    edx,DWORD PTR ds:0x8049aac
   0x08048581 <+29>:	mov    eax,0x8048810
   0x08048586 <+34>:	mov    DWORD PTR [esp+0x8],ecx
   0x0804858a <+38>:	mov    DWORD PTR [esp+0x4],edx
   0x0804858e <+42>:	mov    DWORD PTR [esp],eax
   0x08048591 <+45>:	call   0x8048410 <printf@plt>
   0x08048596 <+50>:	mov    eax,ds:0x8049a80
   0x0804859b <+55>:	mov    DWORD PTR [esp+0x8],eax
   0x0804859f <+59>:	mov    DWORD PTR [esp+0x4],0x80
   0x080485a7 <+67>:	lea    eax,[esp+0x20]
   0x080485ab <+71>:	mov    DWORD PTR [esp],eax
   0x080485ae <+74>:	call   0x8048440 <fgets@plt>
   0x080485b3 <+79>:	test   eax,eax
   0x080485b5 <+81>:	je     0x804872c <main+456>
   0x080485bb <+87>:	lea    eax,[esp+0x20]
   0x080485bf <+91>:	mov    edx,eax
   0x080485c1 <+93>:	mov    eax,0x8048819
   0x080485c6 <+98>:	mov    ecx,0x5
   0x080485cb <+103>:	mov    esi,edx
   0x080485cd <+105>:	mov    edi,eax
   0x080485cf <+107>:	repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]
   0x080485d1 <+109>:	seta   dl
   0x080485d4 <+112>:	setb   al
   0x080485d7 <+115>:	mov    ecx,edx
   0x080485d9 <+117>:	sub    cl,al
   0x080485db <+119>:	mov    eax,ecx
   0x080485dd <+121>:	movsx  eax,al
   0x080485e0 <+124>:	test   eax,eax
   0x080485e2 <+126>:	jne    0x8048642 <main+222>
   0x080485e4 <+128>:	mov    DWORD PTR [esp],0x4
   0x080485eb <+135>:	call   0x8048470 <malloc@plt>
   0x080485f0 <+140>:	mov    ds:0x8049aac,eax
   0x080485f5 <+145>:	mov    eax,ds:0x8049aac
   0x080485fa <+150>:	mov    DWORD PTR [eax],0x0
   0x08048600 <+156>:	lea    eax,[esp+0x20]
   0x08048604 <+160>:	add    eax,0x5
   0x08048607 <+163>:	mov    DWORD PTR [esp+0x1c],0xffffffff
   0x0804860f <+171>:	mov    edx,eax
   0x08048611 <+173>:	mov    eax,0x0
   0x08048616 <+178>:	mov    ecx,DWORD PTR [esp+0x1c]
   0x0804861a <+182>:	mov    edi,edx
   0x0804861c <+184>:	repnz scas al,BYTE PTR es:[edi]
   0x0804861e <+186>:	mov    eax,ecx
   0x08048620 <+188>:	not    eax
```

The decompile C code :

```bash
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[5]; // input buffer
  char v5[2]; // used in auth
  char v6[129]; // used in service

  while (1)
  {
    printf("%p, %p \n", auth, (const void *)service);
    if (!fgets(s, 128, stdin))
      break;
    
    if (!memcmp(s, "auth ", 5u))
    {
      auth = (char *)malloc(4u);
      *(_DWORD *)auth = 0;
      if (strlen(v5) <= 0x1E)
        strcpy(auth, v5);
    }
    if (!memcmp(s, "reset", 5u))
      free(auth);
    if (!memcmp(s, "service", 6u))
      service = (int)strdup(v6);
    if (!memcmp(s, "login", 5u))
    {
      if (*((_DWORD *)auth + 8))
        system("/bin/sh");
      else
        fwrite("Password:\n", 1u, 0xAu, stdout);
    }
  }
  return 0;
}
```

The function: 

- **Aligns the stack**: Adjusts the stack pointer to ensure it is aligned to a 16-byte boundary, adhering to the System V AMD64 ABI calling convention.
- Reads user input using `fgets`
- Compares the input with a hardcoded string representing commands : auth, service, reset and login

The login command Is the most interesting. If `auth[32]` is not zero, it runs `system("/bin/sh")`otherwise, it prints "Password:\n".

`auth` is only allocated 4 bytes, but `strcpy(a)` copies user-controlled data without bounds checking.

This allows an overflow into adjacent memory.

`auth` and `service` are close in memory (16 bytes apart).

Writing to `service` can overwrite `auth[32]`.

Since `auth[32]` is nonzero, it executes `system("/bin/sh")`, giving a shell.

### Final command

The final command : 

```bash
$ cat /home/user/level9/.pass
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```

https://dogbolt.org/?id=c81dd233-7ccb-4ab8-8074-27857c96eb14#Hex-Rays=115
