---
layout: post
title: Pwn/Molten walk
date: 2026-02-15 19:54 +0530
categories: [Pwn, Kernel]
tags: [meltdown, side-channel, cache, speculative-execution, pwncollege]
---



## Introduction

Modern CPUs are fast because they’re impatient.

Instead of waiting to see if an instruction is *allowed*, they go ahead and execute it speculatively and deal with the consequences later. Most of the time this is great for performance. In this challenge, it’s great for us.

We exploit that impatience to read kernel memory from a user process. The CPU eventually realizes something went wrong and throws a segmentation fault… but by then, the secret has already left traces in the cache.

---

## High-Level Strategy

At a high level, the attack looks like this:

1. Ask the kernel (via `ioctl`) to point to a sensitive address
2. Trigger speculative execution that reads from that address
3. Encode the leaked byte into cache state
4. Recover the byte via timing measurements
5. Repeat… a lot
6. Reconstruct page tables and walk them manually
7. Land on the flag and dump it byte-by-byte


It’s less “read memory” and more “interrogate the cache until it confesses.”

---

## The Speculative Gadget

The heart of the exploit is this function:

```c
void speculative_exploit(size_t target_addr, char *com_buffer)
```

Inside it, we deliberately cause a fault:

```nasm
mov rax, [rax]   // invalid access → SIGSEGV
```

Normally, execution would stop here. But the CPU has already speculatively executed the next few instructions:

```nasm
mov cl, BYTE PTR [target_addr]
shl rcx, 12
add rbx, rcx
mov rbx, [rbx]
```

What this does:

* Reads a secret byte from `target_addr`
* Uses it as an index into a large buffer (`buffer + value * 4096`)
* Touches that memory location

This access pulls exactly one cache line into L1. That’s our signal.

---

## “It Crashed” — Good

Every attempt ends in a segmentation fault. That’s expected.

We handle it like this:

```c
if (!setjmp(buf)) {
    speculative_exploit(addr, buffer);
}
```

And the handler:

```c
longjmp(buf, 1);
```

So the flow becomes:

* Try the exploit
* Crash
* Jump back
* Repeat

It’s basically controlled chaos.

---

## Turning Cache Timing into Data

Now comes the sneaky part.

Before each attempt, we flush the entire buffer from the cache:

```c
_mm_clflush(addr);
```

After speculative execution, exactly one cache line *might* be loaded—the one corresponding to the secret byte.

We probe each possible line:

```c
time_access_no_flush(addr);
```

If access is fast → cache hit → that index is likely the secret.

We repeat this ~100 times and keep a score:

```c
stats[mix_i]++;
```

Finally, we pick the most frequent candidate. Not perfect, but statistically reliable.

---

## Getting the Kernel to Cooperate

The challenge provides a helpful interface:

```c
ioctl(fd, 1337, target_addr);
```

This sets up the kernel module so that our speculative gadget reads from `target_addr` in kernel space.

We don’t directly dereference it—because we can’t—but speculation does it for us.

---

## Leaking Important Anchors

We first leak:

* `mm_struct`
* `pgd` (Page Global Directory)

These give us the starting point for walking the process’s page tables.

We read them byte-by-byte using the same side-channel primitive. It’s slow, but once you trust your primitive, everything becomes “just repetition.”

---

## Manual Page Table Walk

Now we do what the MMU normally does for us.

We compute indices:

```c
(addr >> (39 - 9*i)) & 0x1ff
```

Then traverse:

* PGD
* PUD
* PMD
* PTE

At each step:

1. Leak the entry using Meltdown
2. Extract the physical page
3. Move to the next level

This part feels like solving a puzzle where every piece is hidden behind a side-channel.

If you want to know exactly how the page entries are stored by the CPU, I highly recommend [Zolutal's blog](https://blog.zolutal.io/understanding-paging/).

---

## Translating Entries

Each entry contains flags and the physical address. We extract the page like this:

```c
entry & ~0xfff
```

Then rebuild a usable address and continue the walk.

Eventually, we land on the page that contains our target buffer (and the flag nearby).

---

## Extracting the Flag

With the final address in hand:

```c
final_addr = page_translation(entry[3]) + 0x60;
```

We leak it byte-by-byte:

```c
for (int i = 0; i < 61; i++)
```

Each byte is sampled multiple times and decided via majority vote:

```c 
counter[temp]++;
```

This helps smooth out noise and misreads.

---

## Dealing with Noise

Reality is messy:

* Some values (especially `0x00`) are unreliable
* Cache timings fluctuate
* Occasionally you just get garbage

To deal with this:

* Retry failed reads
* Use multiple samples per byte
* Pick the most frequent result

It’s less like reading memory and more like polling an unreliable witness.

---

## Why This Works

The key insight is:

> The CPU enforces permissions architecturally, but not always microarchitecturally.

Even though the illegal access is rolled back, the cache state isn’t. That side-effect becomes a covert channel.

We never bypassed permissions directly—we just observed the aftermath of a mistake.

---

## Final Thoughts

This challenge is a perfect example of how:

* Hardware optimizations can undermine security
* Side channels turn “impossible” reads into possible ones
* You don’t need direct access if you can measure indirect effects

Also, it’s a good reminder that sometimes the best way to get a secret is not to ask for it… but to watch what happens when someone else accidentally looks at it.

---

### Link for the source code: [Molten walk](https://github.com/Ishaantheguy/Meltdown-attack)
