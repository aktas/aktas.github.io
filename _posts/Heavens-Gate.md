---
title: Heaven's Gate Technique
published: false
---

<img src="/assets/heavens_gate_screenshot2.png" alt="Heaven's Gate" style="display:block; margin-right:auto; margin-left:auto; padding-bottom:20px;"  >

## Introduction

In this article, we will examine one of the anti-debug techniques, `Heaven's Gate`. First we will explain this technique in detail and then we will analyze 2 simple crackme file. We will also have a nice challenge at the end of this article :))

## What is Heaven's Gate?

`Heaven's Gate` is a technique to run a 64-bit process from a 32-bit process or a 32-bit process from a 64-bit process. This technique can be realized by executing a `call` or `jmp` command using the reserved selector. So, what's the selector?

> Segmentation is a memory management technique used especially in the x86 architecture.
> Special values that specify the segment to be used for memory access are called `segment selectors`.
> The mode (32bit/64bit) in which `CS` (CodeSelector) related operations will run is specified.
> If the value of the `CS` register is `0x23`, operations are executed in `32-bit` and in `64-bit` if the value is `0x33`.

This technique is intended to prevent detailed analysis by the debugger. It is also intended to confuse the analyst.

![](/assets/d2.png)

Okay, the best way to learn is to practice. Our first file is an elf file. Let's start analyzing it. Download [here](/assets/heavens_gate).

## Crackme-1

We see that the program is a 32-bit elf file. We also can't find anything in the strings. When we run the program it shows us "Where is the secret message????". We also can't find anything in strings.

```
┌──(alper㉿nobody)-[~/Masaüstü/heavens_gate]
└─$ file heavens_gate    
heavens_gate: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, no section header                                                                                        
┌──(alper㉿nobody)-[~/Masaüstü/heavens_gate]
└─$ strings heavens_gate
Where is the secret message???       
┌──(alper㉿nobody)-[~/Masaüstü/heavens_gate]
└─$ ./heavens_gate
Where is the secret message??? 
```

Let's try to open the program with `IDA32` (I show the first program with IDA because it is easy to use and I want you to fully grasp the logic). 

When we start to examine the program, we see that a `far jump` to a specific address is made at the beginning.

<img src="/assets/heavens_gate_screenshot3.png" alt="Heaven's Gate with ida" style="display:block; margin-right:auto; margin-left:auto; padding-bottom:20px;"  >

What we notice here is that the `CS register` is set to `33h` and the jump is made. Since the CS register is set to 0x33, the operations at the jumped address will be executed in `64-bit`.

Let's continue the analyze by going to the relevant address.

<img src="/assets/heavens_gate_screenshot4.png" alt="Heaven's Gate with ida" style="display:block; margin-right:auto; margin-left:auto; padding-bottom:20px;"  >

When we jump to the corresponding address, we see that the commands cannot be made sense of. When we jump to the address, we see that the instructions do not make sense. The reason for this is that the instructions at the address will be executed in 64-bit even though we examine the program in 32-bit with ida32. In this case we need to open ida64. Remember this:

> ida32 can only analyze 32-bit programs, while ida64 can analyze both 32-bit and 64-bit files.

I open the program with ida64 and jump to the corresponding address again, but again I see that the code cannot be interpreted. This is because the program is 32-bit and ida analyzes the program accordingly. We need to analyze the instructions at the relevant address as 64-bit. For this we go to View -> Open Subviews -> Segments, right click on the segment and select edit segment. Set the segment bitness value to 64-bit and click OK.

<img src="/assets/heavens_gate_screenshot5.png" alt="Heaven's Gate with ida" style="display:block; margin-right:auto; margin-left:auto; padding-bottom:20px;" >

Then return to the address, select further from the address, right-click and have it analyzed.

<img src="/assets/heavens_gate_screenshot6.png" alt="Heaven's Gate with ida" style="display:block; margin-right:auto; margin-left:auto; padding-bottom:20px;" >

You will see that relevant commands have been successfully analyzed.

<img src="/assets/heavens_gate_screenshot7.png" alt="Heaven's Gate with ida" style="display:block; margin-right:auto; margin-left:auto; padding-bottom:20px;" >

We have seen that the secret message is `ZAYOTEM{H3AV3NS_GAT3}`. You can review the code of the program [here](https://github.com/aktas/Anti-Analysis/tree/main/anti-debug/HeavensGate).

Now let's move on to another example. This time we will use a debugger. Download [here](/assets/HeavensGate.exe). 

![](/assets/yoda.png)

## Crackme-2

to be continued...



