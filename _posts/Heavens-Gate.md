---
title: Heaven's Gate Technique
published: false
---

<img src="/assets/heavens_gate_screenshot2.png" alt="Heaven's Gate" style="display:block; margin-right:auto; margin-left:auto; padding-bottom:20px;"  >

## Introduction

In this article, we will examine one of the anti-debug techniques, `Heaven's Gate`. First we will explain this technique in detail and then we will analyze 2 simple crackme file. By the end of this article, you will understand what to do when Heaven's Gate technique is encountered on IDA, x32dbg and WinDBG. We will also have a nice challenge at the end of this article :))

## What is Heaven's Gate?

`Heaven's Gate` is a technique to run a 64-bit process from a 32-bit process or a 32-bit process from a 64-bit process. This technique can be realized by executing a `call` or `jmp` command using the reserved selector. So, what's the selector?

> Segmentation is a memory management technique used especially in the x86 architecture.
> Special values that specify the segment to be used for memory access are called `segment selectors`.
> The mode (32bit/64bit) in which `CS` (CodeSelector) related operations will run is specified.
> If the value of the `CS` register is `0x23`, operations are executed in `32-bit` and in `64-bit` if the value is `0x33`.

If a 64-bit process runs from a 32-bit process, the program will switch to the System32 subsystem and use the relevant dll files. Heaven's Gate can be used when a 32-bit program needs to access 64-bit system libraries or interfaces that are not available in 32-bit mode.

> In 64-bit windows, 64-bit system files are located in `%SystemRoot%\System32` and 32-bit system files are located in `%SystemRoot%\SysWOW64`. 

This technique is intended to prevent detailed analysis by the debugger. It is also intended to confuse the analyst. Known as the `evasion` technique.

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

## Crackme-2(x32dbg)

This example is a simple crackme file. When we run the program, we see that it asks us for a key. 

<img src="/assets/heavens_gate_screenshot8.png" alt="Heaven's Gate" style="display:block; margin-right:auto; margin-left:auto; padding-bottom:20px;" >

We need to find the `key`. When we open the file with CFF Explorer, we see that it is 32-bit.

<img src="/assets/heavens_gate_screenshot9.png" alt="CFF Explorer" style="display:block; margin-right:auto; margin-left:auto; padding-bottom:20px;" >

Open the file with x32dbg and go to entrypoint. click f9. You will be asked to enter to valid key. Go to the stack calls section. Right-click and click show suspected call stack frame and show active call stack frame respectively. Go to the relevant address by clicking on the last call.

<img src="/assets/heavens_gate_screenshot10.png" alt="x32dbg call stack" style="display:block; margin-right:auto; margin-left:auto; padding-bottom:20px;" >

When we go to the address, we see the scanf call. Let's put a breakpoint just below it and enter a key from the terminal.

<img src="/assets/heavens_gate_screenshot11.png" alt="x32dbg" style="display:block; margin-right:auto; margin-left:auto; padding-bottom:20px;" >

Keep moving forward with f8. You will come to the following address.

<img src="/assets/heavens_gate_screenshot12.png" alt="x32dbg" style="display:block; margin-right:auto; margin-left:auto; padding-bottom:20px;" >

When we examine the commands, we see that it compares the value at the 8DA480 address with 0 and if it is equal, it prints Wrong on the screen, if not equal, Correct! 

There must be a control function at this point. This function appears to be located at address `8D1AA0`. Let's continue the analysis by going inside this function.

As we proceed step by step, we see that 7 characters of the password we enter are taken and moved to the registers.

<img src="/assets/heavens_gate_screenshot13.png" alt="x32dbg heaven's gate" style="display:block; margin-right:auto; margin-left:auto; padding-bottom:20px;" >

We've come to the difficult part:

Let's examine the picture above carefully. We see that `0x33` is pushed to the stack. Then we see that the `call $0` instruction is called. So what is `call $0`?

The `call $0` instruction actually returns the next address. let's go ahead and execute the `call $0` instruction. Look carefully at what happened.

<img src="/assets/heavens_gate_screenshot15.png" alt="call $0 instruction" style="display:block; margin-right:auto; margin-left:auto; padding-bottom:20px;" >

We see that the ESP is pointing the EIP address. When we execute the current instruction, we see that 0x05 bytes will be added to the value pointed to by ESP. Click f8 and Follow the value of esp in the dump.

<img src="/assets/heavens_gate_screenshot16.png" alt="call $0 instruction" style="display:block; margin-right:auto; margin-left:auto; padding-bottom:20px;" >

When we look at the dump, we see that the value of ESP is `003917FD`. When the 'ret far' instruction is executed, this is the address to jump away from. Remember that 33 was pushed into the stack. So now code will run in 64-bit and we will not be able to continue the analysis with x32dbg.

At this point we need to continue with x64dbg. Open a 64-bit program on x64dbg and go to entrypoint. Copy the code to be executed with 'ret far' until the next 'ret far' command from binary->copy and paste it into the entrypoint in x64dbg from binary->Paste(Ignore Size).

<img src="/assets/heavens_gate_screenshot2.png" alt="Heaven's Gate" style="display:block; margin-right:auto; margin-left:auto; padding-bottom:20px;"  >

Analyze it! 

<img src="/assets/heavens_gate_screenshot17.png" alt="Heaven's Gate" style="display:block; margin-right:auto; margin-left:auto; padding-bottom:20px;"  >

We see that the first 2 characters are `h` and `3`. Then the value of size rcx is extracted from the stack and the rcx register is updated. Remember that the 3rd character of the password is pushed to the stack. Let's remember the relevant field:

```
006917C0 | A0 76A46900              | mov al,byte ptr ds:[69A476]                              | 0069A476:"ssword"
006917C5 | 8A1D 77A46900            | mov bl,byte ptr ds:[69A477]                              | 0069A477:"sword"
006917CB | 8A0D 7AA46900            | mov cl,byte ptr ds:[69A47A]                              | 0069A47A:"rd"
006917D1 | 6A 00                    | push 0                                                   |
006917D3 | 51                       | push ecx                                                 |
006917D4 | 6A 00                    | push 0                                                   |
006917D6 | 53                       | push ebx                                                 |
006917D7 | 6A 00                    | push 0                                                   |
006917D9 | 50                       | push eax                                                 |
```

The 7th, 4th and 3rd characters of the password are pushed onto the stack respectively. The instruction 'pop rcx' will pop a 64-bit value from the stack. The 'push 0' instruction in between sets 32 bits. Thus, when the 64-bit system is switched to, the values can be extracted and set properly. 

So we understand that the 3rd character is `4` and the 4th character is `v`. Then we come up with two equations. These are:

```RAX + RBX == 0xB3```

and

```(0xB3 - RBX) + (0xB3 - RBX) - RBX == 0x1C``` so ```2*0xB3 - 3*RBX == 0x1C```

When we solve the equation, we find RAX is `69(E)` and RBX is `110(n)`. We see that the last character is compared to `0`. This instruction checks whether the string has been terminated or not. As a result we find the key as `h34vEn`.

<img src="/assets/heavens_gate_screenshot18.png" alt="Key" style="display:block; margin-right:auto; margin-left:auto; padding-bottom:20px;"  >

## Crackme-2(WinDBG)

## Challenge!



