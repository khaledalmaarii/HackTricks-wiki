# Reversing Tools & Basic Methods

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!HackTricks</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Find vulnerabilities that matter most so you can fix them faster. Intruder tracks your attack surface, runs proactive threat scans, finds issues across your whole tech stack, from APIs to web apps and cloud systems. [**Try it for free**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) today.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## ImGui Based Reversing tools

Software:

* ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Online:

* Use [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) to **decompile** from wasm (binary) to wat (clear text)
* Use [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) to **compile** from wat to wasm
* you can also try to use [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) to decompile

Software:

* [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
* [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .Net decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek is a decompiler that **decompiles and examines multiple formats**, including **libraries** (.dll), **Windows metadata file**s (.winmd), and **executables** (.exe). Once decompiled, an assembly can be saved as a Visual Studio project (.csproj).

The merit here is that if a lost source code requires restoration from a legacy assembly, this action can save time. Further, dotPeek provides handy navigation throughout the decompiled code, making it one of the perfect tools for **Xamarin algorithm analysis.**&#x20;

### [.Net Reflector](https://www.red-gate.com/products/reflector/)

With a comprehensive add-in model and an API that extends the tool to suit your exact needs, .NET reflector saves time and simplifies development. Let's take a look at the plethora of reverse engineering services this tool provides:

* Provides an insight into how the data flows through a library or component
* Provides insight into the implementation and usage of .NET languages and frameworks
* Finds undocumented and unexposed functionality to get more out of the APIs and technologies used.
* Finds dependencies and different assemblies
* Tracks down the exact location of errors in your code, third-party components, and libraries.&#x20;
* Debugs into the source of all the .NET code you work with.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): You can have it in any OS (you can install it directly from VSCode, no need to download the git. Click on **Extensions** and **search ILSpy**).\
If you need to **decompile**, **modify** and **recompile** again you can use: [**https://github.com/0xd4d/dnSpy/releases**](https://github.com/0xd4d/dnSpy/releases) (**Right Click -> Modify Method** to change something inside a function).\
You cloud also try [https://www.jetbrains.com/es-es/decompiler/](https://www.jetbrains.com/es-es/decompiler/)

### DNSpy Logging

In order to make **DNSpy log some information in a file**, you could use this .Net lines:
```bash
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

In order to debug code using DNSpy you need to:

First, change the **Assembly attributes** related to **debugging**:

![](<../../.gitbook/assets/image (278).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
/README.md

# Reversing Tools - Basic Methods

This file contains information about basic methods and tools used in the field of reverse engineering.

## Introduction

Reverse engineering is the process of analyzing a software or hardware system to understand its design, functionality, and operation. It involves breaking down the system into its individual components and studying how they interact with each other.

Reverse engineering can be used for various purposes, such as understanding how a program works, finding vulnerabilities in a system, or creating a compatible version of a software.

## Basic Methods

### Static Analysis

Static analysis involves examining the code or binary of a program without executing it. This can be done using tools such as disassemblers, decompilers, and hex editors. Static analysis helps in understanding the structure and logic of a program.

### Dynamic Analysis

Dynamic analysis involves running a program and observing its behavior in real-time. This can be done using tools such as debuggers and dynamic analysis frameworks. Dynamic analysis helps in understanding the runtime behavior of a program.

### Code Injection

Code injection involves modifying the code of a program to alter its behavior or add new functionality. This can be done using techniques such as patching, hooking, or DLL injection. Code injection is often used for debugging or bypassing security measures.

### Memory Analysis

Memory analysis involves examining the memory of a running program to extract information such as passwords, encryption keys, or network traffic. This can be done using tools such as memory dumpers or memory forensics frameworks. Memory analysis is useful for reverse engineering malware or analyzing network protocols.

## Reversing Tools

There are various tools available for reverse engineering, each with its own strengths and weaknesses. Some popular tools include:

- IDA Pro: A powerful disassembler and debugger.
- Ghidra: An open-source software reverse engineering suite.
- OllyDbg: A user-friendly debugger for Windows.
- Radare2: A command-line reverse engineering framework.
- Hopper: A macOS disassembler and debugger.
- x64dbg: A free and open-source debugger for Windows.

These tools provide a range of features and capabilities, allowing reverse engineers to analyze and understand complex software and hardware systems.

## Conclusion

Reverse engineering is a valuable skill for understanding and analyzing software and hardware systems. By using various tools and techniques, reverse engineers can gain insights into the inner workings of a system and identify vulnerabilities or opportunities for improvement.
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
'ej **compile** vItlhutlh:

![](<../../.gitbook/assets/image (314) (1) (1).png>)

vaj **File >> Save module...** vItlhutlh vItlhutlh:

![](<../../.gitbook/assets/image (279).png>)

vaj vItlhutlh vItlhutlh vItlhutlh vItlhutlh, **runtime** **optimisations** **code** **break-point is never hit** **variables don't exist**.

vaj, .Net application **run** **IIS** **restart**:
```
iisreset /noforce
```
ngoD, debugging laH je jImej. **Debug Tab** Daq jImej **Attach to Process...** qar:

![](<../../.gitbook/assets/image (280).png>)

**w3wp.exe** **IIS server** attach **click**:

![](<../../.gitbook/assets/image (281).png>)

jImej process debugging, 'ej 'oH **jImej** 'ej **Windows >> Modules** **Debug >>** click:

![](<../../.gitbook/assets/image (286).png>)

![](<../../.gitbook/assets/image (283).png>)

**Modules** **jImej** 'ej **Open All Modules** **select**:

![](<../../.gitbook/assets/image (284).png>)

**Assembly Explorer** **jImej** **Sort Assemblies** **click**:

![](<../../.gitbook/assets/image (285).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### IDA Daq

* **rundll32** **Load** (64bits in C:\Windows\System32\rundll32.exe 'ej 32 bits in C:\Windows\SysWOW64\rundll32.exe)
* **Windbg** debugger **select**
* "**Suspend on library load/unload**" **select**

![](<../../.gitbook/assets/image (135).png>)

* **parameters** **execution** **Configure** **DLL path** 'ej **function** **put**:

![](<../../.gitbook/assets/image (136).png>)

jImej debugging **execution** **stopped** **DLL** **loaded** **execution** **stopped**.

'ach, **lodaded DLL** code **ghItlh**? **method** **ghItlh**.

### x64dbg/x32dbg Daq

* **rundll32** **Load** (64bits in C:\Windows\System32\rundll32.exe 'ej 32 bits in C:\Windows\SysWOW64\rundll32.exe)
* **Command Line** **Change** ( _File --> Change Command Line_ ) **dll path** 'ej **function** **put**, "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii\_2.dll",DLLMain
* _Options --> Settings_ **Change** "**DLL Entry**" **select**.
* **execution** **start**, **debugger** **dll main** **stop**, **dll Entry** **stop**. **breakpoint** **put** **search** **points** **breakpoint**.

win64dbg **execution** **stopped** **reason** **top** **win64dbg window** **ghItlh**:

![](<../../.gitbook/assets/image (137).png>)

'ach, **execution** **stopped** **dll** **debug** **want** **ghItlh**.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) **running game** **memory** **important values** **find** **change** **program** **useful**. **more info**:

{% content-ref url="cheat-engine.md" %}
[cheat-engine.md](cheat-engine.md)
{% endcontent-ref %}

## ARM & MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## Shellcodes

### blobrunner Daq shellcode debugging

[**Blobrunner**](https://github.com/OALabs/BlobRunner) **shellcode** **allocate** **memory space**, **memory address** **indicate** **shellcode** **allocated** **execution** **stop**.\
**debugger** (Ida 'ej x64dbg) **process** **attach** **breakpoint** **indicated memory address** **put** **execution** **resume**. **shellcode** **debugging**.

releases github page **compiled releases** **zips** **contain**: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
**Blobrunner** **slightly modified version** **link** **find**. **compile** **C/C++ project** **Visual Studio Code**, **code** **copy** **paste** **build**.

{% content-ref url="blobrunner.md" %}
[blobrunner.md](blobrunner.md)
{% endcontent-ref %}

### jmp2it Daq shellcode debugging

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) **blobrunner** **similar**. **shellcode** **allocate** **memory space**, **eternal loop** **start**. **debugger** **process** **attach**, **play start wait 2-5 secs and press stop** **inside** **eternal loop** **find**. **eternal loop** **next instruction** **jump** **shellcode** **call**, **shellcode** **execute** **find**.

![](<../../.gitbook/assets/image (397).png>)

**compiled version** [jmp2it releases page](https://github.com/adamkramer/jmp2it/releases/) **download**.

### Cutter Daq shellcode debugging

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) **radare** **GUI**. **Cutter** **emulate** **shellcode** **inspect** **dynamically**.

**Cutter** "Open File" 'ej "Open Shellcode" **allow**. **shellcode** **file** **opened** **decompile** **correctly**, **shellcode** **opened** **shellcode** **didn't**:

![](<../../.gitbook/assets/image (400).png>)

**emulation** **start** **place** **set** **bp** **start** **emulation** **automatically** **start**:

![](<../../.gitbook/assets/image (399).png>)

**stack** **hex dump** **see**:

![](<../../.gitbook/assets/image (402).png>)

### shellcode Deobfuscating 'ej executed functions

**scdbg** [**try**](http://sandsprite.com/blogs/index.php?uid=7\&pid=152).\
**shellcode** **using functions** **tell** **shellcode** **decoding** **memory**.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg jup also counts with a graphical launcher where you can select the options you want and execute the shellcode

![](<../../.gitbook/assets/image (398).png>)

The **Create Dump** option will dump the final shellcode if any change is done to the shellcode dynamically in memory (useful to download the decoded shellcode). The **start offset** can be useful to start the shellcode at a specific offset. The **Debug Shell** option is useful to debug the shellcode using the scDbg terminal (however I find any of the options explained before better for this matter as you will be able to use Ida or x64dbg).

### Disassembling using CyberChef

Upload you shellcode file as input and use the following receipt to decompile it: [https://gchq.github.io/CyberChef/#recipe=To\_Hex('Space',0)Disassemble\_x86('32','Full%20x86%20architecture',16,0,true,true)](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('Space',0\)Disassemble\_x86\('32','Full%20x86%20architecture',16,0,true,true\))

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

This obfuscator **modify all the instructions for `mov`**(yeah, really cool). It also uses interruptions to change executions flows. For more information about how does it works:

* [https://www.youtube.com/watch?v=2VF\_wPkiBJY](https://www.youtube.com/watch?v=2VF\_wPkiBJY)
* [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf)

If you are lucky [demovfuscator ](https://github.com/kirschju/demovfuscator)will deofuscate the binary. It has several dependencies
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Qa'vIn [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

If you are playing a **CTF, this workaround to find the flag** could be very useful: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Find vulnerabilities that matter most so you can fix them faster. Intruder tracks your attack surface, runs proactive threat scans, finds issues across your whole tech stack, from APIs to web apps and cloud systems. [**Try it for free**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) today.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Rust

To find the **entry point** search the functions by `::main` like in:

![](<../../.gitbook/assets/image (612).png>)

In this case the binary was called authenticator, so it's pretty obvious that this is the interesting main function.\
Having the **name** of the **functions** being called, search for them on the **Internet** to learn about their **inputs** and **outputs**.

## **Delphi**

For Delphi compiled binaries you can use [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

I you have to reverse a Delphi binary I would suggest you to use the IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Just press **ATL+f7** (import python plugin in IDA) and select the python plugin.

This plugin will execute the binary and resolve function names dynamically at the start of the debugging. After starting the debugging press again the Start button (the green one or f9) and a breakpoint will hit in the beginning of the real code.

It is also very interesting because if you press a button in the graphic application the debugger will stop in the function executed by that bottom.

## Golang

I you have to reverse a Golang binary I would suggest you to use the IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Just press **ATL+f7** (import python plugin in IDA) and select the python plugin.

This will resolve the names of the functions.

## Compiled Python

In this page you can find how to get the python code from an ELF/EXE python compiled binary:

{% content-ref url="../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## GBA - Game Body Advance

If you get the **binary** of a GBA game you can use different tools to **emulate** and **debug** it:

* [**no$gba**](https://problemkaputt.de/gba.htm) (_Download the debug version_) - Contains a debugger with interface
* [**mgba** ](https://mgba.io)- Contains a CLI debugger
* [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
* [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

In [**no$gba**](https://problemkaputt.de/gba.htm), in _**Options --> Emulation Setup --> Controls**_\*\* \*\* you can see how to press the Game Boy Advance **buttons**

![](<../../.gitbook/assets/image (578).png>)

When pressed, each **key has a value** to identify it:
```
A = 1
B = 2
SELECT = 4
START = 8
RIGHT = 16
LEFT = 32
UP = 64
DOWN = 128
R = 256
L = 256
```
So, in this kind of programs, the an interesting part will be **how the program treats the user input**. In the address **0x4000130** you will find the commonly found function: **KEYINPUT.**

![](<../../.gitbook/assets/image (579).png>)

In the previous image you can find that the function is called from **FUN\_080015a8** (addresses: _0x080015fa_ and _0x080017ac_).

In that function, after some init operations (without any importance):

So, in this kind of programs, the an interesting part will be **how the program treats the user input**. In the address **0x4000130** you will find the commonly found function: **KEYINPUT.**

![](<../../.gitbook/assets/image (579).png>)

In the previous image you can find that the function is called from **FUN\_080015a8** (addresses: _0x080015fa_ and _0x080017ac_).

In that function, after some init operations (without any importance):
```c
void FUN_080015a8(void)

{
ushort uVar1;
undefined4 uVar2;
undefined4 uVar3;
ushort uVar4;
int iVar5;
ushort *puVar6;
undefined *local_2c;

DISPCNT = 0x1140;
FUN_08000a74();
FUN_08000ce4(1);
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02009584,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
```
**ghItlh** **code** **vItlhutlh**:

```python
def reverse_string(string):
    return string[::-1]
```

**ghItlh** **code** **vItlhutlh** **ghaH**:

```python
def reverse_string(string):
    return string[::-1]
```

**ghItlh** **code** **vItlhutlh** **ghaH**:

```python
def reverse_string(string):
    return string[::-1]
```
```c
do {
DAT_030004da = uVar4; //This is the last key pressed
DAT_030004d8 = KEYINPUT | 0xfc00;
puVar6 = &DAT_0200b03c;
uVar4 = DAT_030004d8;
do {
uVar2 = DAT_030004dc;
uVar1 = *puVar6;
if ((uVar1 & DAT_030004da & ~uVar4) != 0) {
```
**`uVar4`** is checked in the last Keys and not in the current key, which is stored in **`uVar1`**. This is similar to letting go off a button.
```c
if (uVar1 == 4) {
DAT_030000d4 = 0;
uVar3 = FUN_08001c24(DAT_030004dc);
FUN_08001868(uVar2,0,uVar3);
DAT_05000000 = 0x1483;
FUN_08001844(&DAT_0200ba18);
FUN_08001844(&DAT_0200ba20,&DAT_0200ba40);
DAT_030000d8 = 0;
uVar4 = DAT_030004d8;
}
else {
if (uVar1 == 8) {
if (DAT_030000d8 == 0xf3) {
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02008aac,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
}
}
else {
if (DAT_030000d4 < 8) {
DAT_030000d4 = DAT_030000d4 + 1;
FUN_08000864();
if (uVar1 == 0x10) {
DAT_030000d8 = DAT_030000d8 + 0x3a;
```
In the previous code you can see that we are comparing **uVar1** (the place where the **value of the pressed button** is) with some values:

* First, it's compared with the **value 4** (**SELECT** button): In the challenge this button clears the screen
* Then, it's comparing it with the **value 8** (**START** button): In the challenge this checks is the code is valid to get the flag.
* In this case the var **`DAT_030000d8`** is compared with 0xf3 and if the value is the same some code is executed.
* In any other cases, some cont (`DAT_030000d4`) is checked. It's a cont because it's adding 1 right after entering in the code.\
**I**f less than 8 something that involves **adding** values to \*\*`DAT_030000d8` \*\* is done (basically it's adding the values of the keys pressed in this variable as long as the cont is less than 8).

So, in this challenge, knowing the values of the buttons, you needed to **press a combination with a length smaller than 8 that the resulting addition is 0xf3.**

**Reference for this tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy

{% embed url="https://www.youtube.com/watch?v=VVbRe7wr3G4" %}

## Courses

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Find vulnerabilities that matter most so you can fix them faster. Intruder tracks your attack surface, runs proactive threat scans, finds issues across your whole tech stack, from APIs to web apps and cloud systems. [**Try it for free**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) today.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
