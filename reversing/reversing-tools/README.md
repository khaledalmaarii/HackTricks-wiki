<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks क्लाउड ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 ट्विटर 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ ट्विच 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 यूट्यूब 🎥</strong></a></summary>

- क्या आप किसी **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी को HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने की अनुमति** चाहिए? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!

- खोजें [**The PEASS परिवार**](https://opensea.io/collection/the-peass-family), हमारा विशेष [**NFT**](https://opensea.io/collection/the-peass-family) संग्रह

- प्राप्त करें [**आधिकारिक PEASS और HackTricks swag**](https://peass.creator-spring.com)

- **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या मुझे **ट्विटर** पर **फ़ॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **अपने हैकिंग ट्रिक्स को [hacktricks रेपो](https://github.com/carlospolop/hacktricks) और [hacktricks-cloud रेपो](https://github.com/carlospolop/hacktricks-cloud) में पीआर जमा करके साझा करें।**

</details>


# Wasm डिकंपाइलर / Wat कंपाइलर

ऑनलाइन:

* [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) का उपयोग करें वैसम \(बाइनरी\) से वैट \(स्पष्ट पाठ\) में **डिकंपाइल** करने के लिए
* [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) का उपयोग करें वैट से वैसम में **कंपाइल** करने के लिए
* आप [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) का उपयोग भी कर सकते हैं डिकंपाइल करने के लिए

सॉफ़्टवेयर:

* [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
* [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

# .Net डिकंपाइलर

[https://github.com/icsharpcode/ILSpy](https://github.com/icsharpcode/ILSpy)
[Visual Studio Code के लिए ILSpy प्लगइन](https://github.com/icsharpcode/ilspy-vscode): आप इसे किसी भी ओएस में रख सकते हैं \(आप इसे वीएसकोड से सीधे इंस्टॉल कर सकते हैं, गिट को डाउनलोड करने की आवश्यकता नहीं है। **Extensions** पर क्लिक करें और **ILSpy** खोजें\).
यदि आपको **डिकंपाइल**, **संशोधित** और **फिर से कंपाइल** करने की आवश्यकता हो तो आप इस्तेमाल कर सकते हैं: [**https://github.com/0xd4d/dnSpy/releases**](https://github.com/0xd4d/dnSpy/releases) \(**Right Click -&gt; Modify Method** फ़ंक्शन के अंदर कुछ बदलने के लिए\).
आप [https://www.jetbrains.com/es-es/decompiler/](https://www.jetbrains.com/es-es/decompiler/) भी आजमा सकते हैं

## DNSpy लॉगिंग

**DNSpy में कुछ जानकारी फ़ाइल में लॉग करने के लिए**, आप इस .Net लाइन का उपयोग कर सकते हैं:
```bash
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
## DNSpy डीबगिंग

DNSpy का उपयोग करके कोड की डीबगिंग करने के लिए आपको निम्नलिखित कार्रवाई करनी होगी:

पहले, **डीबगिंग** से संबंधित **असेंबली गुण** बदलें:

![](../../.gitbook/assets/image%20%287%29.png)

से:
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
README.md

# Reversing Tools

This directory contains a collection of tools commonly used in the field of reverse engineering. These tools are essential for analyzing and understanding the inner workings of software and firmware.

## Contents

- [IDA Pro](#ida-pro)
- [Ghidra](#ghidra)
- [OllyDbg](#ollydbg)
- [x64dbg](#x64dbg)
- [Radare2](#radare2)
- [Hopper](#hopper)
- [Binary Ninja](#binary-ninja)
- [Cutter](#cutter)
- [RetDec](#retdec)
- [Angr](#angr)
- [Frida](#frida)
- [Immunity Debugger](#immunity-debugger)
- [WinDbg](#windbg)
- [Volatility](#volatility)
- [Apktool](#apktool)
- [dex2jar](#dex2jar)
- [JD-GUI](#jd-gui)
- [Androguard](#androguard)
- [Bytecode Viewer](#bytecode-viewer)
- [IDA Python](#ida-python)
- [GDB](#gdb)
- [Pwntools](#pwntools)
- [Binwalk](#binwalk)
- [QEMU](#qemu)
- [Unicorn](#unicorn)
- [Capstone](#capstone)
- [Fuzzing Tools](#fuzzing-tools)
- [Debuggers](#debuggers)
- [Disassemblers](#disassemblers)
- [Decompilers](#decompilers)
- [Static Analysis Tools](#static-analysis-tools)
- [Dynamic Analysis Tools](#dynamic-analysis-tools)
- [Memory Analysis Tools](#memory-analysis-tools)
- [Android Tools](#android-tools)
- [Miscellaneous Tools](#miscellaneous-tools)

## IDA Pro

IDA Pro is a widely used disassembler and debugger for analyzing binary code. It supports a wide range of architectures and provides advanced features for reverse engineering.

- Official Website: [https://www.hex-rays.com/](https://www.hex-rays.com/)
- Documentation: [https://www.hex-rays.com/products/ida/support/idadoc/](https://www.hex-rays.com/products/ida/support/idadoc/)

## Ghidra

Ghidra is a powerful open-source software reverse engineering suite developed by the National Security Agency (NSA). It provides a wide range of features for analyzing and understanding binary code.

- Official Website: [https://ghidra-sre.org/](https://ghidra-sre.org/)
- Documentation: [https://ghidra-sre.org/Documentation/](https://ghidra-sre.org/Documentation/)

## OllyDbg

OllyDbg is a 32-bit assembler-level debugger for Microsoft Windows. It is widely used for analyzing and reverse engineering binary code.

- Official Website: [http://www.ollydbg.de/](http://www.ollydbg.de/)
- Download: [http://www.ollydbg.de/version2.html](http://www.ollydbg.de/version2.html)

## x64dbg

x64dbg is a powerful open-source x86/x64 debugger for Windows. It provides a user-friendly interface and a wide range of features for analyzing and debugging binary code.

- Official Website: [https://x64dbg.com/](https://x64dbg.com/)
- Download: [https://github.com/x64dbg/x64dbg/releases](https://github.com/x64dbg/x64dbg/releases)

## Radare2

Radare2 is a powerful open-source framework for reverse engineering and binary analysis. It provides a command-line interface and supports a wide range of architectures.

- Official Website: [https://www.radare.org/](https://www.radare.org/)
- Documentation: [https://radare.gitbooks.io/radare2book/](https://radare.gitbooks.io/radare2book/)

## Hopper

Hopper is a powerful disassembler and reverse engineering tool for macOS and Linux. It supports a wide range of architectures and provides advanced features for analyzing binary code.

- Official Website: [https://www.hopperapp.com/](https://www.hopperapp.com/)
- Documentation: [https://www.hopperapp.com/documentation/](https://www.hopperapp.com/documentation/)

## Binary Ninja

Binary Ninja is a commercial disassembler and reverse engineering platform. It provides a user-friendly interface and advanced features for analyzing binary code.

- Official Website: [https://binary.ninja/](https://binary.ninja/)
- Documentation: [https://docs.binary.ninja/](https://docs.binary.ninja/)

## Cutter

Cutter is a free and open-source GUI for radare2, a powerful reverse engineering framework. It provides a user-friendly interface and advanced features for analyzing binary code.

- Official Website: [https://cutter.re/](https://cutter.re/)
- Documentation: [https://cutter.re/docs/](https://cutter.re/docs/)

## RetDec

RetDec is a retargetable machine-code decompiler based on LLVM. It can be used to decompile binary code into a high-level representation.

- Official Website: [https://retdec.com/](https://retdec.com/)
- Documentation: [https://retdec.com/doc/](https://retdec.com/doc/)

## Angr

Angr is a powerful binary analysis framework that allows for symbolic execution and constraint solving. It can be used for a wide range of tasks, including vulnerability discovery and exploit generation.

- Official Website: [https://angr.io/](https://angr.io/)
- Documentation: [https://docs.angr.io/](https://docs.angr.io/)

## Frida

Frida is a dynamic instrumentation toolkit that allows for runtime manipulation of binary code. It can be used for a wide range of tasks, including hooking and patching.

- Official Website: [https://frida.re/](https://frida.re/)
- Documentation: [https://frida.re/docs/home/](https://frida.re/docs/home/)

## Immunity Debugger

Immunity Debugger is a powerful debugger for analyzing and reverse engineering binary code. It provides a Python API for automation and script development.

- Official Website: [https://www.immunityinc.com/products/debugger/](https://www.immunityinc.com/products/debugger/)
- Documentation: [https://www.immunityinc.com/documentation/](https://www.immunityinc.com/documentation/)

## WinDbg

WinDbg is a powerful debugger for analyzing and debugging Windows kernel-mode and user-mode code. It provides advanced features for troubleshooting and crash analysis.

- Official Website: [https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/)

## Volatility

Volatility is a powerful memory forensics framework for analyzing and extracting information from volatile memory (RAM) samples. It provides a wide range of plugins for various analysis tasks.

- Official Website: [https://www.volatilityfoundation.org/](https://www.volatilityfoundation.org/)
- Documentation: [https://github.com/volatilityfoundation/volatility/wiki](https://github.com/volatilityfoundation/volatility/wiki)

## Apktool

Apktool is a tool for reverse engineering Android APK files. It can decompile APK files into their corresponding source code and resources.

- Official Website: [https://ibotpeaches.github.io/Apktool/](https://ibotpeaches.github.io/Apktool/)
- Documentation: [https://ibotpeaches.github.io/Apktool/documentation/](https://ibotpeaches.github.io/Apktool/documentation/)

## dex2jar

dex2jar is a tool for converting Android DEX files to JAR files. It can be used to decompile Android applications and analyze their Java code.

- Official Website: [https://github.com/pxb1988/dex2jar](https://github.com/pxb1988/dex2jar)

## JD-GUI

JD-GUI is a standalone Java decompiler for analyzing and reverse engineering Java bytecode. It can be used to decompile JAR files and analyze their Java code.

- Official Website: [http://java-decompiler.github.io/](http://java-decompiler.github.io/)
- Download: [http://java-decompiler.github.io/jd-gui/download.html](http://java-decompiler.github.io/jd-gui/download.html)

## Androguard

Androguard is a powerful tool for reverse engineering Android applications. It can be used to analyze APK files, decompile DEX files, and extract information from Android manifests.

- Official Website: [https://androguard.readthedocs.io/](https://androguard.readthedocs.io/)
- Documentation: [https://androguard.readthedocs.io/en/latest/](https://androguard.readthedocs.io/en/latest/)

## Bytecode Viewer

Bytecode Viewer is a Java bytecode viewer and decompiler. It can be used to analyze and decompile Java class files.

- Official Website: [https://bytecodeviewer.com/](https://bytecodeviewer.com/)

## IDA Python

IDA Python is a scripting interface for IDA Pro that allows for automation and custom analysis. It provides a Python API for interacting with IDA Pro's features and data.

- Documentation: [https://www.hex-rays.com/products/ida/support/idadoc/417.shtml](https://www.hex-rays.com/products/ida/support/idadoc/417.shtml)

## GDB

GDB is a powerful debugger for analyzing and debugging C and C++ code. It provides advanced features for source-level debugging and memory analysis.

- Official Website: [https://www.gnu.org/software/gdb/](https://www.gnu.org/software/gdb/)

## Pwntools

Pwntools is a Python library and framework for exploit development and binary analysis. It provides a wide range of tools and utilities for interacting with binary code.

- Official Website: [https://pwntools.com/](https://pwntools.com/)
- Documentation: [https://docs.pwntools.com/](https://docs.pwntools.com/)

## Binwalk

Binwalk is a fast and easy-to-use tool for analyzing and extracting firmware images. It can be used to identify embedded files and signatures within binary code.

- Official Website: [https://github.com/ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- Documentation: [https://github.com/ReFirmLabs/binwalk/wiki](https://github.com/ReFirmLabs/binwalk/wiki)

## QEMU

QEMU is a fast and versatile emulator for running and testing operating systems and software. It can be used for analyzing and debugging binary code in a controlled environment.

- Official Website: [https://www.qemu.org/](https://www.qemu.org/)
- Documentation: [https://qemu-project.gitlab.io/qemu/](https://qemu-project.gitlab.io/qemu/)

## Unicorn

Unicorn is a lightweight, multi-platform CPU emulator framework. It can be used for analyzing and executing binary code in a controlled environment.

- Official Website: [https://www.unicorn-engine.org/](https://www.unicorn-engine.org/)
- Documentation: [https://www.unicorn-engine.org/docs/](https://www.unicorn-engine.org/docs/)

## Capstone

Capstone is a lightweight multi-platform disassembly framework. It provides a simple and powerful interface for disassembling binary code.

- Official Website: [https://www.capstone-engine.org/](https://www.capstone-engine.org/)
- Documentation: [https://www.capstone-engine.org/documentation.html](https://www.capstone-engine.org/documentation.html)

## Fuzzing Tools

Fuzzing tools are used for automated testing and vulnerability discovery. They generate and input random or mutated data into a target application to find security vulnerabilities.

- AFL: [https://lcamtuf.coredump.cx/afl/](https://lcamtuf.coredump.cx/afl/)
- Peach Fuzzer: [https://peachfuzzer.com/](https://peachfuzzer.com/)
- Sulley: [https://github.com/OpenRCE/sulley](https://github.com/OpenRCE/sulley)
- American Fuzzy Lop (AFL): [https://lcamtuf.coredump.cx/afl/](https://lcamtuf.coredump.cx/afl/)

## Debuggers

Debuggers are tools used for analyzing and debugging binary code. They provide features such as breakpoints, stepping through code, and inspecting memory.

- GDB: [https://www.gnu.org/software/gdb/](https://www.gnu.org/software/gdb/)
- WinDbg: [https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/)
- OllyDbg: [http://www.ollydbg.de/](http://www.ollydbg.de/)
- x64dbg: [https://x64dbg.com/](https://x64dbg.com/)
- Immunity Debugger: [https://www.immunityinc.com/products/debugger/](https://www.immunityinc.com/products/debugger/)

## Disassemblers

Disassemblers are tools used for converting binary code into human-readable assembly code. They help in understanding the functionality and behavior of a program.

- IDA Pro: [https://www.hex-rays.com/](https://www.hex-rays.com/)
- Ghidra: [https://ghidra-sre.org/](https://ghidra-sre.org/)
- Radare2: [https://www.radare.org/](https://www.radare.org/)
- Hopper: [https://www.hopperapp.com/](https://www.hopperapp.com/)
- Binary Ninja: [https://binary.ninja/](https://binary.ninja/)
- Cutter: [https://cutter.re/](https://cutter.re/)

## Decompilers

Decompilers are tools used for converting binary code into high-level source code. They help in understanding the logic and structure of a program.

- RetDec: [https://retdec.com/](https://retdec.com/)
- JD-GUI: [http://java-decompiler.github.io/](http://java-decompiler.github.io/)

## Static Analysis Tools

Static analysis tools are used for analyzing code without executing it. They help in identifying vulnerabilities, bugs, and other issues in software.

- Androguard: [https://androguard.readthedocs.io/](https://androguard.readthedocs.io/)
- Bytecode Viewer: [https://bytecodeviewer.com/](https://bytecodeviewer.com/)

## Dynamic Analysis Tools

Dynamic analysis tools are used for analyzing code during runtime. They help in understanding the behavior and execution flow of a program.

- Frida: [https://frida.re/](https://frida.re/)
- GDB: [https://www.gnu.org/software/gdb/](https://www.gnu.org/software/gdb/)

## Memory Analysis Tools

Memory analysis tools are used for analyzing and extracting information from volatile memory (RAM). They help in forensic investigations and reverse engineering.

- Volatility: [https://www.volatilityfoundation.org/](https://www.volatilityfoundation.org/)

## Android Tools

Android tools are used for analyzing and reverse engineering Android applications. They help in understanding the structure and behavior of Android apps.

- Apktool: [https://ibotpeaches.github.io/Apktool/](https://ibotpeaches.github.io/Apktool/)
- dex2jar: [https://github.com/pxb1988/dex2jar](https://github.com/pxb1988/dex2jar)
- JD-GUI: [http://java-decompiler.github.io/](http://java-decompiler.github.io/)
- Androguard: [https://androguard.readthedocs.io/](https://androguard.readthedocs.io/)

## Miscellaneous Tools

Miscellaneous tools are additional tools that can be useful for reverse engineering and binary analysis.

- IDA Python: [https://www.hex-rays.com/products/ida/support/idadoc/417.shtml](https://www.hex-rays.com/products/ida/support/idadoc/417.shtml)
- Pwntools: [https://pwntools.com/](https://pwntools.com/)
- Binwalk: [https://github.com/ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- QEMU: [https://www.qemu.org/](https://www.qemu.org/)
- Unicorn: [https://www.unicorn-engine.org/](https://www.unicorn-engine.org/)
- Capstone: [https://www.capstone-engine.org/](https://www.capstone-engine.org/)

## Conclusion

These reversing tools are essential for any reverse engineer or security researcher. They provide the necessary functionality and features for analyzing and understanding binary code. Whether you are analyzing malware, reverse engineering software, or conducting vulnerability research, these tools will greatly assist you in your work.
```text
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
और **कंपाइल** पर क्लिक करें:

![](../../.gitbook/assets/image%20%28314%29%20%281%29.png)

फिर नया फ़ाइल _**फ़ाइल &gt;&gt; मॉड्यूल सहेजें...**_ पर सहेजें:

![](../../.gitbook/assets/image%20%28261%29.png)

यह आवश्यक है क्योंकि यदि आप ऐसा नहीं करते हैं, तो **टाइमर** पर कई **अनुकूलन** कोड पर लागू होंगे और यह संभव है कि डीबगिंग के दौरान कोई **ब्रेक-पॉइंट नहीं हिट होगा** या कुछ **वेरिएबल्स मौजूद नहीं होंगे**।

फिर, यदि आपका .Net एप्लिकेशन **IIS** द्वारा **चलाया** जा रहा है, तो आप इसे **रीस्टार्ट** कर सकते हैं:
```text
iisreset /noforce
```
तो, डीबगिंग शुरू करने के लिए आपको सभी खोले गए फ़ाइलों को बंद करना चाहिए और **डीबग टैब** में जाकर **प्रक्रिया में जुड़ने के लिए चुनें**:

![](../../.gitbook/assets/image%20%28166%29.png)

फिर **w3wp.exe** को चुनें और **IIS सर्वर** में जुड़ने के लिए **जोड़ें**:

![](../../.gitbook/assets/image%20%28274%29.png)

अब जब हम प्रक्रिया को डीबग कर रहे हैं, तो इसे रोकने और सभी मॉड्यूल लोड करने का समय है। पहले _Debug &gt;&gt; Break All_ पर क्लिक करें और फिर _**Debug &gt;&gt; Windows &gt;&gt; Modules**_ पर क्लिक करें:

![](../../.gitbook/assets/image%20%28210%29.png)

![](../../.gitbook/assets/image%20%28341%29.png)

**Modules** पर किसी मॉड्यूल पर क्लिक करें और **Open All Modules** को चुनें:

![](../../.gitbook/assets/image%20%28216%29.png)

**Assembly Explorer** में किसी मॉड्यूल पर दायां क्लिक करें और **Sort Assemblies** पर क्लिक करें:

![](../../.gitbook/assets/image%20%28130%29.png)

# जावा डिकंपाइलर

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

# DLLs की डीबगिंग

## IDA का उपयोग करके

* **rundll32 लोड करें** \(64 बिट C:\Windows\System32\rundll32.exe और 32 बिट C:\Windows\SysWOW64\rundll32.exe में\)
* **Windbg** डीबगर का चयन करें
* "**Suspend on library load/unload**" का चयन करें

![](../../.gitbook/assets/image%20%2869%29.png)

* निष्पादन के **parameters** को कॉन्फ़िगर करें और **DLL के पथ** और वह फ़ंक्शन डालें जिसे आप कॉल करना चाहते हैं:

![](../../.gitbook/assets/image%20%28325%29.png)

फिर, जब आप निष्पादन शुरू करते हैं, **प्रत्येक DLL लोड होने पर निष्पादन रुक जाएगा**, फिर, जब rundll32 आपकी DLL लोड करेगा, निष्पादन रुक जाएगा।

लेकिन, लोड हुए DLL के कोड तक आप कैसे पहुंच सकते हैं? इस तरीके का उपयोग करके, मुझे नहीं पता है।

## x64dbg/x32dbg का उपयोग करके

* **rundll32 लोड करें** \(64 बिट C:\Windows\System32\rundll32.exe और 32 बिट C:\Windows\SysWOW64\rundll32.exe में\)
* **Command Line बदलें** \( _File --&gt; Change Command Line_ \) और dll के पथ और वह फ़ंक्शन डालें जिसे आप कॉल करना चाहते हैं, उदाहरण के लिए: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\14.ridii\_2.dll",DLLMain
* _Options --&gt; Settings_ बदलें और "**DLL Entry**" का चयन करें।
* फिर **निष्पादन शुरू करें**, डीबगर हर डीएलएल मेन में रुक जाएगा, किसी बिंदु पर आपको अपने ब्रेकपॉइंट रखने के लिए खोजना होगा।

ध्यान दें कि जब निष्पादन किसी कारण से win64dbg में रुक जाता है, तो आप देख सकते हैं कि आप किस कोड में हैं, win64dbg विंडो के शीर्ष में देखें:

![](../../.gitbook/assets/image%20%28181%29.png)

फिर, इसे देखकर आप देख सकते हैं कि निष्पादन उस DLL में रुका था जिसे आप डीबग करना चाहते हैं।

# ARM & MIPS

{% embed url="https://github.com/nongiach/arm\_now" %}

# शेलकोड

## blobrunner के साथ शेलकोड की डीबगिंग

[**Blobrunner**](https://github.com/OALabs/BlobRunner) शेलकोड को मेमोरी के एक स्थान में **आवंटित** करेगा, आपको बताएगा कि शेलकोड को किस मेमोरी पते पर आवंटित किया गया है और निष्पादन को रोक देगा। फिर, आपको प्रक्रिया में एक डीबगर \(Ida या x64dbg\) को **जोड़ना** होगा और निर्दिष्ट मेमोरी पते पर एक **ब्रेकपॉइंट रखना** होगा और निष्पादन को **पुनरारंभ** करना होगा। इस तरह आप शेलकोड की डीबगिंग कर रहे होंगे।

जारी गिथब पृष्ठ में कंपाइल किए गए रिलीज़ को ज़िप में शामिल किया गया है: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
आप निम्नलिखित लिंक में ब्लॉबरनर के थोड़े से संशोधित संस्करण को डाउनलोड कर सकते हैं। इसे कंपाइल करने के लिए, बस **Visual Studio Code में एक सी / सी++ परियोजना बनाएं, कोड की प्रतिलिपि करें और इसे बिल्ड करें**।

{% page-ref page="blobrunner.md" %}

## jmp2it के साथ शेलकोड की डीबगिंग

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) blobrunner के बहुत समान है। यह शेलकोड को मेमोरी के एक स्थान में **आवं
## शैलकोड को डीओबफस्केट करना और निष्पादित फंक्शन प्राप्त करना

आपको [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) का प्रयास करना चाहिए।
यह आपको बताएगा कि शैलकोड कौन से **फंक्शन** का उपयोग कर रहा है और क्या शैलकोड स्वयं को मेमोरी में **डिकोड** कर रहा है।
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg एक ग्राफिकल लॉन्चर के साथ भी आता है जहां आप विकल्पों का चयन कर सकते हैं और शेलकोड को निष्पादित कर सकते हैं

![](../../.gitbook/assets/image%20%28401%29.png)

**Create Dump** विकल्प शेलकोड में डाइनामिक रूप से किसी भी परिवर्तन को डंप करेगा \(डिकोड किए गए शेलकोड को डाउनलोड करने के लिए उपयोगी\). **स्टार्ट ऑफसेट** एक विशेष ऑफसेट पर शेलकोड को शुरू करने के लिए उपयोगी हो सकता है। **Debug Shell** विकल्प scDbg टर्मिनल का उपयोग करके शेलकोड को डीबग करने के लिए उपयोगी है \(हालांकि, मैं इस मामले में पहले बताए गए किसी भी विकल्प का उपयोग करने को बेहतर मानता हूँ क्योंकि आप Ida या x64dbg का उपयोग कर सकेंगे\).

## CyberChef का उपयोग करके डिसअसेंबलिंग

अपनी शेलकोड फ़ाइल को इनपुट के रूप में अपलोड करें और इसे डिकॉम्पाइल करने के लिए निम्नलिखित रसीप का उपयोग करें: [https://gchq.github.io/CyberChef/\#recipe=To\_Hex\('Space',0\)Disassemble\_x86\('32','Full%20x86%20architecture',16,0,true,true\)](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

# [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

यह ऑफसेटर सभी निर्देशों को `mov` के लिए बदल देता है \(हाँ, वास्तव में शानदार\). यह निर्देशों को बदलने के लिए अविराम का उपयोग भी करता है। इसके बारे में अधिक जानकारी के लिए:

* [https://www.youtube.com/watch?v=2VF\_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
* [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

यदि आप भाग्यशाली हैं तो [demovfuscator ](https://github.com/kirschju/demovfuscator)बाइनरी को डीऑफसेट करेगा। इसमें कई आवश्यकताएं होती हैं।
```text
apt-get install libcapstone-dev
apt-get install libz3-dev
```
और [keystone को इंस्टॉल करें](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) \(`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`\)

यदि आप **CTF खेल रहे हैं, तो यह फ्लैग ढूंढ़ने के लिए यह workaround** बहुत उपयोगी हो सकता है: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

# Delphi

Delphi कंपाइल किए गए बाइनरी के लिए आप [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) का उपयोग कर सकते हैं

# कोर्सेज

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(बाइनरी डिओबफस्केशन\)



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- क्या आप **साइबर सुरक्षा कंपनी में काम करते हैं**? क्या आप अपनी कंपनी को **HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का एक्सेस** चाहिए? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!

- खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष [**NFT**](https://opensea.io/collection/the-peass-family) संग्रह

- प्राप्त करें [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या मुझे **ट्विटर** पर **फ़ॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **अपने हैकिंग ट्रिक्स को [hacktricks रेपो](https://github.com/carlospolop/hacktricks) और [hacktricks-cloud रेपो](https://github.com/carlospolop/hacktricks-cloud) में पीआर जमा करके साझा करें।**

</details>
