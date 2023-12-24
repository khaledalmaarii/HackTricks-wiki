# 物理攻击

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 您在**网络安全公司**工作吗？想在**HackTricks**上看到您的**公司广告**？或者想要访问**PEASS的最新版本或下载HackTricks的PDF**？查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列

- 获取[**官方PEASS & HackTricks周边商品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter**上**关注**我 [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud仓库](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>

## BIOS密码

### 电池

大多数**主板**都有一个**电池**。如果你**移除**它**30分钟**，BIOS的设置将会**重启**（包括密码）。

### 跳线CMOS

大多数**主板**都有一个可以重启设置的**跳线**。这个跳线连接一个中心针脚与另一个针脚，如果你**连接这些针脚，主板将会被重置**。

### 实时工具

如果你能够例如从Live CD/USB**运行**一个**Kali** Linux，你可以使用像_**killCmos**_或_**CmosPWD**_（后者包含在Kali中）这样的工具来**恢复BIOS的密码**。

### 在线BIOS密码恢复

输入BIOS密码**3次错误**，然后BIOS将**显示错误信息**并且会被锁定。\
访问页面[https://bios-pw.org](https://bios-pw.org)并**输入BIOS显示的错误代码**，你可能会幸运地得到一个**有效的密码**（**相同的搜索可能会显示不同的密码，而且多个密码可能有效**）。

## UEFI

要检查UEFI的设置并执行某种攻击，你应该尝试使用[chipsec](https://github.com/chipsec/chipsec/blob/master/chipsec-manual.pdf)。\
使用这个工具，你可以轻松地禁用Secure Boot：
```
python chipsec_main.py -module exploits.secure.boot.pk
```
## RAM

### 冷启动

**RAM内存在计算机关闭后的1到2分钟内是持久的**。如果你在内存卡上应用**冷却剂**（例如液氮），你可以将这个时间延长到**10分钟**。

然后，你可以使用工具（如dd.exe、mdd.exe、Memoryze、win32dd.exe或DumpIt）进行**内存转储**，以分析内存。

你应该**使用volatility**来**分析**内存。

### [INCEPTION](https://github.com/carmaa/inception)

Inception是一个利用基于PCI的DMA进行**物理内存操作**的黑客工具。该工具可以通过**FireWire**、**Thunderbolt**、**ExpressCard**、PC Card以及任何其他PCI/PCIe硬件接口进行攻击。\
将你的计算机通过这些**接口**之一连接到受害者计算机，**INCEPTION**将尝试**修补****物理内存**以给你**访问权限**。

**如果INCEPTION成功，任何输入的密码都将有效。**

**它不适用于Windows10。**

## Live CD/USB

### Sticky Keys等

* **SETHC：** 当按下SHIFT键5次时会调用_sethc.exe_
* **UTILMAN：** 按下WINDOWS+U时会调用_Utilman.exe_
* **OSK：** 按下WINDOWS+U，然后启动屏幕键盘时会调用_osk.exe_
* **DISP：** 按下WINDOWS+P时会调用_DisplaySwitch.exe_

这些二进制文件位于_**C:\Windows\System32**_内。你可以将它们中的任何一个**更改**为二进制文件**cmd.exe**的**副本**（也在同一文件夹中），并且任何时候调用这些二进制文件时，都会出现一个以**SYSTEM**身份的命令提示符。

### 修改SAM

你可以使用工具_**chntpw**_来**修改**已挂载Windows文件系统的_**SAM**_**文件**。然后，你可以更改例如管理员用户的密码。\
这个工具在KALI中可用。
```
chntpw -h
chntpw -l <path_to_SAM>
```
**在Linux系统中，你可以修改** _**/etc/shadow**_ **或** _**/etc/passwd**_ **文件。**

### **Kon-Boot**

**Kon-Boot** 是最好的工具之一，它可以让你在不知道密码的情况下登录Windows系统。它通过**挂钩系统BIOS并临时更改Windows内核的内容**来工作（新版本也支持**UEFI**）。然后它允许你在登录时输入**任何内容作为密码**。下次在没有Kon-Boot的情况下启动计算机时，原始密码将恢复，临时更改将被丢弃，系统将表现得如同什么都没有发生。\
阅读更多：[https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/)

它是一个live CD/USB，可以**修补内存**，所以你**不需要知道密码就能登录**。\
Kon-Boot 还执行了**StickyKeys**技巧，所以你可以按下 _**Shift**_ **键5次来获取管理员cmd**。

## **运行Windows**

### 初始快捷方式

### 启动快捷方式

* supr - BIOS
* f8 - 恢复模式
* _supr_ - BIOS ini
* _f8_ - 恢复模式
* _Shitf_（在windows标志之后）- 转到登录页面而不是自动登录（避免自动登录）

### **坏USB**

#### **Rubber Ducky教程**

* [教程1](https://github.com/hak5darren/USB-Rubber-Ducky/wiki/Tutorials)
* [教程2](https://blog.hartleybrody.com/rubber-ducky-guide/)

#### **Teensyduino**

* [有效载荷和教程](https://github.com/Screetsec/Pateensy)

还有大量关于**如何创建你自己的坏USB**的教程。

### 卷影拷贝

拥有管理员权限和powershell，你可以复制SAM文件。[查看这段代码](../windows-hardening/basic-powershell-for-pentesters/#volume-shadow-copy)。

## 绕过Bitlocker

Bitlocker 使用**两个密码**。一个是**用户**使用的，另一个是**恢复**密码（48位数字）。

如果你幸运，在当前的Windows会话中存在文件 _**C:\Windows\MEMORY.DMP**_（它是一个内存转储），你可以尝试**在其中搜索恢复密码**。你可以**获取这个文件**和**文件系统的副本**，然后使用 _Elcomsoft Forensic Disk Decryptor_ 来获取内容（这只有在密码在内存转储中时才有效）。你也可以使用 _**NotMyFault**_ 或 _Sysinternals_ **强制内存转储**，但这将重启系统，并且必须以管理员身份执行。

你也可以尝试使用 _**Passware Kit Forensic**_ 进行**暴力破解攻击**。

### 社会工程学

最后，你可以让用户添加一个新的恢复密码，让他以管理员身份执行：
```bash
schtasks /create /SC ONLOGON /tr "c:/windows/system32/manage-bde.exe -protectors -add c: -rp 000000-000000-000000-000000-000000-000000-000000-000000" /tn tarea /RU SYSTEM /f
```
```markdown
这将在下次登录时添加一个新的恢复密钥（由48个零组成）。

要检查有效的恢复密钥，您可以执行：
```
```
manage-bde -protectors -get c:
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 您在**网络安全公司**工作吗？想在**HackTricks**上看到您的**公司广告**吗？或者您想要访问**PEASS的最新版本或下载HackTricks的PDF**吗？查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列

- 获取[**官方PEASS & HackTricks周边商品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter**上**关注**我 [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud仓库](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>
