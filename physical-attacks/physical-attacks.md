# 物理攻击

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在 HackTricks 中**宣传你的公司**吗？或者你想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家 NFT 收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks 仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud)提交 PR 来分享你的黑客技巧**。

</details>

## BIOS 密码

### 电池

大多数**主板**都有一个**电池**。如果你**拆下**它**30分钟**，BIOS 的设置将会**重置**（包括密码）。

### CMOS 跳线

大多数**主板**都有一个可以重置设置的**跳线**。这个跳线将一个中心引脚与另一个引脚连接起来，如果你**连接这些引脚，主板将被重置**。

### 实时工具

如果你能够从 Live CD/USB 上**运行**例如 Kali Linux，你可以使用像 _**killCmos**_ 或 _**CmosPWD**_（后者已包含在 Kali 中）这样的工具来**恢复 BIOS 的密码**。

### 在线 BIOS 密码恢复

将 BIOS 的密码**连续输错 3 次**，然后 BIOS 将**显示一个错误消息**并被锁定。\
访问页面[https://bios-pw.org](https://bios-pw.org)并**输入 BIOS 显示的错误代码**，你可能会有幸得到一个**有效的密码**（**相同的搜索可能会显示不同的密码，而且可能有多个密码有效**）。

## UEFI

要检查 UEFI 的设置并执行某种攻击，你可以尝试使用 [chipsec](https://github.com/chipsec/chipsec/blob/master/chipsec-manual.pdf)。\
使用这个工具，你可以轻松地禁用 Secure Boot：
```
python chipsec_main.py -module exploits.secure.boot.pk
```
## RAM

### 冷启动攻击

**RAM内存在计算机关闭后的1到2分钟内是持久的**。如果你在内存卡上应用**冷却**（例如液氮），你可以将这个时间延长到**10分钟**。

然后，你可以使用**dd.exe、mdd.exe、Memoryze、win32dd.exe或DumpIt**等工具进行**内存转储**，以便分析内存。

你应该使用**volatility**来**分析**内存。

### [INCEPTION](https://github.com/carmaa/inception)

Inception是一款利用基于PCI的DMA进行**物理内存操作**和黑客攻击的工具。该工具可以通过**FireWire、Thunderbolt、ExpressCard、PC Card**和任何其他PCI/PCIe硬件接口进行攻击。\
将你的计算机通过其中一个**接口**连接到受害者的计算机上，**INCEPTION**将尝试**修改****物理内存**以便给你**访问权限**。

**如果INCEPTION成功，任何输入的密码都将有效。**

**它不适用于Windows10。**

## Live CD/USB

### Sticky Keys和更多

* **SETHC：**在按下SHIFT键5次时调用_sethc.exe_
* **UTILMAN：**通过按下WINDOWS+U调用_Utilman.exe_
* **OSK：**通过按下WINDOWS+U，然后启动屏幕键盘来调用_osk.exe_
* **DISP：**通过按下WINDOWS+P调用_DisplaySwitch.exe_

这些二进制文件位于_**C:\Windows\System32**_目录下。你可以将其中任何一个更改为二进制文件**cmd.exe**的副本（同样位于相同目录下），每当你调用其中任何一个二进制文件时，一个作为**SYSTEM**的命令提示符将出现。

### 修改SAM

你可以使用工具_**chntpw**_来**修改**已挂载的Windows文件系统的_**SAM文件**_。然后，你可以更改管理员用户的密码，例如。\
这个工具在KALI中可用。
```
chntpw -h
chntpw -l <path_to_SAM>
```
**在Linux系统中，您可以修改** _**/etc/shadow**_ **或** _**/etc/passwd**_ **文件。**

### **Kon-Boot**

**Kon-Boot**是一款最好的工具之一，可以在不知道密码的情况下登录Windows。它通过在启动时**钩入系统BIOS并临时更改Windows内核的内容**来工作（新版本也适用于**UEFI**）。然后，它允许您在登录时输入**任何密码**。下次您在没有Kon-Boot的情况下启动计算机时，原始密码将恢复，临时更改将被丢弃，系统将表现得好像什么都没有发生。\
阅读更多：[https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/)

它是一个可以**修补内存**的Live CD/USB，因此您**无需知道密码即可登录**。\
Kon-Boot还执行**StickyKeys**技巧，因此您可以按下_**Shift**_** 5次以获取管理员命令提示符**。

## **运行Windows**

### 初始快捷方式

### 启动快捷方式

* supr - BIOS
* f8 - 恢复模式
* _supr_ - BIOS ini
* _f8_ - 恢复模式
* _Shitf_（在Windows标志后）- 转到登录页面而不是自动登录（避免自动登录）

### **恶意USB**

#### **Rubber Ducky教程**

* [教程1](https://github.com/hak5darren/USB-Rubber-Ducky/wiki/Tutorials)
* [教程2](https://blog.hartleybrody.com/rubber-ducky-guide/)

#### **Teensyduino**

* [Payloads和教程](https://github.com/Screetsec/Pateensy)

还有很多关于**如何创建自己的恶意USB**的教程。

### 阴影副本

使用管理员权限和PowerShell，您可以制作SAM文件的副本。[查看此代码](../windows-hardening/basic-powershell-for-pentesters/#volume-shadow-copy)。

## 绕过Bitlocker

Bitlocker使用**2个密码**。一个是由**用户**使用的密码，另一个是**恢复**密码（48位数字）。

如果您很幸运，并且在当前Windows会话中存在文件_**C:\Windows\MEMORY.DMP**_（它是一个内存转储），您可以尝试在其中搜索恢复密码。您可以**获取此文件**和**文件系统的副本**，然后使用_Elcomsoft Forensic Disk Decryptor_获取内容（仅当密码在内存转储中时才有效）。您还可以使用_Sysinternals_的_NotMyFault_强制进行内存转储，但这将重新启动系统，并且必须以管理员身份执行。

您还可以尝试使用_**Passware Kit Forensic**_进行**暴力破解攻击**。

### 社交工程

最后，您可以让用户添加一个新的恢复密码，使其以管理员身份执行：
```bash
schtasks /create /SC ONLOGON /tr "c:/windows/system32/manage-bde.exe -protectors -add c: -rp 000000-000000-000000-000000-000000-000000-000000-000000" /tn tarea /RU SYSTEM /f
```
这将在下次登录时添加一个由48个零组成的新恢复密钥。

要检查有效的恢复密钥，可以执行以下操作：
```
manage-bde -protectors -get c:
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在 HackTricks 中**宣传你的公司**吗？或者你想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)

- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**推特**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来分享你的黑客技巧**。

</details>
