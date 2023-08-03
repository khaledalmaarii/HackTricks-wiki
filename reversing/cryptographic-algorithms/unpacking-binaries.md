<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者想要**获取PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>


# 识别打包的二进制文件

* **缺少字符串**：通常发现打包的二进制文件几乎没有任何字符串
* 大量**未使用的字符串**：当恶意软件使用某种商业打包工具时，通常会发现大量没有交叉引用的字符串。即使存在这些字符串，也不意味着二进制文件没有被打包。
* 您还可以使用一些工具来尝试找出用于打包二进制文件的打包工具：
* [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
* [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
* [Language 2000](http://farrokhi.net/language/)

# 基本建议

* **从IDA的底部开始**分析打包的二进制文件，然后向上移动。解包器在解包的代码退出时退出，因此解包器不太可能在开始时将执行权传递给解包的代码。
* 搜索**JMP**或**CALL**到**寄存器**或**内存区域**的指令。还要搜索**将参数和地址方向推送到函数中，然后调用`retn`**的函数，因为在这种情况下，函数的返回可能在调用之前调用堆栈上刚刚推送的地址。
* 在`VirtualAlloc`上设置**断点**，因为它会在程序可以写入解包的代码的内存中分配空间。使用“运行到用户代码”或使用F8在执行函数后**进入EAX中的值**，然后“**在转储中跟随该地址**”。您永远不知道解包的代码将保存在哪个区域。
* **`VirtualAlloc`**的参数值为“**40**”表示可读+可写+可执行（将在此处复制一些需要执行的代码）。
* 在解包代码时，通常会发现对**算术运算**和**`memcopy`**或**`Virtual`**`Alloc`等函数的**多次调用**。如果您发现自己在一个似乎只执行算术运算和可能的`memcopy`的函数中，建议尝试**找到函数的结尾**（可能是JMP或对某个寄存器的调用），或者至少找到**最后一个函数的调用**，然后运行到该函数，因为代码不感兴趣。
* 在解包代码时，**注意**每当**更改内存区域**时，因为内存区域的更改可能表示解包代码的开始。您可以使用Process Hacker轻松转储内存区域（进程->属性->内存）。
* 在尝试解包代码时，了解是否已经在处理**解包的代码**（因此可以直接转储）的一个好方法是**检查二进制文件的字符串**。如果在某个时刻执行了跳转（可能更改了内存区域）并且您注意到**添加了更多字符串**，那么您就可以知道**您正在处理解包的代码**。\
但是，如果打包工具已经包含了很多字符串，您可以查看包含单词“http”的字符串数量，并查看该数字是否增加。
* 当从内存区域转储可执行文件时，您可以使用[PE-bear](https://github.com/hasherezade/pe-bear-releases/releases)修复一些头部信息。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者想要**获取PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>
