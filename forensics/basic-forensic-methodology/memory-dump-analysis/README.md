# 内存转储分析

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？想要在HackTricks中看到您的**公司广告**？或者想要访问**PEASS的最新版本或下载HackTricks的PDF**？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上**关注**我 **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧。

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)是**西班牙**最重要的网络安全活动之一，也是**欧洲**最重要的活动之一。作为促进技术知识的使命，这个大会是技术和网络安全专业人士在各个领域的热点交流地。

{% embed url="https://www.rootedcon.com/" %}

## 开始

开始在pcap文件中**搜索****恶意软件**。使用[**恶意软件分析**](../malware-analysis.md)中提到的**工具**。

## [Volatility](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)

**Volatility是主要的开源内存转储分析框架**。这个Python工具分析来自外部来源或VMware虚拟机的转储，根据转储的操作系统配置文件识别数据，如进程和密码。它可以通过插件进行扩展，使其在法医调查中非常灵活。

**[在这里找到一个速查表](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)**

## 迷你转储崩溃报告

当转储文件很小（只有几KB，也许几MB）时，它可能是一个迷你转储崩溃报告，而不是内存转储。

![](<../../../.gitbook/assets/image (216).png>)

如果您安装了Visual Studio，您可以打开此文件并绑定一些基本信息，如进程名称、架构、异常信息和正在执行的模块：

![](<../../../.gitbook/assets/image (217).png>)

您还可以加载异常并查看反编译的指令

![](<../../../.gitbook/assets/image (219).png>)

![](<../../../.gitbook/assets/image (218) (1).png>)

无论如何，Visual Studio并不是执行深度转储分析的最佳工具。

您应该使用IDA或Radare打开它以深入检查。

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)是**西班牙**最重要的网络安全活动之一，也是**欧洲**最重要的活动之一。作为促进技术知识的使命，这个大会是技术和网络安全专业人士在各个领域的热点交流地。

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？想要在HackTricks中看到您的**公司广告**？或者想要访问**PEASS的最新版本或下载HackTricks的PDF**？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上**关注**我 **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧。

</details>
