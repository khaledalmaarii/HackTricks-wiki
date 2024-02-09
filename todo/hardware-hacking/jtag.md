<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


# JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum)是一个工具，可与Raspberry PI或Arduino一起使用，用于查找未知芯片上的JTAG引脚。\
在**Arduino**中，将**2到11引脚连接到可能属于JTAG的10个引脚**。将程序加载到Arduino中，它将尝试对所有引脚进行暴力破解，以查找哪些引脚属于JTAG，以及每个引脚是哪个。\
在**Raspberry PI**中，您只能使用**1到6引脚**（6个引脚，因此在测试每个潜在的JTAG引脚时速度会较慢）。

## Arduino

在Arduino中，连接电缆（将引脚2到11连接到JTAG引脚，将Arduino GND连接到基板GND后），**在Arduino中加载JTAGenum程序**，并在串行监视器中发送一个**`h`**（帮助命令），您应该看到帮助信息：

![](<../../.gitbook/assets/image (643).png>)

![](<../../.gitbook/assets/image (650).png>)

配置**“无行结束”和115200波特率**。\
发送命令s以开始扫描：

![](<../../.gitbook/assets/image (651) (1) (1) (1).png>)

如果您连接到了JTAG，您将找到一个或多个以**FOUND!**开头的行，指示JTAG的引脚。


<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
