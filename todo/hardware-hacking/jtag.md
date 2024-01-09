<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


# JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) 是一个可以与树莓派或Arduino一起使用的工具，用于尝试从未知芯片中找到JTAG引脚。\
在**Arduino**中，将**2到11号引脚连接到可能属于JTAG的10个引脚**。在Arduino中加载程序，它将尝试暴力破解所有引脚，以找出哪些引脚属于JTAG以及每个引脚的位置。\
在**树莓派**中，你只能使用**1到6号引脚**（6个引脚，所以测试每个潜在的JTAG引脚的速度会慢一些）。

## Arduino

在Arduino中，连接好电缆（2到11号引脚到JTAG引脚，Arduino GND到基板GND）后，**在Arduino中加载JTAGenum程序**，在串行监视器中发送**`h`**（帮助命令），你应该会看到帮助：

![](<../../.gitbook/assets/image (643).png>)

![](<../../.gitbook/assets/image (650).png>)

配置**"无行结束"和115200波特率**。\
发送命令s开始扫描：

![](<../../.gitbook/assets/image (651) (1) (1) (1).png>)

如果你正在接触JTAG，你会发现一个或多个**以FOUND!开头的行**，指示JTAG的引脚。


<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
