# Pickle Rick

## Pickle Rick

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

![](../../.gitbook/assets/picklerick.gif)

这台机器被归类为简单，而且很容易。

## 枚举

我开始使用我的工具[**Legion**](https://github.com/carlospolop/legion)对机器进行枚举：

![](<../../.gitbook/assets/image (79) (2).png>)

如你所见，有2个端口是开放的：80（**HTTP**）和22（**SSH**）

所以，我启动了Legion来枚举HTTP服务：

![](<../../.gitbook/assets/image (234).png>)

请注意，在图像中你可以看到`robots.txt`包含字符串`Wubbalubbadubdub`

几秒钟后，我查看了`disearch`已经发现的内容：

![](<../../.gitbook/assets/image (235).png>)

![](<../../.gitbook/assets/image (236).png>)

正如你在最后一张图片中看到的，发现了一个**登录**页面。

检查根页面的源代码，发现了一个用户名：`R1ckRul3s`

![](<../../.gitbook/assets/image (237) (1).png>)

因此，你可以使用凭据`R1ckRul3s:Wubbalubbadubdub`登录登录页面

## 用户

使用这些凭据，你将进入一个可以执行命令的门户：

![](<../../.gitbook/assets/image (241).png>)

一些命令，如cat，是不允许的，但你可以使用grep来读取第一个配料（flag）：

![](<../../.gitbook/assets/image (242).png>)

然后我使用了：

![](<../../.gitbook/assets/image (243) (1).png>)

来获取一个反向shell：

![](<../../.gitbook/assets/image (239) (1).png>)

**第二个配料**可以在`/home/rick`中找到

![](<../../.gitbook/assets/image (240).png>)

## Root

用户**www-data可以以sudo的方式执行任何命令**：

![](<../../.gitbook/assets/image (238).png>)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
