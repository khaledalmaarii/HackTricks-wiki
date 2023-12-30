# Pickle Rick

## Pickle Rick

<details>

<summary><strong>从零到英雄学习AWS黑客技术</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果你想在 **HackTricks中看到你的公司广告** 或者 **下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现 [**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享你的黑客技巧。**

</details>

![](../../.gitbook/assets/picklerick.gif)

这台机器被归类为简单，而且确实很简单。

## 枚举

我开始使用我的工具 [**Legion**](https://github.com/carlospolop/legion) **枚举这台机器**：

![](<../../.gitbook/assets/image (79) (2).png>)

如你所见，有2个端口开放：80 (**HTTP**) 和 22 (**SSH**)

因此，我启动了legion来枚举HTTP服务：

![](<../../.gitbook/assets/image (234).png>)

注意，在图片中你可以看到 `robots.txt` 包含字符串 `Wubbalubbadubdub`

几秒钟后，我回顾了 `disearch` 已经发现的内容：

![](<../../.gitbook/assets/image (235).png>)

![](<../../.gitbook/assets/image (236).png>)

正如你在最后一张图片中看到的，一个**登录**页面被发现了。

检查根页面的源代码，发现了一个用户名：`R1ckRul3s`

![](<../../.gitbook/assets/image (237) (1).png>)

因此，你可以使用凭据 `R1ckRul3s:Wubbalubbadubdub` 在登录页面登录

## 用户

使用这些凭据，你将访问一个可以执行命令的门户：

![](<../../.gitbook/assets/image (241).png>)

一些命令如cat是不允许的，但你可以使用例如grep来读取第一个成分（标志）：

![](<../../.gitbook/assets/image (242).png>)

然后我使用了：

![](<../../.gitbook/assets/image (243) (1).png>)

来获得一个反向shell：

![](<../../.gitbook/assets/image (239) (1).png>)

**第二个成分**可以在 `/home/rick` 中找到

![](<../../.gitbook/assets/image (240).png>)

## 根

用户 **www-data可以作为sudo执行任何操作**：

![](<../../.gitbook/assets/image (238).png>)

<details>

<summary><strong>从零到英雄学习AWS黑客技术</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果你想在 **HackTricks中看到你的公司广告** 或者 **下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现 [**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享你的黑客技巧。**

</details>
