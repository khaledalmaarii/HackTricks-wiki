# Pickle Rick

## Pickle Rick

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

![](../../.gitbook/assets/picklerick.gif)

这台机器被归类为简单，而且确实很简单。

## 枚举

我开始使用我的工具[**Legion**](https://github.com/carlospolop/legion)来**枚举机器**：

![](<../../.gitbook/assets/image (79) (2).png>)

如您所见，有2个端口打开：80（**HTTP**）和22（**SSH**）

因此，我启动了Legion来枚举HTTP服务：

![](<../../.gitbook/assets/image (234).png>)

请注意，在图像中您可以看到`robots.txt`包含字符串`Wubbalubbadubdub`

几秒钟后，我查看了`disearch`已经发现的内容：

![](<../../.gitbook/assets/image (235).png>)

![](<../../.gitbook/assets/image (236).png>)

正如您在最后一个图像中所看到的，发现了一个**登录**页面。

检查根页面的源代码，发现了一个用户名：`R1ckRul3s`

![](<../../.gitbook/assets/image (237) (1).png>)

因此，您可以使用凭据`R1ckRul3s:Wubbalubbadubdub`登录登录页面

## 用户

使用这些凭据，您将访问一个可以执行命令的门户：

![](<../../.gitbook/assets/image (241).png>)

一些命令如cat不被允许，但您可以使用例如grep来读取第一个成分（标志）：

![](<../../.gitbook/assets/image (242).png>)

然后我使用：

![](<../../.gitbook/assets/image (243) (1).png>)

来获取一个反向shell：

![](<../../.gitbook/assets/image (239) (1).png>)

**第二个成分**可以在`/home/rick`中找到

![](<../../.gitbook/assets/image (240).png>)

## Root

用户**www-data可以作为sudo执行任何操作**：

![](<../../.gitbook/assets/image (238).png>)

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
