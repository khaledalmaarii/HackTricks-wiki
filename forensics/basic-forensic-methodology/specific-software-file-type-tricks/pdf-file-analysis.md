# PDF文件分析

<details>

<summary><strong>从零到英雄学习AWS黑客技术，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方的PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) 轻松构建并**自动化工作流程**，由世界上**最先进的**社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

来源：[https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

PDF是一种极其复杂的文档文件格式，有足够多的技巧和隐藏地方[可以写上好几年](https://www.sultanik.com/pocorgtfo/)。这也使得它在CTF取证挑战中很受欢迎。NSA在2008年写了一份关于这些隐藏地方的指南，标题为“Adobe PDF文件中的隐藏数据和元数据：发布风险和对策”。它在原始URL上不再可用，但您可以[在这里找到副本](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)。Ange Albertini还在GitHub上维护了一个关于[PDF文件格式技巧的wiki](https://github.com/corkami/docs/blob/master/PDF/PDF.md)。

PDF格式部分是纯文本的，类似HTML，但内容中有许多二进制“对象”。Didier Stevens编写了关于格式的[良好入门材料](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/)。二进制对象可以是压缩的或甚至是加密的数据，并包括像JavaScript或Flash这样的脚本语言内容。要显示PDF的结构，您可以使用文本编辑器浏览它，或者用像Origami这样的PDF感知文件格式编辑器打开它。

[qpdf](https://github.com/qpdf/qpdf) 是一个有用的工具，可以用来探索PDF并转换或提取信息。另一个是Ruby中的框架，称为 [Origami](https://github.com/mobmewireless/origami-pdf)。

在探索PDF内容以寻找隐藏数据时，一些要检查的隐藏地方包括：

* 不可见的图层
* Adobe的元数据格式“XMP”
* PDF的“增量生成”功能，其中保留了以前的版本，但对用户不可见
* 白色背景上的白色文本
* 图像后面的文本
* 重叠图像后面的图像
* 未显示的注释

还有几个Python包可以用来处理PDF文件格式，如 [PeepDF](https://github.com/jesparza/peepdf)，使您能够编写自己的解析脚本。

<details>

<summary><strong>从零到英雄学习AWS黑客技术，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方的PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>
