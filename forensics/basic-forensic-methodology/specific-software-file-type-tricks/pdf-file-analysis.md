# PDF文件分析

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS＆HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)可以轻松构建和**自动化工作流程**，使用世界上**最先进**的社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

来源：[https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

PDF是一种极其复杂的文档文件格式，拥有足够多的技巧和隐藏位置[可以写上几年](https://www.sultanik.com/pocorgtfo/)。这也使其在CTF取证挑战中备受欢迎。NSA在2008年撰写了一份关于这些隐藏位置的指南，标题为“Adobe PDF文件中的隐藏数据和元数据：发布风险和对策”。它不再在原始URL上提供，但您可以[在此处找到副本](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)。Ange Albertini还在GitHub上保留了一个关于[PDF文件格式技巧](https://github.com/corkami/docs/blob/master/PDF/PDF.md)的维基。

PDF格式部分为纯文本，类似于HTML，但内容中包含许多二进制“对象”。Didier Stevens撰写了关于该格式的[良好入门材料](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/)。这些二进制对象可以是压缩或甚至加密数据，并包括使用脚本语言如JavaScript或Flash的内容。要显示PDF的结构，您可以使用文本编辑器浏览它，也可以使用类似Origami这样的PDF感知文件格式编辑器打开它。

[qpdf](https://github.com/qpdf/qpdf)是一个可用于探索PDF并从中转换或提取信息的工具。另一个是Ruby中的一个名为[Origami](https://github.com/mobmewireless/origami-pdf)的框架。

在探索PDF内容以查找隐藏数据时，一些要检查的隐藏位置包括：

* 非可见层
* Adobe的元数据格式“XMP”
* PDF中的“增量生成”功能，其中保留了先前版本但对用户不可见
* 白色背景上的白色文本
* 图像后面的文本
* 一个图像在另一个图像上方
* 未显示的注释

还有几个用于处理PDF文件格式的Python包，如[PeepDF](https://github.com/jesparza/peepdf)，使您能够编写自己的解析脚本。 

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS＆HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
