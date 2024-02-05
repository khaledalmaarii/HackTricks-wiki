# Office文件分析

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

- 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
- 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT收藏品](https://opensea.io/collection/the-peass-family)
- **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
- 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)可以轻松构建和**自动化工作流程**，使用世界上**最先进的社区工具**。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 介绍

微软创建了**数十种办公文档文件格式**，其中许多因其能够**包含宏**（VBA脚本）而流行于分发钓鱼攻击和恶意软件。

广义上说，Office文件格式有两代：**OLE格式**（文件扩展名如RTF、DOC、XLS、PPT）和**“Office Open XML”**格式（包括DOCX、XLSX、PPTX等文件扩展名）。**两种**格式都是结构化的、复合文件二进制格式，可以**启用链接或嵌入内容**（对象）。OOXML文件是zip文件容器，这意味着检查隐藏数据的最简单方法之一就是简单地`unzip`文档：
```
$ unzip example.docx
Archive:  example.docx
inflating: [Content_Types].xml
inflating: _rels/.rels
inflating: word/_rels/document.xml.rels
inflating: word/document.xml
inflating: word/theme/theme1.xml
extracting: docProps/thumbnail.jpeg
inflating: word/comments.xml
inflating: word/settings.xml
inflating: word/fontTable.xml
inflating: word/styles.xml
inflating: word/stylesWithEffects.xml
inflating: docProps/app.xml
inflating: docProps/core.xml
inflating: word/webSettings.xml
inflating: word/numbering.xml
$ tree
.
├── [Content_Types].xml
├── _rels
├── docProps
│   ├── app.xml
│   ├── core.xml
│   └── thumbnail.jpeg
└── word
├── _rels
│   └── document.xml.rels
├── comments.xml
├── document.xml
├── fontTable.xml
├── numbering.xml
├── settings.xml
├── styles.xml
├── stylesWithEffects.xml
├── theme
│   └── theme1.xml
└── webSettings.xml
```
正如您所看到的，一些结构是由文件和文件夹层次结构创建的。其余部分在XML文件中指定。[_OOXML文件格式的新隐写术技术_, 2011](http://download.springer.com/static/pdf/713/chp%3A10.1007%2F978-3-642-23300-5\_27.pdf?originUrl=http%3A%2F%2Flink.springer.com%2Fchapter%2F10.1007%2F978-3-642-23300-5\_27\&token2=exp=1497911340\~acl=%2Fstatic%2Fpdf%2F713%2Fchp%25253A10.1007%25252F978-3-642-23300-5\_27.pdf%3ForiginUrl%3Dhttp%253A%252F%252Flink.springer.com%252Fchapter%252F10.1007%252F978-3-642-23300-5\_27\*\~hmac=aca7e2655354b656ca7d699e8e68ceb19a95bcf64e1ac67354d8bca04146fd3d)详细介绍了一些数据隐藏技术的想法，但CTF挑战的作者们总是会想出新的技术。

再次强调，存在一个用于检查和分析OLE和OOXML文档的Python工具集：[oletools](http://www.decalage.info/python/oletools)。特别针对OOXML文档，[OfficeDissector](https://www.officedissector.com)是一个非常强大的分析框架（以及Python库）。后者包括一个[使用快速指南](https://github.com/grierforensics/officedissector/blob/master/doc/html/\_sources/txt/ANALYZING\_OOXML.txt)。

有时挑战不在于找到隐藏的静态数据，而是分析VBA宏以确定其行为。这是一个更加现实的场景，也是领域内分析人员每天执行的任务。前述的分析工具可以指示是否存在宏，并可能为您提取它。在Windows上，Office文档中的典型VBA宏将下载一个PowerShell脚本到%TEMP%并尝试执行它，这种情况下您现在也有一个PowerShell脚本分析任务。但恶意的VBA宏很少复杂，因为VBA通常只被用作启动代码执行的跳板平台。如果您确实需要理解一个复杂的VBA宏，或者宏被混淆并具有解压例程，您无需拥有Microsoft Office许可证来调试这个。您可以使用[Libre Office](http://libreoffice.org)：[其界面](http://www.debugpoint.com/2014/09/debugging-libreoffice-macro-basic-using-breakpoint-and-watch/)将为任何进行程序调试的人熟悉；您可以设置断点和创建监视变量，并在它们被解压但在执行任何有效负载行为之前捕获值。您甚至可以从命令行启动特定文档的宏：
```
$ soffice path/to/test.docx macro://./standard.module1.mymacro
```
## [oletools](https://github.com/decalage2/oletools)
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
## 自动执行

像`AutoOpen`、`AutoExec`或`Document_Open`这样的宏函数将被**自动执行**。

## 参考

* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)可以轻松构建和**自动化工作流程**，利用全球**最先进**的社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
