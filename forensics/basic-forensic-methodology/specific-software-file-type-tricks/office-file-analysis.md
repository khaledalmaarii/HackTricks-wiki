# Office文件分析

<details>

<summary><strong>从零到英雄学习AWS黑客技术，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) 轻松构建并**自动化工作流程**，由世界上**最先进的**社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 介绍

Microsoft创建了**数十种Office文档文件格式**，其中许多因为能够**包含宏**（VBA脚本）而在钓鱼攻击和恶意软件的分发中非常流行。

总的来说，Office文件格式有两代：**OLE格式**（文件扩展名如RTF、DOC、XLS、PPT），以及"**Office Open XML**"格式（文件扩展名包括DOCX、XLSX、PPTX）。**两种**格式都是结构化的、复合文件二进制格式，能够**启用链接或嵌入内容**（对象）。OOXML文件是zip文件容器，这意味着检查隐藏数据最简单的方法之一就是简单地`unzip`文档：
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
正如您所见，一些结构是由文件和文件夹层次结构创建的。其余的则在XML文件内指定。[_New Steganographic Techniques for the OOXML File Format_, 2011](http://download.springer.com/static/pdf/713/chp%3A10.1007%2F978-3-642-23300-5\_27.pdf?originUrl=http%3A%2F%2Flink.springer.com%2Fchapter%2F10.1007%2F978-3-642-23300-5\_27\&token2=exp=1497911340\~acl=%2Fstatic%2Fpdf%2F713%2Fchp%25253A10.1007%25252F978-3-642-23300-5\_27.pdf%3ForiginUrl%3Dhttp%253A%252F%252Flink.springer.com%252Fchapter%252F10.1007%252F978-3-642-23300-5\_27\*\~hmac=aca7e2655354b656ca7d699e8e68ceb19a95bcf64e1ac67354d8bca04146fd3d) 详细介绍了一些数据隐藏技术的想法，但CTF挑战的作者总是会想出新的方法。

再次强调，存在用于检查和**分析OLE和OOXML文档**的Python工具集：[oletools](http://www.decalage.info/python/oletools)。特别是对于OOXML文档，[OfficeDissector](https://www.officedissector.com) 是一个非常强大的分析框架（和Python库）。后者包括[快速使用指南](https://github.com/grierforensics/officedissector/blob/master/doc/html/\_sources/txt/ANALYZING\_OOXML.txt)。

有时挑战不在于找到隐藏的静态数据，而在于**分析VBA宏**以确定其行为。这是一个更现实的场景，也是领域分析师每天都在执行的任务。上述分析工具可以指示是否存在宏，并且可能为您提取它。在Windows上的Office文档中，典型的VBA宏将下载一个PowerShell脚本到%TEMP%并尝试执行它，在这种情况下，您现在也有了PowerShell脚本分析任务。但是恶意VBA宏很少复杂，因为VBA[通常只是用作引导代码执行的跳板](https://www.lastline.com/labsblog/party-like-its-1999-comeback-of-vba-malware-downloaders-part-3/)。在您确实需要理解复杂的VBA宏的情况下，或者如果宏被混淆并且有一个解包程序，您不需要拥有Microsoft Office的许可证来调试这个。您可以使用[Libre Office](http://libreoffice.org)：[其界面](http://www.debugpoint.com/2014/09/debugging-libreoffice-macro-basic-using-breakpoint-and-watch/)对任何调试过程序的人来说都会很熟悉；您可以设置断点和创建观察变量，并在解包后但在任何有效载荷行为执行之前捕获值。您甚至可以从命令行启动特定文档的宏：
```
$ soffice path/to/test.docx macro://./standard.module1.mymacro
```
## [oletools](https://github.com/decalage2/oletools)
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
## 自动执行

宏功能如 `AutoOpen`、`AutoExec` 或 `Document_Open` 将会**自动** **执行**。

## 参考资料

* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) 可以轻松构建并**自动化工作流程**，由世界上**最先进**的社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击！</strong></summary>

其他支持HackTricks的方式：

* 如果您希望在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来**分享您的黑客技巧。

</details>
