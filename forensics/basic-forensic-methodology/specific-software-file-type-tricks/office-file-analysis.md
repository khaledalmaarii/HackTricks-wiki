# 办公文件分析

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)可以轻松构建和**自动化工作流程**，使用世界上**最先进的**社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 介绍

微软创建了**数十种办公文档文件格式**，其中许多因其能够**包含宏**（VBA脚本）而在分发钓鱼攻击和恶意软件方面很受欢迎。

广义上说，办公文件格式分为两代：**OLE格式**（文件扩展名如RTF、DOC、XLS、PPT）和“**Office Open XML**”格式（文件扩展名包括DOCX、XLSX、PPTX）。**两种**格式都是结构化的、复合文件二进制格式，可以**启用链接或嵌入内容**（对象）。OOXML文件是zip文件容器，这意味着检查隐藏数据的最简单方法之一就是简单地`unzip`文档：
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
正如你所看到的，文件和文件夹层次结构创建了一部分结构，其余部分在XML文件中指定。[_New Steganographic Techniques for the OOXML File Format_, 2011](http://download.springer.com/static/pdf/713/chp%3A10.1007%2F978-3-642-23300-5\_27.pdf?originUrl=http%3A%2F%2Flink.springer.com%2Fchapter%2F10.1007%2F978-3-642-23300-5\_27\&token2=exp=1497911340\~acl=%2Fstatic%2Fpdf%2F713%2Fchp%25253A10.1007%25252F978-3-642-23300-5\_27.pdf%3ForiginUrl%3Dhttp%253A%252F%252Flink.springer.com%252Fchapter%252F10.1007%252F978-3-642-23300-5\_27\*\~hmac=aca7e2655354b656ca7d699e8e68ceb19a95bcf64e1ac67354d8bca04146fd3d)详细介绍了一些数据隐藏技术的想法，但CTF挑战的作者们总是会想出新的方法。

再次强调，存在一个用于检查和分析OLE和OOXML文档的Python工具集：[oletools](http://www.decalage.info/python/oletools)。特别是对于OOXML文档，[OfficeDissector](https://www.officedissector.com)是一个非常强大的分析框架（和Python库）。后者包括一个[使用指南](https://github.com/grierforensics/officedissector/blob/master/doc/html/\_sources/txt/ANALYZING\_OOXML.txt)。

有时候，挑战不在于找到隐藏的静态数据，而是分析VBA宏以确定其行为。这是一个更现实的场景，也是领域中的分析人员每天都要执行的任务。前面提到的分析工具可以指示是否存在宏，并可能为您提取它。在Windows上，Office文档中的典型VBA宏将下载一个PowerShell脚本到%TEMP%并尝试执行它，这样您现在就有了一个PowerShell脚本分析任务。但是恶意的VBA宏很少复杂，因为VBA通常只用作启动代码执行的平台。如果您确实需要理解一个复杂的VBA宏，或者宏被混淆并具有解包例程，您不需要拥有Microsoft Office的许可证来调试它。您可以使用[Libre Office](http://libreoffice.org)：[其界面](http://www.debugpoint.com/2014/09/debugging-libreoffice-macro-basic-using-breakpoint-and-watch/)对于任何调试过程序的人来说都是熟悉的；您可以设置断点、创建监视变量并在解包后但执行任何有效负载行为之前捕获值。您甚至可以从命令行启动特定文档的宏。
```
$ soffice path/to/test.docx macro://./standard.module1.mymacro
```
## [oletools](https://github.com/decalage2/oletools)

oletools是一组用于分析和检测OLE（Object Linking and Embedding）文件的工具。OLE文件是Microsoft Office文件格式的一种，包括.doc、.xls和.ppt文件。这些工具可以帮助我们分析和检测Office文件中的潜在威胁和漏洞。

### olevba

olevba是oletools中的一个工具，用于分析和提取VBA（Visual Basic for Applications）宏代码。VBA宏代码是Office文件中常用的自动化脚本，可以执行各种操作，包括恶意活动。olevba可以帮助我们分析Office文件中的VBA宏代码，以便检测潜在的恶意行为。

### oledump

oledump是oletools中的另一个工具，用于分析和提取OLE文件中的各种对象。它可以帮助我们分析Office文件中的各种对象，包括文本、图像、嵌入的文件等。通过分析这些对象，我们可以发现隐藏在Office文件中的潜在威胁和漏洞。

### oleid

oleid是oletools中的第三个工具，用于识别和分析OLE文件的类型和属性。它可以帮助我们确定一个文件是否是OLE文件，以及它的具体类型和属性。通过分析文件的类型和属性，我们可以更好地理解文件的结构和功能。

### olemeta

olemeta是oletools中的最后一个工具，用于提取和分析OLE文件中的元数据。元数据是描述文件内容和属性的信息，可以帮助我们更好地理解文件的来源和用途。olemeta可以帮助我们提取和分析Office文件中的元数据，以便发现潜在的威胁和漏洞。

oletools是一个强大的工具集，可以帮助我们分析和检测Office文件中的潜在威胁和漏洞。通过使用这些工具，我们可以更好地理解和保护我们的系统和数据。
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
## 自动执行

`AutoOpen`、`AutoExec`或`Document_Open`等宏函数将被**自动执行**。

## 参考资料

* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)可以轻松构建和**自动化工作流程**，并由全球**最先进的**社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者想要**获取最新版本的PEASS或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
