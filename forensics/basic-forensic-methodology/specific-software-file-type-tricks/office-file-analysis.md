# Office文件分析

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
使用[**Trickest**](https://trickest.io/)可以轻松构建和**自动化工作流程**，使用世界上**最先进的**社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 介绍

微软创建了**数十种办公文档文件格式**，其中许多格式因其能够**包含宏**（VBA脚本）而在分发钓鱼攻击和恶意软件方面很受欢迎。

广义上讲，Office文件格式分为两代：**OLE格式**（文件扩展名如RTF、DOC、XLS、PPT）和“**Office Open XML**”格式（文件扩展名包括DOCX、XLSX、PPTX）。**两种**格式都是结构化的、复合文件二进制格式，可以**启用链接或嵌入内容**（对象）。OOXML文件是zip文件容器，这意味着检查隐藏数据的最简单方法之一就是简单地`unzip`文档：
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

再次强调，存在一个用于检查和分析OLE和OOXML文档的Python工具集：[oletools](http://www.decalage.info/python/oletools)。特别是对于OOXML文档，[OfficeDissector](https://www.officedissector.com)是一个非常强大的分析框架（和Python库）。后者包括一个[快速使用指南](https://github.com/grierforensics/officedissector/blob/master/doc/html/\_sources/txt/ANALYZING\_OOXML.txt)。

有时候，挑战不在于找到隐藏的静态数据，而是分析VBA宏以确定其行为。这是一个更现实的场景，也是领域中的分析人员每天都要执行的任务。前面提到的分析工具可以指示是否存在宏，并可能为您提取它。在Windows上，Office文档中的典型VBA宏将下载一个PowerShell脚本到%TEMP%并尝试执行它，这样您现在就有了一个PowerShell脚本分析任务。但是恶意的VBA宏很少复杂，因为VBA通常只用作启动代码执行的平台。如果您确实需要理解一个复杂的VBA宏，或者宏被混淆并具有解包程序，您不需要拥有Microsoft Office的许可证来调试它。您可以使用[Libre Office](http://libreoffice.org)：[其界面](http://www.debugpoint.com/2014/09/debugging-libreoffice-macro-basic-using-breakpoint-and-watch/)对于任何调试过程序的人来说都是熟悉的；您可以设置断点、创建监视变量并在解包后但执行任何有效负载行为之前捕获值。您甚至可以从命令行启动特定文档的宏。
```
$ soffice path/to/test.docx macro://./standard.module1.mymacro
```
## [oletools](https://github.com/decalage2/oletools)

oletools是一组用于分析和检测OLE（Object Linking and Embedding）文件的工具。OLE文件是Microsoft Office文件（如.doc，.xls和.ppt）的基础。这些工具可以帮助你分析和提取OLE文件中的信息，以便进行恶意软件分析、取证和逆向工程。

### olevba

olevba是oletools中的一个工具，用于分析和提取VBA（Visual Basic for Applications）宏代码。VBA宏是一种常见的恶意软件传播和执行代码的方式。olevba可以帮助你分析OLE文件中的VBA宏代码，以便检测潜在的恶意行为。

### oledump

oledump是oletools中的另一个工具，用于分析和提取OLE文件中的各种对象。它可以帮助你查看OLE文件的结构、提取嵌入的文件、查找隐藏的数据和元数据等。oledump还可以检测OLE文件中的恶意代码和漏洞。

### oleid

oleid是oletools中的第三个工具，用于识别OLE文件的类型和属性。它可以帮助你确定一个文件是否是OLE文件，以及它的文件类型和属性。oleid还可以检测OLE文件中的恶意代码和漏洞。

### olemeta

olemeta是oletools中的最后一个工具，用于提取和分析OLE文件中的元数据。元数据包含有关文件的信息，如作者、创建日期、修改日期等。olemeta可以帮助你获取OLE文件的元数据，以便进行取证和分析。

这些工具可以单独使用，也可以结合使用，以便进行全面的OLE文件分析和检测。它们对于恶意软件分析人员、取证人员和逆向工程师来说都是非常有用的工具。
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
## 自动执行

`AutoOpen`、`AutoExec`或`Document_Open`等宏函数将被**自动执行**。

## 参考资料

* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的动态[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
