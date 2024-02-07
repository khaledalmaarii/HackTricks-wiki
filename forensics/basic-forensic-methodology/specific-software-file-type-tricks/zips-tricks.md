# ZIP技巧

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

用于管理**zip文件**的**命令行工具**对于诊断、修复和破解zip文件至关重要。以下是一些关键的实用工具：

- **`unzip`**：显示zip文件无法解压缩的原因。
- **`zipdetails -v`**：提供zip文件格式字段的详细分析。
- **`zipinfo`**：列出zip文件的内容而不解压缩它们。
- **`zip -F input.zip --out output.zip`** 和 **`zip -FF input.zip --out output.zip`**：尝试修复损坏的zip文件。
- **[fcrackzip](https://github.com/hyc/fcrackzip)**：用于暴力破解zip密码的工具，对长达约7个字符的密码有效。

[Zip文件格式规范](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)提供了关于zip文件的结构和标准的详细信息。

值得注意的是，受密码保护的zip文件**不会加密**其中的文件名或文件大小，这是与RAR或7z文件不同的安全漏洞，后者会加密这些信息。此外，使用旧的ZipCrypto方法加密的zip文件如果存在未加密的压缩文件副本，则容易受到**明文攻击**的影响。这种攻击利用已知内容来破解zip文件的密码，这一漏洞在[HackThis的文章](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)中有详细说明，并在[这篇学术论文](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf)中进一步解释。然而，使用**AES-256**加密的zip文件不受这种明文攻击的影响，突显了为敏感数据选择安全加密方法的重要性。

# 参考资料
* [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
