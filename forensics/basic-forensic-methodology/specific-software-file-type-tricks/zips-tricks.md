# ZIPs 技巧

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS 红队专家）</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想看到您的**公司在 HackTricks 中做广告**或**下载 PDF 版的 HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)** 上**关注我们。
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

有一些针对 zip 文件的命令行工具，了解这些工具将会很有帮助。

* `unzip` 经常会输出有关为何无法解压缩 zip 文件的有用信息。
* `zipdetails -v` 将提供有关格式中各个字段中存在的值的详细信息。
* `zipinfo` 列出有关 zip 文件内容的信息，而无需提取它。
* `zip -F input.zip --out output.zip` 和 `zip -FF input.zip --out output.zip` 尝试修复损坏的 zip 文件。
* [fcrackzip](https://github.com/hyc/fcrackzip) 会暴力破解猜测 zip 文件的密码（对于长度小于 7 个字符左右的密码）。

[Zip 文件格式规范](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

关于受密码保护的 zip 文件的一个重要安全相关说明是，它们不会加密所包含的压缩文件的文件名和原始文件大小，不同于受密码保护的 RAR 或 7z 文件。

关于 zip 破解的另一个说明是，如果您拥有任何一个在加密 zip 文件中被压缩的文件的未加密/未压缩副本，您可以执行“明文攻击”并破解 zip 文件，如[此处详细说明](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)，并在[本文](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf)中有解释。用 AES-256（而不是“ZipCrypto”）对 zip 文件进行密码保护的新方案不具有这种弱点。

来源：[https://app.gitbook.com/@cpol/s/hacktricks/\~/edit/drafts/-LlM5mCby8ex5pOeV4pJ/forensics/basic-forensics-esp/zips-tricks](https://app.gitbook.com/o/Iwnw24TnSs9D9I2OtTKX/s/-L\_2uGJGU7AVNRcqRvEi/)
