# ZIPs 技巧

<details>

<summary><strong>从零开始学习 AWS 黑客技术直至成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

其他支持 HackTricks 的方式：

* 如果您想在 HackTricks 中看到您的**公司广告**或**下载 HackTricks 的 PDF 版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

有一些命令行工具对于 zip 文件非常有用，值得了解。

* `unzip` 常常会输出有助于了解为什么 zip 文件无法解压的信息。
* `zipdetails -v` 将提供关于格式各个字段中存在的值的深入信息。
* `zipinfo` 列出 zip 文件内容的信息，无需提取它。
* `zip -F input.zip --out output.zip` 和 `zip -FF input.zip --out output.zip` 尝试修复损坏的 zip 文件。
* [fcrackzip](https://github.com/hyc/fcrackzip) 用暴力破解法猜测 zip 密码（对于少于7个字符的密码）。

[Zip 文件格式规范](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

关于密码保护的 zip 文件的一个重要安全相关说明是，它们不会加密文件名和压缩文件的原始文件大小，不像密码保护的 RAR 或 7z 文件。

关于破解 zip 的另一个说明是，如果您有加密 zip 中压缩的任何一个文件的未加密/未压缩副本，您可以执行“明文攻击”并破解 zip，如[此处详述](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)，并在[这篇论文](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf)中解释。用于密码保护 zip 文件的较新方案（使用 AES-256，而不是“ZipCrypto”）没有这个弱点。

来自：[https://app.gitbook.com/@cpol/s/hacktricks/\~/edit/drafts/-LlM5mCby8ex5pOeV4pJ/forensics/basic-forensics-esp/zips-tricks](https://app.gitbook.com/o/Iwnw24TnSs9D9I2OtTKX/s/-L\_2uGJGU7AVNRcqRvEi/)

<details>

<summary><strong>从零开始学习 AWS 黑客技术直至成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

其他支持 HackTricks 的方式：

* 如果您想在 HackTricks 中看到您的**公司广告**或**下载 HackTricks 的 PDF 版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>
