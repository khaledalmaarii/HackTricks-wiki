# ZIP技巧

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者想要**获取PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

有一些命令行工具可用于处理zip文件，这些工具非常有用。

* `unzip`通常会输出有关为何无法解压缩zip文件的有用信息。
* `zipdetails -v`提供了有关格式中各个字段中存在的值的详细信息。
* `zipinfo`列出了zip文件内容的信息，而无需提取它。
* `zip -F input.zip --out output.zip`和`zip -FF input.zip --out output.zip`尝试修复损坏的zip文件。
* [fcrackzip](https://github.com/hyc/fcrackzip)可以暴力破解zip密码（对于密码长度小于7个字符左右的密码）。

[Zip文件格式规范](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

关于密码保护的zip文件的一个重要安全注意事项是，它们不会加密所包含的压缩文件的文件名和原始文件大小，而与密码保护的RAR或7z文件不同。

关于zip破解的另一个注意事项是，如果你拥有加密zip中任何一个被压缩的文件的未加密/未压缩副本，你可以进行“明文攻击”并破解zip文件，详细信息请参见[这里](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)，并在[这篇论文](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf)中有解释。使用AES-256（而不是“ZipCrypto”）对zip文件进行密码保护的较新方案不具有此弱点。

来源：[https://app.gitbook.com/@cpol/s/hacktricks/\~/edit/drafts/-LlM5mCby8ex5pOeV4pJ/forensics/basic-forensics-esp/zips-tricks](https://app.gitbook.com/o/Iwnw24TnSs9D9I2OtTKX/s/-L\_2uGJGU7AVNRcqRvEi/)
