# ZIP技巧

{% hint style="success" %}
学习并练习AWS Hacking：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习并练习GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** 上关注我们**.
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}

用于管理**zip文件**的**命令行工具**对于诊断、修复和破解zip文件至关重要。以下是一些关键的实用程序：

- **`unzip`**：显示zip文件无法解压缩的原因。
- **`zipdetails -v`**：提供zip文件格式字段的详细分析。
- **`zipinfo`**：列出zip文件的内容而不解压缩它们。
- **`zip -F input.zip --out output.zip`** 和 **`zip -FF input.zip --out output.zip`**：尝试修复损坏的zip文件。
- **[fcrackzip](https://github.com/hyc/fcrackzip)**：用于暴力破解zip密码的工具，对长度约为7个字符的密码非常有效。

[Zip文件格式规范](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)提供了关于zip文件的结构和标准的全面细节。

值得注意的是，受密码保护的zip文件**不会加密**其中的文件名或文件大小，这是与RAR或7z文件不同的安全漏洞，后者会加密这些信息。此外，使用较旧的ZipCrypto方法加密的zip文件如果存在未加密的压缩文件副本，则容易受到**明文攻击**。这种攻击利用已知内容来破解zip的密码，这一漏洞在[HackThis的文章](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)中有详细说明，并在[这篇学术论文](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf)中进一步解释。然而，使用**AES-256**加密的zip文件免疫于这种明文攻击，突显了为敏感数据选择安全加密方法的重要性。

## 参考资料
* [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)

{% hint style="success" %}
学习并练习AWS Hacking：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习并练习GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** 上关注我们**.
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
