# Hash Length Extension Attack

{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) 是一个由 **暗网** 驱动的搜索引擎，提供 **免费** 功能以检查公司或其客户是否被 **窃取恶意软件** **入侵**。

WhiteIntel 的主要目标是打击由于信息窃取恶意软件导致的账户接管和勒索软件攻击。

您可以访问他们的网站并免费尝试他们的引擎：

{% embed url="https://whiteintel.io" %}

***

## 攻击概述

想象一个服务器，它通过 **附加** 一个 **秘密** 到一些已知的明文数据并对这些数据进行 **签名**。如果您知道：

* **秘密的长度**（这也可以从给定的长度范围进行暴力破解）
* **明文数据**
* **算法（并且它对这种攻击是脆弱的）**
* **填充是已知的**
* 通常使用默认填充，因此如果满足其他 3 个要求，这个也满足
* 填充根据秘密+数据的长度而变化，这就是为什么需要知道秘密的长度

那么，**攻击者** 可以 **附加** **数据** 并为 **之前的数据 + 附加的数据** 生成一个有效的 **签名**。

### 如何？

基本上，脆弱的算法首先通过 **哈希一个数据块** 来生成哈希，然后 **从** 之前创建的 **哈希**（状态）中 **添加下一个数据块** 并 **哈希它**。

然后，想象秘密是 "secret"，数据是 "data"，"secretdata" 的 MD5 是 6036708eba0d11f6ef52ad44e8b74d5b。\
如果攻击者想要附加字符串 "append"，他可以：

* 生成 64 个 "A" 的 MD5
* 将之前初始化的哈希状态更改为 6036708eba0d11f6ef52ad44e8b74d5b
* 附加字符串 "append"
* 完成哈希，结果哈希将是 **"secret" + "data" + "padding" + "append" 的有效哈希**

### **工具**

{% embed url="https://github.com/iagox86/hash_extender" %}

### 参考

您可以在 [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks) 找到对此攻击的详细解释。

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) 是一个由 **暗网** 驱动的搜索引擎，提供 **免费** 功能以检查公司或其客户是否被 **窃取恶意软件** **入侵**。

WhiteIntel 的主要目标是打击由于信息窃取恶意软件导致的账户接管和勒索软件攻击。

您可以访问他们的网站并免费尝试他们的引擎：

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}
