<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>从零开始学习 AWS 黑客攻击！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上[**关注我**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>


# 攻击概要

想象一个服务器，它通过在一些已知的明文数据后**附加**一个**秘密**，然后对该数据进行哈希处理来**签名**一些**数据**。如果你知道：

* **秘密的长度**（这也可以从给定的长度范围内暴力破解）
* **明文数据**
* **算法（并且它对这种攻击是脆弱的）**
* **填充是已知的**
* 通常使用默认的填充，所以如果满足其他三个要求，这也是满足的
* 填充根据秘密+数据的长度而变化，这就是为什么需要秘密的长度

那么，**攻击者**就有可能**附加** **数据**并为**之前的数据 + 附加的数据**生成有效的**签名**。

## 如何做？

基本上，脆弱的算法首先通过**哈希一个数据块**来生成哈希值，然后，从**先前**创建的**哈希**（状态）出发，它们**添加下一个数据块**并**对其进行哈希处理**。

然后，假设秘密是 "secret" 而数据是 "data"，"secretdata" 的 MD5 是 6036708eba0d11f6ef52ad44e8b74d5b。\
如果攻击者想要附加字符串 "append"，他可以：

* 生成 64 个 "A" 的 MD5
* 将先前初始化的哈希状态更改为 6036708eba0d11f6ef52ad44e8b74d5b
* 附加字符串 "append"
* 完成哈希，结果哈希将是 "secret" + "data" + "padding" + "append" 的**有效哈希**

## **工具**

{% embed url="https://github.com/iagox86/hash_extender" %}

# 参考资料

你可以在 [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks) 找到很好的解释这种攻击的文章


<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>从零开始学习 AWS 黑客攻击！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上[**关注我**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>
