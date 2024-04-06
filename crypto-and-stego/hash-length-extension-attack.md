<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


# 攻击摘要

想象一个服务器通过**将一个** **秘密** **附加**到一些已知的明文数据上，然后对该数据进行哈希来**签署**一些**数据**。如果您知道：

* **秘密的长度**（这也可以从给定长度范围内进行暴力破解）
* **明文数据**
* **算法（及其容易受到此攻击）**
* **填充是已知的**
* 通常会使用默认填充，因此如果满足其他3个要求，这也是可以的
* 填充取决于秘密+数据的长度，因此需要知道秘密的长度

那么，攻击者可以**附加** **数据**并为**先前数据+附加数据**生成有效的**签名**。

## 如何实现？

基本上，易受攻击的算法首先通过**对数据块进行哈希处理**生成哈希，然后，**从**先前创建的**哈希**（状态）开始，它们**添加下一个数据块**并**对其进行哈希处理**。

然后，想象秘密是"secret"，数据是"data"，"secretdata"的MD5是6036708eba0d11f6ef52ad44e8b74d5b。\
如果攻击者想要附加字符串"append"，他可以：

* 生成64个"A"的MD5
* 将先前初始化的哈希状态更改为6036708eba0d11f6ef52ad44e8b74d5b
* 附加字符串"append"
* 完成哈希处理，生成的哈希将是**对"secret" + "data" + "填充" + "append"**的有效哈希**

## **工具**

{% embed url="https://github.com/iagox86/hash_extender" %}

# 参考资料

您可以在[https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)中找到对此攻击的很好解释。

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
