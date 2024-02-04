<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


# CBC

如果**cookie**只是**用户名**（或cookie的第一部分是用户名），而您想要冒充用户名"**admin**"。那么，您可以创建用户名**"bdmin"**并**暴力破解**cookie的**第一个字节**。

# CBC-MAC

在密码学中，**密码块链接消息认证码**（**CBC-MAC**）是一种从块密码构造消息认证码的技术。消息使用某种块密码算法在CBC模式下加密，以创建一个**块链，使得每个块依赖于前一个块的正确加密**。这种相互依赖确保对**任何**明文**位**的更改将导致**最终加密块**以一种不能预测或抵消的方式发生**更改**，而不知道块密码的密钥。

要计算消息m的CBC-MAC，需要使用零初始化向量在CBC模式下加密m并保留最后一个块。以下图示了使用秘密密钥k和块密码E计算消息包含块的CBC-MAC![m\_{1}\\|m\_{2}\\|\cdots \\|m\_{x}](https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5)的计算过程：

![CBC-MAC structure (en).svg](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png)

# 漏洞

使用CBC-MAC时，通常使用的**IV为0**。\
这是一个问题，因为独立的2个已知消息（`m1`和`m2`）将生成2个签名（`s1`和`s2`）。因此：

* `E(m1 XOR 0) = s1`
* `E(m2 XOR 0) = s2`

然后，由m1和m2连接而成的消息（m3）将生成2个签名（s31和s32）：

* `E(m1 XOR 0) = s31 = s1`
* `E(m2 XOR s1) = s32`

**这是可以在不知道加密密钥的情况下计算的。**

想象一下，您正在以**8字节**块加密名称**Administrator**：

* `Administ`
* `rator\00\00\00`

您可以创建一个名为**Administ**（m1）的用户名并检索签名（s1）。\
然后，您可以创建一个名为`rator\00\00\00 XOR s1`结果的用户名。这将生成`E(m2 XOR s1 XOR 0)`，即s32。\
现在，您可以使用s32作为完整名称**Administrator**的签名。

### 总结

1. 获取用户名**Administ**（m1）的签名，即s1
2. 获取用户名**rator\x00\x00\x00 XOR s1 XOR 0**的签名为s32**。**
3. 将cookie设置为s32，它将成为用户**Administrator**的有效cookie。

# 攻击控制IV

如果您可以控制使用的IV，则攻击可能会变得非常容易。\
如果cookie只是加密的用户名，要冒充用户"**administrator**"，您可以创建用户"**Administrator**"并获取其cookie。\
现在，如果您可以控制IV，您可以更改IV的第一个字节，使得**IV\[0] XOR "A" == IV'\[0] XOR "a"**，并重新生成用户**Administrator**的cookie。这个cookie将有效地**冒充**初始**IV**下的用户**administrator**。

# 参考

更多信息请参阅[https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)


<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
