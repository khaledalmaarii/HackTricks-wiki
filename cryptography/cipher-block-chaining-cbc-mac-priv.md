<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>从零开始学习 AWS 黑客攻击！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方的 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。**

</details>


# CBC

如果**cookie** **仅仅**是**用户名**（或者 cookie 的第一部分是用户名），并且你想冒充用户名“**admin**”。那么，你可以创建用户名**"bdmin"** 并**暴力破解** cookie 的**第一个字节**。

# CBC-MAC

在密码学中，**密码块链接消息认证码**（**CBC-MAC**）是一种从块密码构造消息认证码的技术。消息使用某种块密码算法以 CBC 模式加密，以创建**一系列块，使得每个块都依赖于前一个块的正确加密**。这种相互依赖确保对明文**任何**位的**改变**都会导致**最终加密块**以无法预测或抵消的方式**改变**，除非知道块密码的密钥。

要计算消息 m 的 CBC-MAC，人们使用零初始化向量以 CBC 模式加密 m，并保留最后一个块。下图概述了使用秘密密钥 k 和块密码 E 计算由块![m\_{1}\\|m\_{2}\\|\cdots \\|m\_{x}](https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5)组成的消息的 CBC-MAC 的计算：

![CBC-MAC 结构 (en).svg](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png)

# 漏洞

通常使用的 CBC-MAC **IV 是 0**。\
这是一个问题，因为两个已知消息（`m1` 和 `m2`）将独立生成两个签名（`s1` 和 `s2`）。所以：

* `E(m1 XOR 0) = s1`
* `E(m2 XOR 0) = s2`

然后，由 m1 和 m2 连接（m3）组成的消息将生成两个签名（s31 和 s32）：

* `E(m1 XOR 0) = s31 = s1`
* `E(m2 XOR s1) = s32`

**这是可以在不知道加密密钥的情况下计算出来的。**

想象你正在以**8字节**块加密名字**Administrator**：

* `Administ`
* `rator\00\00\00`

你可以创建一个叫做**Administ**的用户名（m1）并检索签名（s1）。\
然后，你可以创建一个叫做 `rator\00\00\00 XOR s1` 的用户名。这将生成 `E(m2 XOR s1 XOR 0)`，即 s32。\
现在，你可以使用 s32 作为完整名字**Administrator**的签名。

### 总结

1. 获取用户名**Administ**（m1）的签名，即 s1
2. 获取用户名**rator\x00\x00\x00 XOR s1 XOR 0** 的签名是 s32**。**
3. 将 cookie 设置为 s32，它将是用户**Administrator**的有效 cookie。

# 攻击控制 IV

如果你可以控制使用的 IV，攻击可能非常简单。\
如果 cookie 只是加密的用户名，为了冒充用户“**administrator**”，你可以创建用户“**Administrator**”，并将得到它的 cookie。\
现在，如果你可以控制 IV，你可以改变 IV 的第一个字节，使得 **IV\[0] XOR "A" == IV'\[0] XOR "a"** 并为用户**Administrator**重新生成 cookie。这个 cookie 将有效地**冒充**初始**IV**下的用户**administrator**。

# 参考资料

更多信息在 [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)


<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>从零开始学习 AWS 黑客攻击！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方的 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。**

</details>
