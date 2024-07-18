{% hint style="success" %}
学习并练习AWS Hacking：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习并练习GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 检查[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}


# CBC

如果**cookie**只是**用户名**（或 cookie 的第一部分是用户名），而您想要冒充用户名"**admin**"。那么，您可以创建用户名**"bdmin"**并**暴力破解** cookie 的**第一个字节**。

# CBC-MAC

**密码块链接消息认证码**（**CBC-MAC**）是密码学中使用的一种方法。它通过逐块加密消息来工作，其中每个块的加密与前一个块相关联。这个过程创建了一个**块链**，确保即使更改原始消息的一个位，也会导致加密数据的最后一个块发生不可预测的变化。要进行或逆转这样的更改，需要加密密钥，确保安全性。

要计算消息 m 的 CBC-MAC，需要使用零初始化向量在 CBC 模式下加密 m 并保留最后一个块。以下图示了使用秘密密钥 k 和块密码 E 计算消息组成的块的 CBC-MAC 的计算过程![https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5](https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5)：

![https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png)

# 漏洞

使用 CBC-MAC 时通常使用的**初始化向量为 0**。\
这是一个问题，因为独立的 2 个已知消息（`m1` 和 `m2`）将生成 2 个签名（`s1` 和 `s2`）。因此：

* `E(m1 XOR 0) = s1`
* `E(m2 XOR 0) = s2`

然后，由 m1 和 m2 连接而成的消息（m3）将生成 2 个签名（s31 和 s32）：

* `E(m1 XOR 0) = s31 = s1`
* `E(m2 XOR s1) = s32`

**这是可以在不知道加密密钥的情况下计算的。**

想象一下，您正在以**8字节**块加密名称**Administrator**：

* `Administ`
* `rator\00\00\00`

您可以创建一个名为**Administ**（m1）的用户名并检索签名（s1）。\
然后，您可以创建一个用户名，称为`rator\00\00\00 XOR s1`的结果。这将生成`E(m2 XOR s1 XOR 0)`，即 s32。\
现在，您可以使用 s32 作为完整名称**Administrator**的签名。

### 总结

1. 获取用户名**Administ**（m1）的签名，即 s1
2. 获取用户名**rator\x00\x00\x00 XOR s1 XOR 0**的签名为 s32**。**
3. 将 cookie 设置为 s32，它将成为用户**Administrator**的有效 cookie。

# 攻击控制 IV

如果您可以控制使用的 IV，攻击可能会变得非常容易。\
如果 cookie 只是加密的用户名，要冒充用户"**administrator**"，您可以创建用户"**Administrator**"并获取其 cookie。\
现在，如果您可以控制 IV，您可以更改 IV 的第一个字节，使得**IV\[0] XOR "A" == IV'\[0] XOR "a"**，并重新生成用户**Administrator**的 cookie。这个 cookie 将有效地**冒充**初始**IV**下的用户**administrator**。

## 参考

更多信息请参阅[https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)


{% hint style="success" %}
学习并练习AWS Hacking：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习并练习GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 检查[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
