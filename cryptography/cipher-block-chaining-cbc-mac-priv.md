<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者想要获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFT收藏品**](https://opensea.io/collection/the-peass-family)——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>


# CBC

如果**cookie**只是**用户名**（或cookie的第一部分是用户名），而你想要冒充用户名“**admin**”。那么，你可以创建用户名**"bdmin"**并**暴力破解**cookie的**第一个字节**。

# CBC-MAC

在密码学中，**密码块链接消息认证码**（**CBC-MAC**）是一种从块密码构造消息认证码的技术。消息使用某种块密码算法在CBC模式下进行加密，以创建一个**块链，使得每个块都依赖于前一个块的正确加密**。这种相互依赖性确保了对任何明文位的更改都会导致最终加密块以无法预测或抵消的方式发生变化，而不知道块密码的密钥。

要计算消息m的CBC-MAC，可以使用零初始化向量在CBC模式下对m进行加密，并保留最后一个块。下图概述了使用秘密密钥k和块密码E计算由块组成的消息的CBC-MAC![m\_{1}\\|m\_{2}\\|\cdots \\|m\_{x}](https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5)的计算过程：

![CBC-MAC structure (en).svg](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png)

# 漏洞

在CBC-MAC中，通常使用的**初始化向量（IV）为0**。\
这是一个问题，因为两个已知的消息（`m1`和`m2`）独立地将生成两个签名（`s1`和`s2`）。因此：

* `E(m1 XOR 0) = s1`
* `E(m2 XOR 0) = s2`

然后，由m1和m2连接而成的消息（m3）将生成两个签名（s31和s32）：

* `E(m1 XOR 0) = s31 = s1`
* `E(m2 XOR s1) = s32`

**这是可以在不知道加密密钥的情况下计算出来的。**

假设你正在以**8字节**块加密名称**Administrator**：

* `Administ`
* `rator\00\00\00`

你可以创建一个名为**Administ**（m1）的用户名并获取其签名（s1）。\
然后，你可以创建一个名为`rator\00\00\00 XOR s1`的用户名。这将生成`E(m2 XOR s1 XOR 0)`，即s32。\
现在，你可以使用s32作为完整名称**Administrator**的签名。

### 总结

1. 获取用户名**Administ**（m1）的签名，即s1
2. 获取用户名**rator\x00\x00\x00 XOR s1 XOR 0**的签名，即s32**.**
3. 将cookie设置为s32，它将成为用户**Administrator**的有效cookie。

# 攻击控制IV

如果你可以控制使用的IV，攻击将变得非常容易。\
如果cookie只是加密的用户名，要冒充用户“**administrator**”，你可以创建用户“**Administrator**”，并获得它的cookie。\
现在，如果你可以控制IV，你可以更改IV的第一个字节，使得**IV\[0] XOR "A" == IV'\[0] XOR "a"**，并重新生成用户**Administrator**的cookie。这个cookie将有效地**冒充**初始**IV**下的用户**administrator**。

# 参考资料

更多信息请参阅[https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者想要获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFT收藏品**](https://opensea.io/collection/the-peass-family)——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
- **加入** [💬](https://emojipedia.org/speech-balloon/) [Discord 群组](https://discord.gg/hRep4RUj7f) 或 [Telegram 群组](https://t.me/peass) 或 **关注**我的 **Twitter** [🐦](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[@carlospolopm](https://twitter.com/hacktricks_live)**。**

- **通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来分享你的黑客技巧**。

</details>
