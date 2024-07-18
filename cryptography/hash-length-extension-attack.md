{% hint style="success" %}
学习并练习AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习并练习GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 检查 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}


# 攻击摘要

想象一个服务器正在通过将一个**秘密**附加到一些已知明文数据上然后对该数据进行哈希来**签署**一些**数据**。如果你知道：

* **秘密的长度**（这也可以从给定长度范围内暴力破解）
* **明文数据**
* **算法（及其容易受到此攻击）**
* **填充是已知的**
* 通常会使用默认填充，因此如果满足其他 3 个要求，这也是可以的
* 填充取决于秘密+数据的长度，这就是为什么需要秘密的长度

那么，对于**攻击者**来说，就有可能**附加数据**并为**先前数据+附加数据**生成有效的**签名**。

## 如何？

基本上，易受攻击的算法首先通过**哈希一个数据块**生成哈希，然后，从**先前**创建的**哈希**（状态）开始，它们**添加下一个数据块**并**对其进行哈希**。

然后，想象秘密是"secret"，数据是"data"，"secretdata"的 MD5 是 6036708eba0d11f6ef52ad44e8b74d5b。\
如果攻击者想要附加字符串"append"，他可以：

* 生成 64 个"A"的 MD5
* 将先前初始化的哈希状态更改为 6036708eba0d11f6ef52ad44e8b74d5b
* 附加字符串"append"
* 完成哈希，生成的哈希将是一个**对于"secret" + "data" + "填充" + "append"**有效的哈希

## **工具**

{% embed url="https://github.com/iagox86/hash_extender" %}

## 参考资料

你可以在 [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks) 中找到对这种攻击的很好解释。


{% hint style="success" %}
学习并练习AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习并练习GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 检查 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
