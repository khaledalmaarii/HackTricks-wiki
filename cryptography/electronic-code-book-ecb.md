<details>

<summary><strong>零基础学习AWS黑客攻击直至成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您希望在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


# ECB

(ECB) 电子密码本 - 对称加密方案，它将**明文的每个块**替换为**密文块**。这是**最简单**的加密方案。主要思想是将明文**分割**成**N位的块**（取决于输入数据块的大小，加密算法），然后使用唯一的密钥对每个明文块进行加密（解密）。

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

使用ECB有多个安全隐患：

* **可以移除加密消息中的块**
* **可以在加密消息中移动块**

# 检测漏洞

想象一下，您多次登录一个应用程序，**总是得到相同的cookie**。这是因为应用程序的cookie是**`<用户名>|<密码>`**。\
然后，您生成了两个新用户，他们都有**相同的长密码**和**几乎相同的**用户名。\
您发现，**8B的块**中，两个用户的**信息相同的部分**是**相等的**。然后，您猜想这可能是因为**正在使用ECB**。

就像下面的例子。观察这**两个解码的cookie**如何多次有相同的块**`\x23U\xE45K\xCB\x21\xC8`**
```
\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9

\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9
```
这是因为**这些cookie中的用户名和密码包含了好几次字母“a”**（例如）。**不同的区块**是那些包含了**至少1个不同字符**的区块（可能是分隔符“|”或用户名中的一些必要差异）。

现在，攻击者只需要发现格式是`<用户名><分隔符><密码>`还是`<密码><分隔符><用户名>`。为此，他可以**生成几个用户名**，用**相似且长的用户名和密码**，直到他找到格式和分隔符的长度：

| 用户名长度: | 密码长度: | 用户名+密码长度: | Cookie的长度（解码后）: |
| ------------ | ---------- | ----------------- | ------------------------- |
| 2            | 2          | 4                 | 8                         |
| 3            | 3          | 6                 | 8                         |
| 3            | 4          | 7                 | 8                         |
| 4            | 4          | 8                 | 16                        |
| 7            | 7          | 14                | 16                        |

# 利用漏洞

## 移除整个区块

知道了cookie的格式（`<用户名>|<密码>`），为了冒充用户名`admin`，创建一个叫做`aaaaaaaaadmin`的新用户，获取并解码cookie：
```
\x23U\xE45K\xCB\x21\xC8\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
我们可以看到之前使用只包含 `a` 的用户名创建的模式 `\x23U\xE45K\xCB\x21\xC8`。\
然后，你可以移除前8字节的数据块，你将得到用户名为 `admin` 的有效cookie：
```
\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
## 移动块

在许多数据库中，搜索 `WHERE username='admin';` 或者 `WHERE username='admin    ';` _(注意额外的空格)_ 是相同的。

因此，另一种冒充用户 `admin` 的方法是：

* 生成一个用户名，使得：`len(<username>) + len(<delimiter) % len(block)`。如果块大小为 `8B`，你可以生成一个叫做：`username       ` 的用户名，使用分隔符 `|`，则 `<username><delimiter>` 将生成两个8字节的块。
* 然后，生成一个密码，它将填充一个完整的块数，包含我们想要冒充的用户名和空格，比如：`admin   `

这个用户的cookie将由3个块组成：前两个是用户名+分隔符的块，第三个是密码块（假装是用户名）：`username       |admin   `

**然后，只需将第一个块替换为最后一个块，就可以冒充用户 `admin` 了：`admin          |username`**

# 参考资料

* [http://cryptowiki.net/index.php?title=Electronic_Code_Book\_(ECB)](http://cryptowiki.net/index.php?title=Electronic_Code_Book_\(ECB\))


<details>

<summary><strong>从零开始学习AWS黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果你想在 **HackTricks** 中看到你的**公司广告**或者**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现 [**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来**分享你的黑客技巧**。

</details>
