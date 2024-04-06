<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


# ECB

(ECB) 电子密码本 - 对称加密方案，**将明文的每个块**替换为**密文块**。这是**最简单**的加密方案。其主要思想是将明文分割成**N位的块**（取决于输入数据块的大小、加密算法），然后使用唯一密钥加密（解密）每个明文块。

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

使用ECB存在多个安全问题：

* **加密消息中的块可以被移除**
* **加密消息中的块可以被移动**

# 漏洞的检测

想象一下，您多次登录一个应用程序，**总是得到相同的cookie**。这是因为应用程序的cookie是**`<用户名>|<密码>`**。\
然后，您创建两个新用户，两者都具有**相同的长密码**和**几乎相同的用户名**。\
您发现**两个用户信息的8字节块**是**相同的**。然后，您想象这可能是因为正在使用**ECB**。

就像以下示例中一样。观察这**两个解码的cookie**中多次出现的块**`\x23U\xE45K\xCB\x21\xC8`**。
```
\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9

\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9
```
这是因为这些 cookie 的**用户名和密码中包含多次字母"a"**（例如）。**不同的区块**是包含**至少 1 个不同字符**的区块（也许是分隔符"|"或用户名中的某些必要差异）。

现在，攻击者只需发现格式是`<用户名><分隔符><密码>`还是`<密码><分隔符><用户名>`。为了做到这一点，他只需**生成几个相似且较长的用户名和密码**，直到找到格式和分隔符的长度：

| 用户名长度： | 密码长度： | 用户名+密码长度： | 解码后的 Cookie 长度： |
| ------------ | ---------- | ---------------- | ----------------------- |
| 2            | 2          | 4                | 8                       |
| 3            | 3          | 6                | 8                       |
| 3            | 4          | 7                | 8                       |
| 4            | 4          | 8                | 16                      |
| 7            | 7          | 14               | 16                      |

# 漏洞的利用

## 移除整个区块

了解 cookie 的格式（`<用户名>|<密码>`），为了冒充用户名`admin`，创建一个名为`aaaaaaaaadmin`的新用户，获取 cookie 并解码：
```
\x23U\xE45K\xCB\x21\xC8\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
我们可以看到先前使用只包含`a`的用户名创建的模式`\x23U\xE45K\xCB\x21\xC8`。\
然后，您可以移除前8B块，就可以得到用户名为`admin`的有效cookie：
```
\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
## 移动块

在许多数据库中，搜索`WHERE username='admin';`和`WHERE username='admin    ';`（注意额外的空格）是相同的。

因此，另一种冒充用户`admin`的方法是：

- 生成一个用户名：`len(<username>) + len(<delimiter) % len(block)`。使用`8B`的块大小，您可以生成名为`username       `的用户名，使用分隔符`|`，块`<username><delimiter>`将生成2个8B块。
- 然后，生成一个密码，填充包含我们想要冒充的用户名和空格的确切块数，例如：`admin   `。

该用户的cookie将由3个块组成：前两个是用户名+分隔符的块，第三个是密码的块（伪装成用户名）：`username       |admin   `。

**然后，只需用最后一个块替换第一个块，就可以冒充用户`admin`：`admin          |username`**

# 参考

* [http://cryptowiki.net/index.php?title=Electronic_Code_Book\_(ECB)](http://cryptowiki.net/index.php?title=Electronic_Code_Book_\(ECB\))
