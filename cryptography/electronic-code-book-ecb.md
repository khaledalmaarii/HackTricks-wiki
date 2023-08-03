<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>


# ECB

(ECB) 电子密码本 - 对称加密方案，它通过**将明文的每个块**替换为**密文的块**来进行加密。这是**最简单**的加密方案。主要思想是将明文分成**N位的块**（取决于输入数据块的大小、加密算法），然后使用唯一的密钥对每个明文块进行加密（解密）。

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

使用ECB有多个安全隐患：

* **加密消息的块可以被删除**
* **加密消息的块可以被移动**

# 漏洞的检测

假设你多次登录一个应用程序，**每次都得到相同的cookie**。这是因为应用程序的cookie是**`<用户名>|<密码>`**。\
然后，你生成了两个新用户，他们的**密码相同且几乎相同的用户名**。\
你发现**两个用户信息相同的8字节块**是**相等的**。于是，你猜测可能是因为**使用了ECB**。

就像下面的例子一样。观察这**2个解码的cookie**中多次出现的块**`\x23U\xE45K\xCB\x21\xC8`**
```
\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9

\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9
```
这是因为这些cookie的**用户名和密码中多次包含字母"a"**（例如）。**不同的块**是包含**至少一个不同字符**的块（可能是分隔符"|"或用户名中的某些必要差异）。

现在，攻击者只需要发现格式是`<用户名><分隔符><密码>`还是`<密码><分隔符><用户名>`。为了做到这一点，他可以**生成几个相似且较长的用户名和密码**，直到找到格式和分隔符的长度：

| 用户名长度 | 密码长度 | 用户名+密码长度 | 解码后的Cookie长度 |
| ---------- | -------- | -------------- | ------------------ |
| 2          | 2        | 4              | 8                  |
| 3          | 3        | 6              | 8                  |
| 3          | 4        | 7              | 8                  |
| 4          | 4        | 8              | 16                 |
| 7          | 7        | 14             | 16                 |

# 漏洞的利用

## 删除整个块

知道cookie的格式（`<用户名>|<密码>`）后，为了冒充用户名`admin`，创建一个名为`aaaaaaaaadmin`的新用户，获取并解码cookie：
```
\x23U\xE45K\xCB\x21\xC8\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
我们可以看到之前使用只包含`a`的用户名创建的模式`\x23U\xE45K\xCB\x21\xC8`。
然后，您可以删除前8B的块，这样您就可以得到一个有效的用于用户名`admin`的cookie：
```
\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
## 移动块

在许多数据库中，搜索`WHERE username='admin';`和`WHERE username='admin    ';`（注意额外的空格）是相同的。

因此，模拟用户`admin`的另一种方法是：

* 生成一个用户名：`len(<username>) + len(<delimiter) % len(block)`。使用块大小为`8B`，可以生成名为`username       `的用户名，使用分隔符`|`，块`<username><delimiter>`将生成2个8B的块。
* 然后，生成一个密码，该密码将填充包含我们想要模拟的用户名和空格的确切块数，例如：`admin   `

该用户的cookie将由3个块组成：前两个块是用户名+分隔符的块，第三个块是密码（伪装成用户名）：`username       |admin   `

**然后，只需将第一个块替换为最后一个块，就可以模拟用户`admin`：`admin          |username`**

# 参考资料

* [http://cryptowiki.net/index.php?title=Electronic_Code_Book\_(ECB)](http://cryptowiki.net/index.php?title=Electronic_Code_Book_\(ECB\))


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在HackTricks中**为你的公司做广告**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks的衣物**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>
