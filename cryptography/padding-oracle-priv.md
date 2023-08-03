<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[NFT收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或者 [**Telegram群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud仓库](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>


# CBC - 密码块链接

在CBC模式下，**前一个加密块被用作初始化向量（IV）**与下一个块进行异或运算：

![CBC加密](https://defuse.ca/images/cbc\_encryption.png)

要解密CBC，需要进行**相反的操作**：

![CBC解密](https://defuse.ca/images/cbc\_decryption.png)

注意需要使用**加密密钥**和**初始化向量（IV）**。

# 消息填充

由于加密是以**固定大小的块**进行的，通常需要在**最后一个块**中进行填充以完成其长度。\
通常使用**PKCS7**填充，它生成一个重复**所需字节数**以**完成**块的填充。例如，如果最后一个块缺少3个字节，填充将为`\x03\x03\x03`。

让我们看一些使用**长度为8字节的2个块**的更多示例：

| 字节 #0 | 字节 #1 | 字节 #2 | 字节 #3 | 字节 #4 | 字节 #5 | 字节 #6 | 字节 #7 | 字节 #0  | 字节 #1  | 字节 #2  | 字节 #3  | 字节 #4  | 字节 #5  | 字节 #6  | 字节 #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

注意在最后一个示例中，**最后一个块已满，因此生成了另一个仅包含填充的块**。

# 填充预言机

当应用程序解密加密数据时，它首先会解密数据，然后会删除填充。在填充清理过程中，如果**无效的填充触发了可检测的行为**，则存在填充预言机漏洞。可检测的行为可以是**错误**、**缺少结果**或**响应变慢**。

如果检测到这种行为，可以**解密加密数据**，甚至**加密任何明文**。

## 如何利用

你可以使用[https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster)来利用这种漏洞，或者只需执行以下操作：
```
sudo apt-get install padbuster
```
为了测试一个网站的cookie是否存在漏洞，你可以尝试以下方法：
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**编码 0** 表示使用 **base64**（但也可以使用其他编码，请查看帮助菜单）。

您还可以**利用此漏洞加密新数据**。例如，假设 cookie 的内容是 "**_**user=MyUsername**_**"，您可以将其更改为 "\_user=administrator\_" 并在应用程序中提升权限。您也可以使用 `paduster` 并指定 `-plaintext**` 参数来实现：
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
如果网站存在漏洞，`padbuster`将自动尝试查找填充错误发生的时机，但您也可以使用**-error**参数指定错误消息。
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
## 理论

简而言之，您可以通过猜测可以用来创建所有不同填充的正确值来开始解密加密数据。然后，填充预言攻击将从末尾开始解密字节，猜测哪个值将是创建填充为1、2、3等的正确值。

![](<../.gitbook/assets/image (629) (1) (1).png>)

假设您有一些加密文本，占用由字节E0到E15形成的2个块。为了解密最后一个块（E8到E15），整个块通过“块密码解密”生成中间字节I0到I15。最后，每个中间字节与前面的加密字节（E0到E7）进行异或运算。所以：

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

现在，可以修改`E7`直到`C15`为`0x01`，这也将是一个正确的填充。所以，在这种情况下：`\x01 = I15 ^ E'7`

因此，找到E'7，就可以计算I15：`I15 = 0x01 ^ E'7`

这使我们能够计算C15：`C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

知道了C15，现在可以计算C14，但这次是通过强制填充`\x02\x02`来进行的。

这个BF与之前的BF一样复杂，因为可以计算出值为0x02的`E''15`：`E''7 = \x02 ^ I15`，所以只需要找到生成`C14`等于`0x02`的`E'14`。

然后，按照相同的步骤解密C14：`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`

**按照这个链条解密整个加密文本。**

## 漏洞的检测

注册一个帐户并使用该帐户登录。\
如果您多次登录并始终获得相同的cookie，那么应用程序可能存在问题。每次登录时，返回的cookie应该是唯一的。如果cookie始终相同，它可能始终有效，没有任何方法可以使其无效。

现在，如果您尝试修改cookie，您会发现应用程序会返回错误。\
但是，如果您使用padbuster等工具进行填充BF，您可以获得另一个适用于不同用户的有效cookie。这种情况很可能容易受到padbuster的攻击。

# 参考资料

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 您在**网络安全公司**工作吗？您想在HackTricks中看到您的公司广告吗？或者您想获得PEASS的最新版本或下载PDF格式的HackTricks吗？请查看[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks衣物**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>
