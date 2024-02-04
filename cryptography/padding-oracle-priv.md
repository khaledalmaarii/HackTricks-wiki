<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


# CBC - 密码块链接

在CBC模式中，**前一个加密块被用作IV**与下一个块进行XOR运算：

![CBC加密](https://defuse.ca/images/cbc\_encryption.png)

要解密CBC，需要执行**相反的操作**：

![CBC解密](https://defuse.ca/images/cbc\_decryption.png)

请注意需要使用**加密密钥**和**IV**。

# 消息填充

由于加密是以**固定大小的块**进行的，通常需要在**最后一个块**中进行填充以完成其长度。\
通常使用**PKCS7**，它生成一个填充，重复**所需的字节数**以**完成**该块。例如，如果最后一个块缺少3个字节，填充将是`\x03\x03\x03`。

让我们看看一个**长度为8字节的2个块**的更多示例：

| 字节 #0 | 字节 #1 | 字节 #2 | 字节 #3 | 字节 #4 | 字节 #5 | 字节 #6 | 字节 #7 | 字节 #0  | 字节 #1  | 字节 #2  | 字节 #3  | 字节 #4  | 字节 #5  | 字节 #6  | 字节 #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

请注意，在最后一个示例中，**最后一个块已满，因此另一个仅包含填充的块被生成**。

# 填充Oracle

当应用程序解密加密数据时，它将首先解密数据；然后将删除填充。在清除填充时，如果**无效的填充触发可检测的行为**，则存在**填充Oracle漏洞**。可检测的行为可以是**错误**、**缺少结果**或**响应速度变慢**。

如果检测到这种行为，您可以**解密加密数据**甚至**加密任何明文**。

## 如何利用

您可以使用[https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster)来利用这种漏洞，或者只需执行
```
sudo apt-get install padbuster
```
为了测试网站的 cookie 是否存在漏洞，您可以尝试：
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**编码 0** 意味着使用 **base64**（但其他选项也可用，请查看帮助菜单）。

您还可以**滥用此漏洞来加密新数据。例如，假设 cookie 的内容是 "**_**user=MyUsername**_**"，然后您可以将其更改为 "\_user=administrator\_" 并在应用程序内提升权限。您也可以使用 `paduster` 指定 `-plaintext**` 参数来执行此操作：
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
如果网站存在漏洞，`padbuster`将自动尝试在出现填充错误时找到漏洞，但您也可以使用**-error**参数指定错误消息。
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
## 理论

**总结**：您可以通过猜测可以用来创建所有**不同填充**的正确值来开始解密加密数据。然后，填充预言攻击将从末尾向开头开始解密字节，猜测哪个值将是**创建填充为1、2、3等的正确值**。

![](<../.gitbook/assets/image (629) (1) (1).png>)

假设您有一些加密文本，占据了由**E0到E15**字节组成的**2个块**。\
为了解密**最后一个**块（**E8**到**E15**），整个块通过“块密码解密”生成**中间字节I0到I15**。\
最后，每个中间字节都与先前的加密字节（E0到E7）进行**XOR运算**。因此：

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

现在，可以**修改`E7`直到`C15`为`0x01`**，这也将是一个正确的填充。因此，在这种情况下：`\x01 = I15 ^ E'7`

因此，找到E'7，就可以**计算I15**：`I15 = 0x01 ^ E'7`

这使我们能够**计算C15**：`C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

知道**C15**，现在可以**计算C14**，但这次要用` \x02\x02`来暴力破解填充。

这个BF与前一个一样复杂，因为可以计算出值为0x02的`E''15`：`E''7 = \x02 ^ I15`，所以只需要找到生成**`C14`等于`0x02`**的**`E'14`**。\
然后，执行相同的步骤来解密C14：**`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**按照这个链条继续，直到解密整个加密文本。**

## 漏洞检测

注册一个帐户并使用该帐户登录。\
如果您**多次登录**并始终获得**相同的cookie**，则应用程序可能存在**问题**。每次登录时发送回的**cookie应该是唯一的**。如果cookie**始终**是**相同的**，它可能始终有效，**无法使其失效**。

现在，如果您尝试**修改**cookie，您会看到应用程序返回一个**错误**。\
但是，如果您使用填充预言（例如使用padbuster）进行BF，您可以获得另一个适用于不同用户的有效cookie。这种情况很可能容易受到padbuster的攻击。

# 参考资料

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)


<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF版HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 发现[**PEASS Family**](https://opensea.io/collection/the-peass-family)，我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**上关注**我们。
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
