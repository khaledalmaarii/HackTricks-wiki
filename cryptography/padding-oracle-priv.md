{% hint style="success" %}
学习并练习AWS Hacking：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习并练习GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 检查[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或 **关注**我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}


# CBC - 密码块链接

在 CBC 模式中，**前一个加密块被用作 IV** 与下一个块进行异或运算：

![https://defuse.ca/images/cbc\_encryption.png](https://defuse.ca/images/cbc\_encryption.png)

要解密 CBC，需要执行**相反的操作**：

![https://defuse.ca/images/cbc\_decryption.png](https://defuse.ca/images/cbc\_decryption.png)

请注意，需要使用一个**加密密钥**和一个**IV**。

# 消息填充

由于加密是以**固定大小的块**进行的，通常需要在**最后一个块**中进行填充以完成其长度。\
通常使用 **PKCS7**，它生成一个填充，**重复**所需的**字节数**以**完成**块。例如，如果最后一个块缺少 3 个字节，填充将是 `\x03\x03\x03`。

让我们看看一个**长度为 8 字节的 2 个块**的更多示例：

| byte #0 | byte #1 | byte #2 | byte #3 | byte #4 | byte #5 | byte #6 | byte #7 | byte #0  | byte #1  | byte #2  | byte #3  | byte #4  | byte #5  | byte #6  | byte #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

请注意，在最后一个示例中，**最后一个块已满，因此另一个仅带填充的块被生成**。

# 填充 Oracle

当应用程序解密加密数据时，它将首先解密数据；然后将删除填充。在清除填充时，如果**无效的填充触发可检测的行为**，则存在**填充 Oracle 漏洞**。可检测的行为可以是一个**错误**，**缺少结果**或**响应较慢**。

如果检测到这种行为，您可以**解密加密数据**甚至**加密任何明文**。

## 如何利用

您可以使用 [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) 来利用这种漏洞，或者只需执行
```
sudo apt-get install padbuster
```
为了测试一个网站的 cookie 是否存在漏洞，你可以尝试：
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**编码 0** 意味着使用 **base64**（但其他选项也可用，请查看帮助菜单）。

您还可以**滥用此漏洞来加密新数据。例如，假设 cookie 的内容是 "**_**user=MyUsername**_**"，然后您可以将其更改为 "\_user=administrator\_" 并在应用程序内提升权限。您也可以使用 `paduster` 并指定 `-plaintext** 参数来执行此操作：
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
如果网站存在漏洞，`padbuster`将在出现填充错误时自动尝试查找，但您也可以使用**-error**参数指定错误消息。
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
## 理论

**总结**：您可以通过猜测可以用来创建所有**不同填充**的正确值来开始解密加密数据。然后，填充预言攻击将从末尾向开头开始解密字节，猜测哪个值将是**创建填充为1、2、3等的正确值**。

![](<../.gitbook/assets/image (629) (1) (1).png>)

假设您有一些加密文本，占据了由**E0到E15**字节组成的**2个块**。\
为了解密**最后一个**块（**E8**到**E15**），整个块通过“块密码解密”生成**中间字节I0到I15**。\
最后，每个中间字节都与先前加密的字节（E0到E7）进行**XOR运算**。因此：

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

现在，可以**修改`E7`直到`C15`为`0x01`**，这也将是一个正确的填充。因此，在这种情况下：`\x01 = I15 ^ E'7`

因此，找到E'7，就可以**计算I15**：`I15 = 0x01 ^ E'7`

这使我们能够**计算C15**：`C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

知道**C15**，现在可以**计算C14**，但这次是通过暴力破解填充`\x02\x02`。

这个BF与前一个一样复杂，因为可以计算出值为0x02的`E''15`：`E''7 = \x02 ^ I15`，所以只需要找到生成**`C14`等于`0x02`**的**`E'14`**。\
然后，执行相同的步骤来解密C14：**`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**按照这个链条继续，直到解密整个加密文本。**

## 漏洞检测

注册一个帐户并使用该帐户登录。\
如果您**多次登录**并始终获得**相同的cookie**，则应用程序可能存在**问题**。每次登录时发送回的cookie应该是**唯一的**。如果cookie**始终**是**相同的**，那么它可能始终有效，**无法使其失效**。

现在，如果您尝试**修改**cookie，您会看到应用程序返回一个**错误**。\
但是，如果您使用填充预言（例如使用padbuster）进行BF，您将成功获得另一个适用于不同用户的有效cookie。这种情况很可能对padbuster易受攻击。

## 参考

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)
