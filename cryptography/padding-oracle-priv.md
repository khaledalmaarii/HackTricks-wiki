<details>

<summary><strong>从零到英雄学习AWS黑客攻击</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**上关注我。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>


# CBC - 密码块链接

在CBC模式中，**前一个加密块被用作IV**与下一个块进行XOR操作：

![CBC encryption](https://defuse.ca/images/cbc\_encryption.png)

要解密CBC，需要执行**相反的** **操作**：

![CBC decryption](https://defuse.ca/images/cbc\_decryption.png)

注意需要使用一个**加密** **密钥**和一个**IV**。

# 消息填充

由于加密是在**固定** **大小** **块**中执行的，通常需要在**最后** **块**中添加**填充**以补全其长度。\
通常使用**PKCS7**，它会生成一个填充，**重复**所需**字节数**以**完成**块。例如，如果最后一个块缺少3个字节，填充将是`\x03\x03\x03`。

让我们看看更多例子，这里有**2个长度为8字节的块**：

| 字节#0 | 字节#1 | 字节#2 | 字节#3 | 字节#4 | 字节#5 | 字节#6 | 字节#7 | 字节#0  | 字节#1  | 字节#2  | 字节#3  | 字节#4  | 字节#5  | 字节#6  | 字节#7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

注意在最后一个例子中，**最后一个块已满，所以又生成了一个只有填充的块**。

# 填充预言机

当应用程序解密加密数据时，它首先会解密数据；然后它会移除填充。在清理填充的过程中，如果一个**无效的填充触发了可检测的行为**，你就有了一个**填充预言机漏洞**。可检测的行为可以是一个**错误**，一个**缺少结果**，或者一个**响应较慢**。

如果你检测到这种行为，你可以**解密加密数据**，甚至**加密任何明文**。

## 如何利用

你可以使用[https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster)来利用这种漏洞，或者只需
```
sudo apt-get install padbuster
```
为了测试网站的cookie是否存在漏洞，你可以尝试：
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**编码 0** 表示使用了 **base64**（但还有其他可用的编码，查看帮助菜单了解详情）。

你还可以**利用这个漏洞来加密新数据。例如，假设 cookie 的内容是“**_**user=MyUsername**_**”，那么你可以将其更改为“\_user=administrator\_”以在应用程序内提升权限。你也可以使用 `paduster` 并指定 -plaintext** 参数来实现这一点：
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
如果网站存在漏洞，`padbuster` 将自动尝试找出填充错误发生的时刻，但你也可以使用 **-error** 参数来指示错误信息。
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
## 理论

**总结**，您可以通过猜测可以用来创建所有**不同填充**的正确值来开始解密加密数据。然后，填充oracle攻击将通过猜测哪个是正确的值来开始从末尾到开头解密字节，**创建1、2、3等填充**。

![](<../.gitbook/assets/image (629) (1) (1).png>)

假设您有一些加密文本，它占用**2个块**，由**E0到E15**的字节组成。\
为了**解密**最**后一个块**（**E8**到**E15**），整个块通过“块密码解密”生成**中间字节I0到I15**。\
最后，每个中间字节与前一个加密字节（E0到E7）进行**XOR**运算。所以：

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

现在，可以**修改`E7`直到`C15`为`0x01`**，这也将是一个正确的填充。所以，在这种情况下：`\x01 = I15 ^ E'7`

因此，找到E'7，就**可以计算I15**：`I15 = 0x01 ^ E'7`

这允许我们**计算C15**：`C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

知道了**C15**，现在可以**计算C14**，但这次暴力破解填充`\x02\x02`。

这次BF与之前一样复杂，因为可以计算出`E''15`的值为0x02：`E''7 = \x02 ^ I15`，所以只需要找到生成**`C14`等于`0x02`**的**`E'14`**。\
然后，执行相同的步骤来解密C14：**`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**按照这个链条继续，直到解密整个加密文本。**

## 漏洞检测

注册一个账户并使用这个账户登录。\
如果您**多次登录**并且总是得到**相同的cookie**，应用程序中可能**有些问题**。**每次登录时返回的cookie应该是唯一的**。如果cookie**总是**相**同**，它可能总是有效的，并且**没有办法使其失效**。

现在，如果您尝试**修改**这个**cookie**，您会看到应用程序返回一个**错误**。\
但是如果您使用padbuster（例如）暴力破解填充，您可以得到另一个对不同用户有效的cookie。这种情况很可能容易受到padbuster的攻击。

# 参考资料

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)


<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
