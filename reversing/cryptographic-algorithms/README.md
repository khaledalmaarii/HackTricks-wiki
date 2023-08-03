# 密码/压缩算法

## 密码/压缩算法

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在 HackTricks 中看到你的**公司广告**吗？或者你想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass)，或者**关注**我在**推特**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>

## 识别算法

如果你遇到了一个使用**移位操作、异或操作和其他多种算术操作**的代码，很有可能它是一个**密码算法的实现**。下面将展示一些无需逆向每一步就能**识别所使用的算法**的方法。

### API 函数

**CryptDeriveKey**

如果使用了这个函数，你可以通过检查第二个参数的值来找到所使用的**算法**：

![](<../../.gitbook/assets/image (375) (1) (1) (1) (1).png>)

在这里查看可能算法及其分配的值的表格：[https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

压缩和解压给定的数据缓冲区。

**CryptAcquireContext**

**CryptAcquireContext** 函数用于获取特定加密服务提供程序（CSP）中特定密钥容器的句柄。**返回的句柄用于调用使用所选 CSP 的 CryptoAPI 函数**。

**CryptCreateHash**

启动对数据流的哈希计算。如果使用了这个函数，你可以通过检查第二个参数的值来找到所使用的**算法**：

![](<../../.gitbook/assets/image (376).png>)

在这里查看可能算法及其分配的值的表格：[https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### 代码常量

有时候，通过需要使用特殊且唯一的值来识别算法是非常容易的。

![](<../../.gitbook/assets/image (370).png>)

如果你在 Google 中搜索第一个常量，你会得到以下结果：

![](<../../.gitbook/assets/image (371).png>)

因此，你可以假设反编译的函数是一个**sha256 计算器**。\
你可以搜索其他任何常量，你可能会得到（大概）相同的结果。

### 数据信息

如果代码中没有任何重要的常量，它可能是从**.data 部分加载信息**。\
你可以访问该数据，**将第一个 dword 分组**，并像前面的部分一样在 Google 中搜索它：

![](<../../.gitbook/assets/image (372).png>)

在这种情况下，如果你搜索**0xA56363C6**，你会发现它与**AES 算法的表格**相关。

## RC4 **（对称加密）**

### 特征

它由 3 个主要部分组成：

* **初始化阶段/**：创建一个从 0x00 到 0xFF 的值的表格（总共 256 字节，0x100）。这个表格通常被称为**替代盒**（或 SBox）。
* **混淆阶段**：将在之前创建的表格上进行循环（再次循环 0x100 次），使用**半随机**字节修改每个值。为了创建这些半随机字节，使用了 RC4 **密钥**。RC4 密钥的长度可以在 1 到 256 字节之间，但通常建议长度超过 5 字节。通常，RC4 密钥的长度为 16 字节。
* **XOR 阶段**：最后，明文或密文与之前创建的值进行**异或**。加密和解密的函数是相同的。为此，将根据需要执行**对创建的 256 字节的循环**。在反编译的代码中，通常会使用**%256（mod 256）**来识别这一点。

{% hint style="info" %}
**为了在反汇编/反编译代码中识别 RC4，你可以检查大小为 0x100 的 2 个循环（使用密钥），然后将输入数据与之前在 2 个循环中创建的 256 个值进行异或，可能使用了 %256（mod 256）**
{% endhint %}
### **初始化阶段/替代盒：**（注意计数器使用的数字256以及如何在256个字符的每个位置上写入0）

![](<../../.gitbook/assets/image (377).png>)

### **混淆阶段：**

![](<../../.gitbook/assets/image (378).png>)

### **XOR阶段：**

![](<../../.gitbook/assets/image (379).png>)

## **AES（对称加密）**

### **特征**

* 使用**替代盒和查找表**
* 可以通过使用特定查找表值（常量）来区分AES。_注意，**常量**可以**存储**在二进制中，也可以**动态创建**。_
* **加密密钥**必须是**16的倍数**（通常为32B），通常使用16B的**IV**。

### SBox常量

![](<../../.gitbook/assets/image (380).png>)

## Serpent（对称加密）

### 特征

* 很少发现使用它的恶意软件，但有一些例子（Ursnif）
* 可以根据其长度（非常长的函数）确定算法是否为Serpent。

### 识别

在下图中，请注意使用了常量**0x9E3779B9**（注意，此常量也被其他加密算法如**TEA**（Tiny Encryption Algorithm）使用）。\
还请注意**循环的大小**（**132**）以及**反汇编指令**和**代码示例**中的**XOR操作的数量**：

![](<../../.gitbook/assets/image (381).png>)

正如之前提到的，可以在任何反编译器中将此代码视为**非常长的函数**，因为其中**没有跳转**。反编译后的代码可能如下所示：

![](<../../.gitbook/assets/image (382).png>)

因此，可以通过检查**魔术数字**和**初始XOR**，查看**非常长的函数**并将其**与实现进行比较**（如左移7位和左旋转22位）来识别此算法。

## RSA（非对称加密）

### 特征

* 比对称算法更复杂
* 没有常量！（难以确定自定义实现）

### 通过比较进行识别

![](<../../.gitbook/assets/image (383).png>)

* 在第11行（左侧）有一个`+7) >> 3`，与第35行（右侧）的`+7) / 8`相同。
* 第12行（左侧）检查`modulus_len < 0x040`，而第36行（右侧）检查`inputLen+11 > modulusLen`。

## MD5和SHA（哈希）

### 特征

* 3个函数：Init、Update、Final
* 初始化函数相似

### 识别

**Init**

可以通过检查常量来识别它们。请注意，sha_init有一个MD5没有的常量：

![](<../../.gitbook/assets/image (385).png>)

**MD5变换**

请注意使用了更多的常量

![](<../../.gitbook/assets/image (253) (1) (1) (1).png>)

## CRC（哈希）

* 较小且更高效，其功能是查找数据中的意外更改
* 使用查找表（因此可以识别常量）

### 识别

检查**查找表常量**：

![](<../../.gitbook/assets/image (387).png>)

CRC哈希算法如下所示：

![](<../../.gitbook/assets/image (386).png>)

## APLib（压缩）

### 特征

* 无法识别的常量
* 可以尝试在Python中编写算法并在网上搜索类似的内容

### 识别

图形非常大：

![](<../../.gitbook/assets/image (207) (2) (1).png>)

检查**3个比较以识别它**：

![](<../../.gitbook/assets/image (384).png>)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在HackTricks中看到您的公司广告吗？或者您想获得PEASS的**最新版本或下载PDF格式的HackTricks**吗？请查看[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品The PEASS Family](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks衣物**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>
