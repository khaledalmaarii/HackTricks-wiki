# 加密/压缩算法

## 加密/压缩算法

{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}

## 识别算法

如果你在代码中发现 **使用了右移和左移、异或和多个算术操作**，那么它很可能是 **加密算法** 的实现。这里将展示一些 **识别所使用算法的方法，而无需逐步反向工程**。

### API 函数

**CryptDeriveKey**

如果使用了此函数，可以通过检查第二个参数的值来找到 **所使用的算法**：

![](<../../.gitbook/assets/image (375) (1) (1) (1) (1).png>)

在这里查看可能的算法及其分配值的表格：[https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

压缩和解压缩给定的数据缓冲区。

**CryptAcquireContext**

来自 [文档](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta)：**CryptAcquireContext** 函数用于获取特定加密服务提供程序 (CSP) 中特定密钥容器的句柄。**此返回的句柄用于调用使用所选 CSP 的 CryptoAPI** 函数。

**CryptCreateHash**

初始化数据流的哈希。如果使用了此函数，可以通过检查第二个参数的值来找到 **所使用的算法**：

![](<../../.gitbook/assets/image (376).png>)

\
在这里查看可能的算法及其分配值的表格：[https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### 代码常量

有时，由于需要使用特殊且唯一的值，识别算法非常简单。

![](<../../.gitbook/assets/image (370).png>)

如果你在 Google 中搜索第一个常量，这就是你得到的结果：

![](<../../.gitbook/assets/image (371).png>)

因此，你可以假设反编译的函数是 **sha256 计算器**。\
你可以搜索其他常量，可能会得到相同的结果。

### 数据信息

如果代码没有任何显著的常量，它可能在 **加载 .data 段中的信息**。\
你可以访问该数据，**将第一个 dword 分组**，并像我们在前面的部分那样在 Google 中搜索：

![](<../../.gitbook/assets/image (372).png>)

在这种情况下，如果你搜索 **0xA56363C6**，你会发现它与 **AES 算法的表** 相关。

## RC4 **(对称加密)**

### 特点

它由三个主要部分组成：

* **初始化阶段/**：创建一个 **从 0x00 到 0xFF 的值表**（总共 256 字节，0x100）。这个表通常称为 **替代盒**（或 SBox）。
* **打乱阶段**：将 **循环遍历之前创建的表**（0x100 次迭代的循环），用 **半随机** 字节修改每个值。为了创建这些半随机字节，使用 RC4 **密钥**。RC4 **密钥** 的长度可以 **在 1 到 256 字节之间**，但通常建议长度超过 5 字节。通常，RC4 密钥为 16 字节。
* **异或阶段**：最后，明文或密文与 **之前创建的值进行异或**。加密和解密的函数是相同的。为此，将对创建的 256 字节进行循环，循环次数根据需要而定。通常，在反编译的代码中可以通过 **%256（模 256）** 识别。

{% hint style="info" %}
**为了在反汇编/反编译代码中识别 RC4，你可以检查两个大小为 0x100 的循环（使用密钥），然后将输入数据与之前在两个循环中创建的 256 个值进行异或，可能使用 %256（模 256）**
{% endhint %}

### **初始化阶段/替代盒：**（注意用作计数器的数字 256 以及在 256 个字符的每个位置写入 0 的方式）

![](<../../.gitbook/assets/image (377).png>)

### **打乱阶段：**

![](<../../.gitbook/assets/image (378).png>)

### **异或阶段：**

![](<../../.gitbook/assets/image (379).png>)

## **AES (对称加密)**

### **特点**

* 使用 **替代盒和查找表**
* 由于使用特定查找表值（常量），可以 **区分 AES**。_注意 **常量** 可以 **存储** 在二进制中 **或动态创建**。_
* **加密密钥** 必须 **可被 16 整除**（通常为 32B），并且通常使用 16B 的 **IV**。

### SBox 常量

![](<../../.gitbook/assets/image (380).png>)

## Serpent **(对称加密)**

### 特点

* 很少发现某些恶意软件使用它，但有一些例子（Ursnif）
* 根据其长度（极长的函数）简单判断算法是否为 Serpent

### 识别

在下图中注意常量 **0x9E3779B9** 的使用（注意该常量也被其他加密算法如 **TEA** -微型加密算法使用）。\
还要注意 **循环的大小**（**132**）和 **反汇编** 指令中的 **异或操作** 数量以及 **代码** 示例：

![](<../../.gitbook/assets/image (381).png>)

如前所述，这段代码可以在任何反编译器中可视化为 **非常长的函数**，因为其中 **没有跳转**。反编译的代码可能看起来如下：

![](<../../.gitbook/assets/image (382).png>)

因此，可以通过检查 **魔法数字** 和 **初始异或** 来识别此算法，看到 **非常长的函数** 并 **比较** 一些 **指令** 与 **实现**（如左移 7 和左旋转 22）。

## RSA **(非对称加密)**

### 特点

* 比对称算法更复杂
* 没有常量！（自定义实现难以确定）
* KANAL（加密分析器）未能显示 RSA 的提示，因为它依赖于常量。

### 通过比较识别

![](<../../.gitbook/assets/image (383).png>)

* 在第 11 行（左）有一个 `+7) >> 3`，与第 35 行（右）相同：`+7) / 8`
* 第 12 行（左）检查 `modulus_len < 0x040`，而第 36 行（右）检查 `inputLen+11 > modulusLen`

## MD5 & SHA（哈希）

### 特点

* 3 个函数：Init、Update、Final
* 初始化函数相似

### 识别

**Init**

你可以通过检查常量来识别它们。注意 sha\_init 有一个 MD5 没有的常量：

![](<../../.gitbook/assets/image (385).png>)

**MD5 Transform**

注意使用了更多常量

![](<../../.gitbook/assets/image (253) (1) (1) (1).png>)

## CRC（哈希）

* 更小且更高效，因为它的功能是查找数据中的意外更改
* 使用查找表（因此你可以识别常量）

### 识别

检查 **查找表常量**：

![](<../../.gitbook/assets/image (387).png>)

一个 CRC 哈希算法看起来像：

![](<../../.gitbook/assets/image (386).png>)

## APLib（压缩）

### 特点

* 不可识别的常量
* 你可以尝试用 Python 编写算法并在线搜索类似的东西

### 识别

图表相当大：

![](<../../.gitbook/assets/image (207) (2) (1).png>)

检查 **3 个比较以识别它**：

![](<../../.gitbook/assets/image (384).png>)

{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}
