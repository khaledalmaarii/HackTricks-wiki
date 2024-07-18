# 密码/压缩算法

## 密码/压缩算法

{% hint style="success" %}
学习并练习AWS黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks培训AWS红队专家（ARTE）**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习并练习GCP黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks培训GCP红队专家（GRTE）**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持HackTricks</summary>

* 查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享黑客技巧。

</details>
{% endhint %}

## 识别算法

如果你在代码中**使用移位、异或和多种算术运算**，很可能是**实现了一个密码算法**。这里将展示一些方法来**识别所使用的算法，而无需逆向每一步**。

### API函数

**CryptDeriveKey**

如果使用了这个函数，可以通过检查第二个参数的值来找到**正在使用的算法**：

![](<../../.gitbook/assets/image (156).png>)

在这里查看可能算法及其分配的值的表格：[https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

压缩和解压给定的数据缓冲区。

**CryptAcquireContext**

根据[文档](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta)：**CryptAcquireContext**函数用于获取特定加密服务提供商（CSP）中特定密钥容器的句柄。**返回的句柄用于调用使用所选CSP的CryptoAPI函数**。

**CryptCreateHash**

启动对数据流的哈希处理。如果使用了这个函数，可以通过检查第二个参数的值来找到**正在使用的算法**：

![](<../../.gitbook/assets/image (549).png>)

\
在这里查看可能算法及其分配的值的表格：[https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### 代码常量

有时候很容易识别一个算法，因为它需要使用一个特殊且独特的值。

![](<../../.gitbook/assets/image (833).png>)

如果你在Google中搜索第一个常量，你会得到以下结果：

![](<../../.gitbook/assets/image (529).png>)

因此，你可以假设反编译的函数是一个**sha256计算器**。\
你可以搜索任何其他常量，你可能会得到（可能）相同的结果。

### 数据信息

如果代码没有任何重要的常量，它可能是**从.data部分加载信息**。\
你可以访问这些数据，**将第一个双字分组**，并像前面的部分一样在Google中搜索：

![](<../../.gitbook/assets/image (531).png>)

在这种情况下，如果你搜索**0xA56363C6**，你会发现它与**AES算法的表**有关。

## RC4 **（对称加密）**

### 特征

它由3个主要部分组成：

* **初始化阶段/**：创建一个**值表从0x00到0xFF**（总共256字节，0x100）。这个表通常称为**替代盒**（或SBox）。
* **混淆阶段**：将**循环遍历**之前创建的表（再次循环0x100次）并使用**半随机**字节修改每个值。为了创建这些半随机字节，RC4使用**密钥**。RC4的**密钥**可以是**1到256字节的长度**，但通常建议长度超过5字节。通常，RC4密钥长度为16字节。
* **XOR阶段**：最后，明文或密文与之前创建的值**进行XOR运算**。加密和解密的函数是相同的。为此，将**循环遍历创建的256字节**，直到必要次数。在反编译的代码中，通常会被识别为**%256（模256）**。

{% hint style="info" %}
**为了在反汇编/反编译的代码中识别RC4，你可以检查大小为0x100的2个循环（使用密钥），然后将输入数据与在2个循环中之前创建的256个值进行XOR运算，可能使用%256（模256）**
{% endhint %}

### **初始化阶段/替代盒：**（注意计数器使用的数字256以及如何在256个字符的每个位置写入0）

![](<../../.gitbook/assets/image (584).png>)

### **混淆阶段：**

![](<../../.gitbook/assets/image (835).png>)

### **XOR阶段：**

![](<../../.gitbook/assets/image (904).png>)

## **AES（对称加密）**

### **特征**

* 使用**替代盒和查找表**
* 可以**通过特定查找表值**（常量）来**区分AES**。_注意**常量**可以**存储**在二进制文件中**或动态创建**。_
* **加密密钥**必须是**16的倍数**（通常为32字节），通常使用16字节的**IV**。

### SBox常量

![](<../../.gitbook/assets/image (208).png>)

## Serpent **（对称加密）**

### 特征

* 很少发现一些恶意软件使用它，但有例外（Ursnif）
* 通过长度（非常长的函数）很容易确定算法是否为Serpent。

### 识别

在下图中注意常量**0x9E3779B9**的使用（注意这个常量也被其他加密算法如**TEA** - Tiny Encryption Algorithm使用）。\
还要注意**循环的大小**（**132**）以及**反汇编指令**和**代码示例**中的**XOR操作数量**：

![](<../../.gitbook/assets/image (547).png>)

如前所述，这段代码可以在任何反编译器中显示为**非常长的函数**，因为其中**没有跳转**。反编译的代码可能如下所示：

![](<../../.gitbook/assets/image (513).png>)

因此，可以通过检查**魔术数字**和**初始XOR**，查看**非常长的函数**，并将长函数的**一些指令**与一个实现（如左移7位和左旋转22位）**进行比较**来识别此算法。
## RSA **（非对称加密）**

### 特征

* 比对称算法更复杂
* 没有常量！（自定义实现难以确定）
* KANAL（一个加密分析器）无法显示RSA的提示，因为它依赖于常量。

### 通过比较进行识别

![](<../../.gitbook/assets/image (1113).png>)

* 在第11行（左侧）有一个 `+7) >> 3`，与第35行（右侧）的 `+7) / 8` 相同
* 第12行（左侧）检查 `modulus_len < 0x040`，而第36行（右侧）检查 `inputLen+11 > modulusLen`

## MD5 & SHA（哈希）

### 特征

* 3个函数：Init，Update，Final
* 初始化函数相似

### 识别

**Init**

您可以通过检查常量来识别它们。请注意，sha\_init有一个MD5没有的常量：

![](<../../.gitbook/assets/image (406).png>)

**MD5 Transform**

注意更多常量的使用

![](<../../.gitbook/assets/image (253) (1) (1).png>)

## CRC（哈希）

* 较小且更高效，因为其功能是查找数据中的意外更改
* 使用查找表（因此您可以识别常量）

### 识别

检查**查找表常量**：

![](<../../.gitbook/assets/image (508).png>)

CRC哈希算法如下：

![](<../../.gitbook/assets/image (391).png>)

## APLib（压缩）

### 特征

* 无法识别的常量
* 您可以尝试在Python中编写算法并在网上搜索类似的内容

### 识别

图形相当大：

![](<../../.gitbook/assets/image (207) (2) (1).png>)

检查**3个比较以识别它**：

![](<../../.gitbook/assets/image (430).png>)
