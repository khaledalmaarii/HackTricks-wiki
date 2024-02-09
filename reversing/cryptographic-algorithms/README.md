# 加密/压缩算法

## 加密/压缩算法

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF版本的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFT**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 识别算法

如果您在代码中**使用移位、异或和多个算术运算**，很可能是**加密算法**的实现。以下将展示一些**无需逆向每个步骤即可识别所使用算法**的方法。

### API函数

**CryptDeriveKey**

如果使用此函数，可以通过检查第二个参数的值来找到**正在使用的算法**：

![](<../../.gitbook/assets/image (375) (1) (1) (1) (1).png>)

在此处查看可能算法及其分配值的表格：[https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

压缩和解压给定的数据缓冲区。

**CryptAcquireContext**

从[文档](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta)中得知，**CryptAcquireContext**函数用于获取特定加密服务提供商（CSP）中特定密钥容器的句柄。**返回的句柄用于调用使用所选CSP的CryptoAPI函数**。

**CryptCreateHash**

启动数据流的哈希处理。如果使用此函数，可以通过检查第二个参数的值来找到**正在使用的算法**：

![](<../../.gitbook/assets/image (376).png>)

在此处查看可能算法及其分配值的表格：[https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### 代码常量

有时很容易识别算法，因为它需要使用特殊且独特的值。

![](<../../.gitbook/assets/image (370).png>)

如果您在Google中搜索第一个常量，您会得到以下结果：

![](<../../.gitbook/assets/image (371).png>)

因此，您可以假设反编译的函数是**sha256计算器**。\
您可以搜索任何其他常量，您可能会得到（可能）相同的结果。

### 数据信息

如果代码没有任何重要的常量，可能是**从.data部分加载信息**。\
您可以访问该数据，**将第一个双字组合在一起**，并像前面的部分一样在Google中搜索：

![](<../../.gitbook/assets/image (372).png>)

在这种情况下，如果您搜索**0xA56363C6**，您会发现它与**AES算法的表**相关联。

## RC4 **（对称加密）**

### 特征

由3个主要部分组成：

* **初始化阶段/**：创建一个值表，从0x00到0xFF（总共256字节，0x100）。这个表通常称为**替换盒**（或SBox）。
* **混淆阶段**：将在之前创建的表中循环（再次循环0x100次）并使用**半随机**字节修改每个值。为了创建这些半随机字节，使用RC4**密钥**。RC4**密钥**可以是**1到256字节的长度**，但通常建议长度超过5字节。通常，RC4密钥长度为16字节。
* **XOR阶段**：最后，明文或密文与之前创建的值**进行异或**。加密和解密的函数是相同的。为此，将对创建的256字节执行**多次循环**。在反编译的代码中，通常会识别为**%256（模256）**。

{% hint style="info" %}
**要在反汇编/反编译的代码中识别RC4，您可以检查大小为0x100的2个循环（使用密钥），然后将输入数据与在2个循环中创建的256个值进行XOR，可能使用%256（模256）**
{% endhint %}

### **初始化阶段/替换盒：**（注意计数器使用的数字256以及如何在256个字符的每个位置写入0）

![](<../../.gitbook/assets/image (377).png>)

### **混淆阶段：**

![](<../../.gitbook/assets/image (378).png>)

### **XOR阶段：**

![](<../../.gitbook/assets/image (379).png>)

## **AES（对称加密）**

### **特征**

* 使用**替换盒和查找表**
* 可以**通过特定查找表值**（常量）来区分AES。_请注意，**常量**可以**存储**在二进制文件中**或动态创建**。_
* **加密密钥**必须是**16的倍数**（通常为32字节），通常使用16字节的**IV**。

### SBox常量

![](<../../.gitbook/assets/image (380).png>)

## Serpent **（对称加密）**

### 特征

* 很少发现某些恶意软件使用它，但有例外（Ursnif）
* 可以根据其长度（非常长的函数）轻松确定算法是否为Serpent。

### 识别

请注意以下图像中使用的常量**0x9E3779B9**（请注意，此常量也用于其他加密算法，如**TEA** - Tiny Encryption Algorithm）。\
还请注意**循环的大小**（**132**）以及**反汇编**指令和**代码示例**中的**XOR操作数量**：

![](<../../.gitbook/assets/image (381).png>)

如前所述，此代码可以在任何反编译器中显示为**非常长的函数**，因为其中**没有跳转**。反编译的代码可能如下所示：

![](<../../.gitbook/assets/image (382).png>)

因此，可以通过检查**魔术数字**和**初始XOR**，查看**非常长的函数**，并将一些**指令**与**实现**（如左移7位和左旋转22位）进行**比较**，来识别此算法。

## RSA **（非对称加密）**

### 特征

* 比对称算法更复杂
* 没有常量！（难以确定自定义实现）
* KANAL（加密分析器）无法显示RSA的提示，因为它依赖于常量。

### 通过比较识别

![](<../../.gitbook/assets/image (383).png>)

* 在第11行（左侧）有一个`+7) >> 3`，与第35行（右侧）的`+7) / 8`相同
* 第12行（左侧）检查`modulus_len < 0x040`，第36行（右侧）检查`inputLen+11 > modulusLen`

## MD5和SHA（哈希）

### 特征

* 3个函数：初始化、更新、完成
* 相似的初始化函数

### 识别

**初始化**

您可以通过检查常量来识别它们。请注意，sha_init具有MD5没有的1个常量：

![](<../../.gitbook/assets/image (385).png>)

**MD5变换**

请注意使用更多常量

![](<../../.gitbook/assets/image (253) (1) (1) (1).png>)

## CRC（哈希）

* 由于其功能是查找数据中的意外更改，因此更小且更有效
* 使用查找表（因此您可以识别常量）

### 识别

检查**查找表常量**：

![](<../../.gitbook/assets/image (387).png>)

CRC哈希算法如下：

![](<../../.gitbook/assets/image (386).png>)

## APLib（压缩）

### 特征

* 无法识别的常量
* 您可以尝试在Python中编写算法并在线搜索类似的内容

### 识别

图表相当大：

![](<../../.gitbook/assets/image (207) (2) (1).png>)

检查**3个比较以识别它**：

![](<../../.gitbook/assets/image (384).png>)

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF版本的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFT**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
