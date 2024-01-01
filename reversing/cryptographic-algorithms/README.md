# 加密/压缩算法

## 加密/压缩算法

<details>

<summary><strong>从零开始学习AWS黑客攻击成为英雄</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>

## 识别算法

如果你在代码中**使用了右移和左移、异或和多个算术操作**，很可能是**加密算法**的实现。这里将展示一些方法来**识别使用的算法，而无需逆向每一步**。

### API函数

**CryptDeriveKey**

如果使用了这个函数，你可以通过检查第二个参数的值来找出**正在使用的算法**：

![](<../../.gitbook/assets/image (375) (1) (1) (1) (1).png>)

在这里查看可能的算法及其分配的值的表格：[https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

压缩和解压缩给定的数据缓冲区。

**CryptAcquireContext**

**CryptAcquireContext**函数用于获取特定加密服务提供商（CSP）内特定密钥容器的句柄。**这个返回的句柄在调用使用选定CSP的CryptoAPI**函数时使用。

**CryptCreateHash**

开始对数据流进行哈希处理。如果使用了这个函数，你可以通过检查第二个参数的值来找出**正在使用的算法**：

![](<../../.gitbook/assets/image (376).png>)

\
在这里查看可能的算法及其分配的值的表格：[https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### 代码常量

有时候，由于需要使用特殊且唯一的值，很容易识别出算法。

![](<../../.gitbook/assets/image (370).png>)

如果你在Google中搜索第一个常量，你会得到这个结果：

![](<../../.gitbook/assets/image (371).png>)

因此，你可以假设反编译的函数是**sha256计算器**。
你可以搜索任何其他的常量，你将得到（可能）相同的结果。

### 数据信息

如果代码中没有任何显著的常量，它可能是**从.data段加载信息**。\
你可以访问那些数据，**将第一个双字组合起来**，并像我们在前一节中所做的那样在google中搜索它：

![](<../../.gitbook/assets/image (372).png>)

在这种情况下，如果你查找**0xA56363C6**，你可以发现它与**AES算法的表格**有关。

## RC4 **（对称加密）**

### 特点

它由3个主要部分组成：

* **初始化阶段/**：创建一个**从0x00到0xFF的值表**（总共256字节，0x100）。这个表通常被称为**替换盒**（或SBox）。
* **混乱阶段**：将**循环遍历**之前创建的表（再次循环0x100次），使用**半随机**字节修改每个值。为了创建这些半随机字节，使用了RC4**密钥**。RC4**密钥**可以是**1到256字节的长度**，但通常建议它超过5字节。通常，RC4密钥长度为16字节。
* **XOR阶段**：最后，明文或密文将**与之前创建的值进行异或**。加密和解密的函数是相同的。为此，将**循环遍历创建的256字节**，根据需要进行多次。这通常在反编译的代码中以**%256（模256）**被识别。

{% hint style="info" %}
**为了在反汇编/反编译代码中识别RC4，你可以检查2个大小为0x100的循环（使用密钥），然后将输入数据与之前在2个循环中创建的256个值进行异或，可能使用%256（模256）**
{% endhint %}

### **初始化阶段/替换盒：**（注意使用256作为计数器，以及如何在256个字符的每个位置写入0）

![](<../../.gitbook/assets/image (377).png>)

### **混乱阶段：**

![](<../../.gitbook/assets/image (378).png>)

### **XOR阶段：**

![](<../../.gitbook/assets/image (379).png>)

## **AES（对称加密）**

### **特点**

* 使用**替换盒和查找表**
* 可以通过使用特定的查找表值（常量）来**区分AES**。_注意**常量**可以存储在二进制文件中**或动态创建**。_
* **加密密钥**必须能**被16整除**（通常为32B），通常使用16B的**IV**。

### SBox常量

![](<../../.gitbook/assets/image (380).png>)

## Serpent **（对称加密）**

### 特点

* 很少有恶意软件使用它，但有例子（Ursnif）
* 根据其长度（极长的函数）简单确定算法是否为Serpent

### 识别

在下图中注意到如何使用常量**0x9E3779B9**（注意这个常量也被其他加密算法如**TEA** -Tiny Encryption Algorithm使用）。\
还要注意**循环的大小**（**132**）和**反汇编**指令中的**XOR操作数量**以及**代码**示例：

![](<../../.gitbook/assets/image (381).png>)

如前所述，这段代码可以在任何反编译器中可视化为一个**非常长的函数**，因为它**内部没有跳转**。反编译的代码可能看起来如下：

![](<../../.gitbook/assets/image (382).png>)

因此，可以通过检查**魔术数字**和**初始XORs**，看到一个**非常长的函数**，并**比较**长函数中的一些**指令**与实现（如左移7和左旋转22）来识别这个算法。

## RSA **（非对称加密）**

### 特点

* 比对称算法复杂
* 没有常量！（自定义实现难以确定）
* KANAL（一个加密分析器）在RSA上无法显示提示，因为它依赖于常量。

### 通过比较识别

![](<../../.gitbook/assets/image (383).png>)

* 在第11行（左边）有一个`+7) >> 3`，与第35行（右边）的`+7) / 8`相同
* 第12行（左边）正在检查`modulus_len < 0x040`，而第36行（右边）正在检查`inputLen+11 > modulusLen`

## MD5 & SHA（哈希）

### 特点

* 3个函数：Init, Update, Final
* 类似的初始化函数

### 识别

**Init**

你可以通过检查常量来识别它们。注意sha\_init有一个MD5没有的常量：

![](<../../.gitbook/assets/image (385).png>)

**MD5 Transform**

注意使用了更多的常量

![](<../../.gitbook/assets/image (253) (1) (1) (1).png>)

## CRC（哈希）

* 更小更高效，因为它的功能是找到数据中的意外变化
* 使用查找表（所以你可以识别常量）

### 识别

检查**查找表常量**：

![](<../../.gitbook/assets/image (387).png>)

CRC哈希算法看起来像：

![](<../../.gitbook/assets/image (386).png>)

## APLib（压缩）

### 特点

* 没有可识别的常量
* 你可以尝试用python编写算法，并在线搜索类似的东西

### 识别

图形相当大：

![](<../../.gitbook/assets/image (207) (2) (1).png>)

检查**3个比较以识别它**：

![](<../../.gitbook/assets/image (384).png>)

<details>

<summary><strong>从零开始学习AWS黑客攻击成为英雄</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>
