# macOS序列号

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


## 基本信息

自2010年以来，苹果设备的序列号由**12个字母数字字符**组成，每个部分传达特定信息：

- **前3个字符**：表示**制造地点**。
- **第4和第5个字符**：表示**制造年份和周数**。
- **第6到8个字符**：作为每个设备的**唯一标识符**。
- **最后4个字符**：指定**型号编号**。

例如，序列号**C02L13ECF8J2**遵循此结构。

### **制造地点（前3个字符）**
某些代码代表特定工厂：
- **FC，F，XA/XB/QP/G8**：美国的各个地点。
- **RN**：墨西哥。
- **CK**：爱尔兰科克。
- **VM**：捷克富士康。
- **SG/E**：新加坡。
- **MB**：马来西亚。
- **PT/CY**：韩国。
- **EE/QT/UV**：台湾。
- **FK/F1/F2，W8，DL/DM，DN，YM/7J，1C/4H/WQ/F7**：中国的不同地点。
- **C0，C3，C7**：中国的特定城市。
- **RM**：翻新设备。

### **制造年份（第4个字符）**
此字符从'C'（代表2010年上半年）变化到'Z'（2019年下半年），不同的字母表示不同的半年期。

### **制造周数（第5个字符）**
数字1-9对应周数1-9。字母C-Y（不包括元音和'S'）表示周数10-27。对于一年的下半年，将此数字加26。

### **唯一标识符（第6到8个字符）**
这三个数字确保每个设备，即使是相同型号和批次的设备，也有不同的序列号。

### **型号编号（最后4个字符）**
这些数字标识设备的具体型号。

### 参考

* [https://beetstech.com/blog/decode-meaning-behind-apple-serial-number](https://beetstech.com/blog/decode-meaning-behind-apple-serial-number)

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
