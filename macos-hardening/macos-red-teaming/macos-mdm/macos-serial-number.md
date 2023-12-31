# macOS 序列号

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 HackTricks 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

2010 年后生产的 Apple 设备通常具有 **12 个字符的字母数字**序列号，**前三位代表制造地点**，接下来的**两位**表示制造的**年份**和**周数**，接下来的**三位**提供一个**唯一的** **标识符**，最后**四位**代表**型号编号**。

序列号示例：**C02L13ECF8J2**

### **3 - 制造地点**

| 代码           | 工厂                                          |
| -------------- | -------------------------------------------- |
| FC             | 美国科罗拉多州喷泉市                         |
| F              | 美国加利福尼亚州弗里蒙特                     |
| XA, XB, QP, G8 | 美国                                          |
| RN             | 墨西哥                                       |
| CK             | 爱尔兰科克                                   |
| VM             | 捷克共和国帕尔杜比采富士康                   |
| SG, E          | 新加坡                                        |
| MB             | 马来西亚                                      |
| PT, CY         | 韩国                                          |
| EE, QT, UV     | 台湾                                          |
| FK, F1, F2     | 中国郑州富士康                               |
| W8             | 中国上海                                      |
| DL, DM         | 中国富士康                                    |
| DN             | 中国成都富士康                                |
| YM, 7J         | 中国鸿海/富士康                              |
| 1C, 4H, WQ, F7 | 中国                                          |
| C0             | 中国科技通 - 夸达电脑子公司                   |
| C3             | 中国深圳富士康                                |
| C7             | 中国上海潘特拉贡                              |
| RM             | 翻新/再制造                                   |

### 1 - 制造年份

| 代码 | 发布时间              |
| ---- | -------------------- |
| C    | 2010/2020（上半年）   |
| D    | 2010/2020（下半年）   |
| F    | 2011/2021（上半年）   |
| G    | 2011/2021（下半年）   |
| H    | 2012/...（上半年）    |
| J    | 2012（下半年）        |
| K    | 2013（上半年）        |
| L    | 2013（下半年）        |
| M    | 2014（上半年）        |
| N    | 2014（下半年）        |
| P    | 2015（上半年）        |
| Q    | 2015（下半年）        |
| R    | 2016（上半年）        |
| S    | 2016（下半年）        |
| T    | 2017（上半年）        |
| V    | 2017（下半年）        |
| W    | 2018（上半年）        |
| X    | 2018（下半年）        |
| Y    | 2019（上半年）        |
| Z    | 2019（下半年）        |

### 1 - 制造周数

第五个字符代表设备制造的周数。这个位置有 28 个可能的字符：**数字 1-9 用于表示第一周到第九周**，而**字符 C 到 Y**，**不包括元音 A, E, I, O 和 U，以及字母 S**，代表**第十周到第二十七周**。对于下半年制造的设备，将第五个字符代表的数字加上 26。例如，序列号的第四和第五位是“JH”的产品是在 2012 年的第 40 周制造的。

### 3 - 唯一代码

接下来的三位数字是一个标识符代码，**用于区分在同一地点、同一周、同一年制造的同一型号的每个 Apple 设备**，确保每个设备都有不同的序列号。

### 4 - 序列号

序列号的最后四位代表**产品的型号**。

### 参考

{% embed url="https://beetstech.com/blog/decode-meaning-behind-apple-serial-number" %}

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 HackTricks 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>
