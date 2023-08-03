# macOS序列号

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

自2010年以后，苹果设备通常具有**12个字符的字母数字**序列号，其中**前三个数字代表制造地点**，接下来的**两个数字表示制造年份和周数**，接下来的**三个数字提供唯一标识符**，最后的**四个数字表示型号号码**。

序列号示例：**C02L13ECF8J2**

### **3 - 制造地点**

| 代码           | 工厂                                         |
| -------------- | -------------------------------------------- |
| FC             | 美国科罗拉多州喷泉                           |
| F              | 美国加利福尼亚州弗里蒙特                     |
| XA, XB, QP, G8 | 美国                                         |
| RN             | 墨西哥                                       |
| CK             | 爱尔兰科克                                   |
| VM             | 捷克共和国帕尔杜比采富士康                   |
| SG, E          | 新加坡                                       |
| MB             | 马来西亚                                     |
| PT, CY         | 韩国                                         |
| EE, QT, UV     | 台湾                                         |
| FK, F1, F2     | 中国郑州富士康                               |
| W8             | 中国上海                                     |
| DL, DM         | 中国富士康                                   |
| DN             | 中国成都富士康                               |
| YM, 7J         | 中国鸿海/富士康                              |
| 1C, 4H, WQ, F7 | 中国                                         |
| C0             | 科技通 - 全球零部件制造商富士康子公司，中国 |
| C3             | 中国深圳富士康                               |
| C7             | 中国长海五角大楼                             |
| RM             | 翻新/再制造                                  |

### 1 - 制造年份

| 代码 | 发布                  |
| ---- | -------------------- |
| C    | 2010/2020（上半年） |
| D    | 2010/2020（下半年） |
| F    | 2011/2021（上半年） |
| G    | 2011/2021（下半年） |
| H    | 2012/...（上半年）  |
| J    | 2012（下半年）      |
| K    | 2013（上半年）      |
| L    | 2013（下半年）      |
| M    | 2014（上半年）      |
| N    | 2014（下半年）      |
| P    | 2015（上半年）      |
| Q    | 2015（下半年）      |
| R    | 2016（上半年）      |
| S    | 2016（下半年）      |
| T    | 2017（上半年）      |
| V    | 2017（下半年）      |
| W    | 2018（上半年）      |
| X    | 2018（下半年）      |
| Y    | 2019（上半年）      |
| Z    | 2019（下半年）      |

### 1 - 制造周数

第五个字符表示设备制造的周数。在这个位置上有28个可能的字符：**数字1-9用于表示第1到第9周**，而**字符C到Y**，**不包括**元音字母A、E、I、O和U，以及字母S，表示**第10到第27周**。对于在**年的下半年制造的设备，将26加到序列号的第五个字符所代表的数字上**。例如，序列号的第四个和第五个数字为“JH”的产品是在2012年的第40周制造的。

### 3 - 唯一标识符

接下来的三个数字是一个标识符，**用于区分在同一地点、同一年的同一周制造的每个相同型号的苹果设备**，确保每个设备都有不同的序列号。

### 4 - 序列号

序列号的最后四位数字表示产品的**型号**。
### 参考资料

{% embed url="https://beetstech.com/blog/decode-meaning-behind-apple-serial-number" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
