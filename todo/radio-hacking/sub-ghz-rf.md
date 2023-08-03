# Sub-GHz RF

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFT收藏品The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 车库门

车库门开启器通常在300-190 MHz的频率范围内工作，最常见的频率是300 MHz、310 MHz、315 MHz和390 MHz。之所以在这个频率范围内使用车库门开启器，是因为相比其他频段，这个频率范围更不拥挤，更不容易受到其他设备的干扰。

## 车门

大多数汽车钥匙遥控器使用的频率是**315 MHz或433 MHz**。这两个频率都是无线电频率，用于各种不同的应用。两个频率之间的主要区别是433 MHz的传输距离比315 MHz更远。这意味着433 MHz更适用于需要较长传输距离的应用，例如远程无钥匙进入。\
在欧洲，常用的是433.92MHz，在美国和日本，常用的是315MHz。

## **暴力破解攻击**

<figure><img src="../../.gitbook/assets/image (4) (3) (2).png" alt=""><figcaption></figcaption></figure>

如果不是将每个代码发送5次（以确保接收器接收到），而是只发送一次，时间将缩短到6分钟：

<figure><img src="../../.gitbook/assets/image (1) (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

如果**去除信号之间的2毫秒等待**时间，可以将时间缩短到3分钟。

此外，通过使用De Bruijn序列（一种减少发送所有潜在二进制数所需位数的方法），这个时间只需8秒：

<figure><img src="../../.gitbook/assets/image (5) (2) (3).png" alt=""><figcaption></figcaption></figure>

这种攻击的示例已在[https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)中实现。

要避免De Bruijn序列优化，可以使用**前导码**，而**滚动码**将防止此攻击（假设代码足够长，无法通过暴力破解破解）。

## Sub-GHz攻击

要使用Flipper Zero攻击这些信号，请查看：

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## 滚动码保护

自动车库门开启器通常使用无线遥控器来打开和关闭车库门。遥控器**发送无线电频率（RF）信号**给车库门开启器，激活电机打开或关闭门。

有人可以使用一种称为代码抓取器的设备来拦截RF信号并记录下来以供以后使用。这被称为**重放攻击**。为了防止这种类型的攻击，许多现代车库门开启器使用一种更安全的加密方法，称为**滚动码**系统。

**RF信号通常使用滚动码**进行传输，这意味着每次使用时代码都会更改。这使得某人很难拦截信号并将其用于未经授权的进入车库。

在滚动码系统中，遥控器和车库门开启器有一个**共享算法**，每次使用遥控器时都会**生成一个新的代码**。车库门开启器只会响应**正确的代码**，这使得某人仅通过捕获一个代码就更难未经授权地进入车库。

### **缺失链接攻击**

基本上，你在遥控器**超出设备范围**（比如车或车库）时监听按钮并**捕获信号**。然后你移动到设备附近并使用捕获的代码打开它。

### 完整链接干扰攻击

攻击者可以在车辆或接收器附近**干扰信号**，使接收器无法**“听到”代码**，一旦发生这种情况，你可以简单地**捕获和重放**代码。

受害者在某个时刻会使用**钥匙锁车**，但攻击将**记录足够多的“关闭门”代码**，希望可以重新发送以打开门（可能需要更改频率，因为有些汽车使用相同的代码来打开和关闭，但在不同的频率上接收两个命令）。

{% hint style="warning" %}
**干扰是有效的**，但如果**锁车的人只是测试门**以确保它们已锁上，他们会注意到车辆未锁定。此外，如果他们意识到此类攻击，他们甚至可以听到门在按下“锁定”按钮时从未发出**锁定声音**或车辆的**灯光**未闪烁。
{% endhint %}
### **代码抓取攻击（又名“RollJam”）**

这是一种更隐蔽的干扰技术。攻击者会干扰信号，使得受害者在尝试锁门时无法成功，但攻击者会记录下这个代码。然后，受害者会再次尝试按下按钮锁车，此时车辆会记录下第二个代码。\
紧接着，攻击者可以发送第一个代码，车辆会被锁上（受害者会认为第二次按下按钮锁上了）。然后，攻击者可以发送第二个窃取的代码来打开车门（假设“锁车”代码也可以用来打开车门）。可能需要更改频率（因为有些车辆使用相同的代码来打开和关闭，但在不同的频率上监听这两个命令）。

攻击者可以干扰车辆接收器而不是自己的接收器，因为如果车辆接收器在例如1MHz的宽带上监听，攻击者不会干扰遥控器使用的确切频率，而是在该频谱中的一个接近频率上干扰，而攻击者的接收器将在一个较小的范围内监听遥控信号，而不会受到干扰信号的影响。

{% hint style="warning" %}
在其他规范中看到的其他实现显示，滚动代码是发送的总代码的一部分。例如，发送的代码是一个24位密钥，其中前12位是滚动代码，接下来的8位是命令（如锁定或解锁），最后4位是校验和。实现此类型的车辆也容易受到攻击，因为攻击者只需替换滚动代码段即可使用任何滚动代码在两个频率上。
{% endhint %}

{% hint style="danger" %}
请注意，如果受害者在攻击者发送第一个代码时发送第三个代码，第一个和第二个代码将无效。
{% endhint %}

### 报警声干扰攻击

对安装在汽车上的售后滚动代码系统进行测试，**发送相同的代码两次**会立即**激活报警器**和防盗装置，提供了一个独特的**拒绝服务**机会。具有讽刺意味的是，**禁用报警器**和防盗装置的方法是**按下**遥控器，这为攻击者提供了持续执行DoS攻击的能力。或者将此攻击与**前面的攻击混合**，以获取更多的代码，因为受害者希望尽快停止攻击。

## 参考资料

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**为你的公司做广告**吗？或者想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass)，或者在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
