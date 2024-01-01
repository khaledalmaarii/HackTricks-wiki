# Sub-GHz RF

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>

## 车库门

车库门开启器通常在300-190 MHz频段运作，最常见的频率是300 MHz、310 MHz、315 MHz和390 MHz。这个频段常用于车库门开启器，因为它比其他频段拥挤程度低，不太可能受到其他设备的干扰。

## 汽车门

大多数汽车钥匙遥控器在**315 MHz或433 MHz**上操作。这两个都是无线电频率，它们用于多种不同的应用。两个频率的主要区别是433 MHz的范围比315 MHz更远。这意味着433 MHz更适合需要较远范围的应用，例如无钥匙远程进入。\
在欧洲，常用的是433.92MHz，在美国和日本则是315MHz。

## **暴力破解攻击**

<figure><img src="../../.gitbook/assets/image (4) (3) (2).png" alt=""><figcaption></figcaption></figure>

如果不是发送每个代码5次（这样发送是为了确保接收器收到），而只发送一次，时间可以缩短到6分钟：

<figure><img src="../../.gitbook/assets/image (1) (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

如果你**去掉信号之间的2毫秒等待**时间，你可以**将时间缩短到3分钟。**

此外，通过使用De Bruijn序列（一种减少发送所有潜在二进制数以进行暴力破解所需比特数的方法），这个**时间只需8秒**：

<figure><img src="../../.gitbook/assets/image (5) (2) (3).png" alt=""><figcaption></figcaption></figure>

这种攻击的例子实现在[https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

要求**前导码将避免De Bruijn序列**优化，**滚动代码将阻止此攻击**（假设代码足够长，无法被暴力破解）。

## Sub-GHz攻击

要使用Flipper Zero攻击这些信号，请查看：

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## 滚动代码保护

自动车库门开启器通常使用无线遥控器来开启和关闭车库门。遥控器**发送无线电频率（RF）信号**给车库门开启器，激活电机以开启或关闭门。

有人可能会使用称为代码抓取器的设备来截取RF信号并记录下来以供后用。这被称为**重放攻击**。为了防止这种类型的攻击，许多现代车库门开启器使用一种更安全的加密方法，称为**滚动代码**系统。

**RF信号通常使用滚动代码传输**，这意味着代码每次使用时都会改变。这使得某人**截取**信号并**使用**它来获得**未授权**访问变得**困难**。

在滚动代码系统中，遥控器和车库门开启器有一个**共享算法**，每次使用遥控器时都会**生成新代码**。车库门开启器只会响应**正确的代码**，这使得某人想要仅通过捕获代码就获得未授权访问车库变得更加困难。

### **缺失链接攻击**

基本上，你监听按钮并**在遥控器超出设备（比如汽车或车库）范围时捕获信号**。然后你移动到设备并**使用捕获的代码打开它**。

### 全链路干扰攻击

攻击者可以**在车辆或接收器附近干扰信号**，以便**接收器实际上无法‘听到’代码**，一旦发生这种情况，你可以简单地**捕获并重放**代码，当你停止干扰时。

受害者在某个时刻会使用**钥匙锁车**，但随后攻击者将会**记录足够多的“关闭门”代码**，希望可以重新发送以打开门（可能需要**更换频率**，因为有些车辆使用相同的代码来开启和关闭，但在不同频率上监听两个命令）。

{% hint style="warning" %}
**干扰有效**，但是如果**锁车的人简单地测试门**确保它们被锁上，他们会注意到车辆未锁。此外，如果他们意识到这种攻击，他们甚至可以听到门从未发出锁定**声音**，或者当他们按下‘锁定’按钮时，车辆的**灯光**从未闪烁。
{% endhint %}

### **代码抓取攻击（又名‘RollJam’）**

这是一种更**隐蔽的干扰技术**。攻击者将干扰信号，所以当受害者尝试锁门时它不会起作用，但攻击者将**记录这个代码**。然后，受害者将**再次尝试锁车**按下按钮，车辆将**记录这第二个代码**。\
紧接着攻击者可以发送第一个代码，**车辆将锁定**（受害者会认为第二次按下关闭了它）。然后，攻击者将能够**发送第二个被盗代码来打开**车辆（假设一个**“关闭车辆”代码也可以用来打开它**）。可能需要更换频率（因为有些车辆使用相同的代码来开启和关闭，但在不同频率上监听两个命令）。

攻击者可以**干扰车辆接收器而不是他的接收器**，因为如果车辆接收器在例如1MHz宽带上监听，攻击者不会**干扰**遥控器使用的确切频率，而是**一个在那个频谱中接近的频率**，同时**攻击者的接收器将在一个更小的范围内监听**，他可以在那里听到遥控器信号**没有干扰信号**。

{% hint style="warning" %}
其他在规格书中看到的实现表明，**滚动代码是发送的总代码的一部分**。即发送的代码是一个**24位密钥**，其中前**12位是滚动代码**，**接下来的8位是命令**（如锁定或解锁），最后4位是**校验和**。实施这种类型的车辆也自然容易受到攻击，因为攻击者只需要替换滚动代码段，就能够**在两个频率上使用任何滚动代码**。
{% endhint %}

{% hint style="danger" %}
请注意，如果受害者在攻击者发送第一个代码时发送第三个代码，第一个和第二个代码将被作废。
{% endhint %}

### 报警声干扰攻击

在对安装在汽车上的市售滚动代码系统进行测试时，**连续发送相同的代码两次**立即**激活了报警器**和防盗器，提供了独特的**拒绝服务**机会。具有讽刺意味的是，**禁用报警器**和防盗器的方法是**按下**遥控器，为攻击者提供了**持续进行DoS攻击的能力**。或者将这种攻击与**前一个混合以获得更多代码**，因为受害者会希望尽快停止攻击。

## 参考资料

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>
