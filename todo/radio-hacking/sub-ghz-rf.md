# Sub-GHz RF

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

- 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
- 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
- **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
- 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 车库门

车库门开启器通常在300-190 MHz范围内运行，最常见的频率为300 MHz、310 MHz、315 MHz和390 MHz。车库门开启器通常使用这个频率范围，因为与其他频段相比，这个频率范围更不拥挤，不太可能受到其他设备的干扰。

## 车门

大多数汽车钥匙遥控器使用**315 MHz或433 MHz**。这两种都是无线电频率，用于各种不同的应用。这两种频率之间的主要区别在于433 MHz的范围比315 MHz更长。这意味着433 MHz更适用于需要更长范围的应用，例如远程无钥匙进入。\
在欧洲，常用的是433.92MHz，在美国和日本则是315MHz。

## **暴力破解攻击**

<figure><img src="../../.gitbook/assets/image (1084).png" alt=""><figcaption></figcaption></figure>

如果不是发送每个代码5次（这样发送是为了确保接收器收到），而只发送一次，时间可以缩短到6分钟：

<figure><img src="../../.gitbook/assets/image (622).png" alt=""><figcaption></figcaption></figure>

如果**去除信号之间的2毫秒等待**时间，可以将时间缩短到3分钟。

此外，通过使用德布鲁因序列（一种减少发送所有潜在二进制数所需位数的方法），这个**时间仅缩短到8秒**：

<figure><img src="../../.gitbook/assets/image (583).png" alt=""><figcaption></figcaption></figure>

这种攻击的示例已在[https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)中实现。

需要**前导码**将避免德布鲁因序列优化，而**滚动代码将防止这种攻击**（假设代码足够长，无法通过暴力破解获得）。

## 亚GHz攻击

要使用Flipper Zero攻击这些信号，请查看：

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## 滚动代码保护

自动车库门开启器通常使用无线遥控器来打开和关闭车库门。遥控器**发送无线电频率（RF）信号**给车库门开启器，激活电机打开或关闭门。

有人可以使用称为代码抓取器的设备拦截RF信号并记录以供以后使用。这被称为**重放攻击**。为了防止这种类型的攻击，许多现代车库门开启器使用更安全的加密方法，称为**滚动代码**系统。

**RF信号通常使用滚动代码**传输，这意味着每次使用时代码都会更改。这使得某人很难**拦截**信号并将其用于未经授权地访问车库。

在滚动代码系统中，遥控器和车库门开启器有一个**共享算法**，每次使用遥控器时都会**生成一个新代码**。车库门开启器只会响应**正确的代码**，这使得某人仅通过捕获代码就更难未经授权地访问车库。

### **缺失链接攻击**

基本上，您监听按钮并在设备（如汽车或车库）**超出范围时捕获信号**。然后，您移动到设备并**使用捕获的代码打开它**。

### 完整链接干扰攻击

攻击者可以在车辆或接收器附近**干扰信号**，使**接收器实际上无法‘听到’代码**，一旦发生这种情况，您可以简单地**捕获和重放**代码。

受害者最终会使用**钥匙锁车**，但攻击将已经记录了足够多的“关闭车门”代码，希望可以重新发送以打开车门（可能需要**更改频率**，因为有些车辆使用相同的代码来打开和关闭，但在不同频率上监听两个命令）。

{% hint style="warning" %}
**干扰有效**，但如果**锁车的人简单地测试门**以确保它们已锁上，他们会注意到车辆未锁定。此外，如果他们意识到此类攻击，甚至可以听到车门从未发出锁定**声音**或汽车**灯光**在按下“锁定”按钮时未闪烁。
{% endhint %}

### **代码抓取攻击（又名‘RollJam’）**

这是一种更**隐蔽的干扰技术**。攻击者将干扰信号，因此当受害者尝试锁定门时，它不起作用，但攻击者将**记录此代码**。然后，受害者将**再次尝试锁定汽车**按下按钮，汽车将**记录第二个代码**。\
在此之后，**攻击者可以发送第一个代码**，汽车将锁定（受害者会认为第二次按下按钮已关闭）。然后，攻击者将能够**发送第二个窃取的代码以打开**汽车（假设**“关闭车”代码也可以用于打开**）。可能需要更改频率（因为有些车辆使用相同的代码来打开和关闭，但在不同频率上监听两个命令）。

攻击者可以**干扰汽车接收器而不是自己的接收器**，因为如果汽车接收器在例如1MHz宽带中监听，攻击者不会**干扰**遥控器使用的确切频率，而是**在该频谱中的一个接近频率**，而**攻击者的接收器将在较小范围内监听**，在那里他可以**听到遥控器信号而不受干扰信号的影响**。

{% hint style="warning" %}
其他规范中看到的实现显示**滚动代码是发送的总代码的一部分**。即发送的代码是一个**24位密钥**，其中前**12位是滚动代码**，第二个8位是命令（如锁定或解锁），最后4位是**校验和**。实施这种类型的车辆也天然容易受到攻击，因为攻击者只需替换滚动代码段即可**在两个频率上使用任何滚动代码**。
{% endhint %}

{% hint style="danger" %}
请注意，如果受害者在攻击者发送第一个代码时发送第三个代码，则第一个和第二个代码将无效。
### 报警声干扰攻击

针对安装在汽车上的售后滚动码系统进行测试，**立即发送相同的代码**会**激活报警器**和防盗装置，提供了一种独特的**拒绝服务**机会。具有讽刺意味的是，**禁用报警器**和防盗装置的方法是**按下**遥控器，使攻击者能够**持续执行 DoS 攻击**。或者将此攻击与**先前的攻击混合**，以获取更多代码，因为受害者希望尽快停止攻击。

## 参考资料

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS 红队专家）</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 HackTricks 中看到您的**公司广告**或**下载 PDF 版本的 HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFT**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live) 上**关注**我们。
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧**。

</details>
