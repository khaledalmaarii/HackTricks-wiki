# macOS安全与权限提升

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

加入[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy)服务器，与经验丰富的黑客和赏金猎人交流！

**黑客见解**\
参与深入探讨黑客的刺激和挑战的内容

**实时黑客新闻**\
通过实时新闻和见解了解快节奏的黑客世界

**最新公告**\
了解最新的赏金任务发布和重要平台更新

**加入我们的**[**Discord**](https://discord.com/invite/N3FrSbmwdy)，与顶级黑客一起合作！

## 基本的MacOS知识

如果你对macOS不熟悉，你应该开始学习macOS的基础知识：

* 特殊的macOS**文件和权限：**

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* 常见的macOS**用户**

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* **内核**的**架构**

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* 常见的macOS**网络服务和协议**

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **开源**的macOS：[https://opensource.apple.com/](https://opensource.apple.com/)
* 要下载一个`tar.gz`文件，将URL从[https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/)更改为[https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

在公司中，**macOS**系统很可能会被**MDM管理**。因此，从攻击者的角度来看，了解**它是如何工作的**是很有意义的：

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - 检查、调试和模糊测试

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## MacOS安全保护

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## 攻击面

### 文件权限

如果以**root权限运行的进程**写入一个可以被用户控制的文件，用户可以利用这个漏洞**提升权限**。\
这种情况可能发生在以下情况下：

* 使用的文件已经由用户创建（由用户拥有）
* 使用的文件由于一个组的原因可被用户写入
* 使用的文件位于用户拥有的目录中（用户可以创建文件）
* 使用的文件位于由root拥有但用户具有写入权限的目录中（用户可以创建文件）

能够**创建一个将被root使用的文件**，允许用户**利用其内容**，甚至创建**符号链接/硬链接**将其指向另一个位置。

对于这种类型的漏洞，不要忘记**检查易受攻击的`.pkg`安装程序**：

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}
### 文件扩展名和URL方案应用程序处理程序

通过文件扩展名注册的奇怪应用程序可能会被滥用，并且不同的应用程序可以注册以打开特定的协议。

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## macOS TCC / SIP权限提升

在macOS中，**应用程序和二进制文件可以具有访问文件夹或设置的权限**，使它们比其他应用程序更具特权。

因此，想要成功攻击macOS机器的攻击者将需要**提升其TCC权限**（甚至**绕过SIP**，取决于他的需求）。

这些权限通常以应用程序签名的**授权**形式给出，或者应用程序可能请求某些访问权限，经过**用户批准**后，这些权限可以在**TCC数据库**中找到。进程可以获得这些权限的另一种方式是作为具有这些权限的进程的**子进程**，因为它们通常是**继承**的。

请参阅以下链接，了解不同的方法来[**提升TCC权限**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses)，[**绕过TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/)以及过去如何[**绕过SIP**](macos-security-protections/macos-sip.md#sip-bypasses)。

## macOS传统权限提升

当然，从红队的角度来看，您也应该对提升为root感兴趣。查看以下文章以获取一些提示：

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}

## 参考资料

* [**OS X事件响应：脚本和分析**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

加入[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy)服务器，与经验丰富的黑客和赏金猎人交流！

**黑客见解**\
参与深入探讨黑客的刺激和挑战的内容

**实时黑客新闻**\
通过实时新闻和见解了解快节奏的黑客世界

**最新公告**\
了解最新的赏金任务启动和重要平台更新

**加入我们的** [**Discord**](https://discord.com/invite/N3FrSbmwdy) **，与顶级黑客一起合作！**

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想要访问**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品](https://opensea.io/collection/the-peass-family)——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>
