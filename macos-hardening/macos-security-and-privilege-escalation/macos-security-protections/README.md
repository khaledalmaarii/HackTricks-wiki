# macOS安全保护

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云平台 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者想要**获取PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFT收藏品The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass)，或者**关注**我在**Twitter上** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## Gatekeeper

Gatekeeper通常用来指代**Quarantine + Gatekeeper + XProtect**的组合，这是3个macOS安全模块，它们会尝试**阻止用户执行潜在恶意软件的下载**。

更多信息请参考：

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## MRT - 恶意软件移除工具

恶意软件移除工具（MRT）是macOS安全基础设施的另一部分。顾名思义，MRT的主要功能是**从受感染的系统中移除已知的恶意软件**。

一旦在Mac上检测到恶意软件（无论是通过XProtect还是其他方式），MRT可以用于自动**移除恶意软件**。MRT在后台静默运行，通常在系统更新或下载新的恶意软件定义时运行（看起来MRT用于检测恶意软件的规则嵌入在二进制文件中）。

虽然XProtect和MRT都是macOS的安全措施的一部分，但它们具有不同的功能：

* **XProtect**是一种预防工具。它会在文件下载时（通过某些应用程序）**检查文件**，如果检测到任何已知类型的恶意软件，它会**阻止文件打开**，从而防止恶意软件首次感染系统。
* 另一方面，**MRT是一种响应工具**。它在检测到系统上的恶意软件后运行，目的是移除有问题的软件以清理系统。

MRT应用程序位于**`/Library/Apple/System/Library/CoreServices/MRT.app`**

## 进程限制

### SIP - 系统完整性保护

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### 沙盒

macOS沙盒**限制在沙盒内运行的应用程序**只能执行沙盒配置文件中指定的允许操作。这有助于确保**应用程序只能访问预期的资源**。

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - 透明度、同意和控制

**TCC（透明度、同意和控制）**是macOS中的一种机制，用于从隐私角度**限制和控制应用程序对某些功能的访问**。这可能包括位置服务、联系人、照片、麦克风、摄像头、辅助功能、完全磁盘访问等等。

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

## 信任缓存

苹果macOS的信任缓存，有时也称为AMFI（Apple Mobile File Integrity）缓存，是macOS中的一种安全机制，旨在**防止未经授权或恶意软件的运行**。实质上，它是操作系统用于**验证软件的完整性和真实性的加密哈希列表**。

当应用程序或可执行文件尝试在macOS上运行时，操作系统会检查AMFI信任缓存。如果在信任缓存中找到文件的哈希值，系统会**允许**该程序运行，因为它被识别为可信任的。

## 启动限制

它控制从何处以及什么可以启动Apple签名的二进制文件：

* 如果应该由launchd运行，你不能直接启动应用程序
* 你不能在受信任的位置之外运行应用程序（如/System/）

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云平台 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者想要**获取PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFT收藏品The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass)，或者**关注**我在**Twitter上** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>
