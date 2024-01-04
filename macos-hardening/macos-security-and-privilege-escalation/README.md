# macOS 安全性与权限提升

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 HackTricks 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

加入 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 服务器，与经验丰富的黑客和漏洞赏金猎人交流！

**黑客洞察**\
参与深入探讨黑客技术的刺激和挑战的内容

**实时黑客新闻**\
通过实时新闻和洞察，跟上快节奏的黑客世界

**最新公告**\
通过最新的漏洞赏金发布和关键平台更新，保持信息的更新

**加入我们的** [**Discord**](https://discord.com/invite/N3FrSbmwdy) 并立即开始与顶尖黑客合作！

## 基础 MacOS

如果您不熟悉 macOS，您应该开始学习 macOS 的基础知识：

* 特殊的 macOS **文件和权限：**

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* 常见的 macOS **用户**

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* 内核的**架构**

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* 常见的 macOS **网络服务和协议**

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **开源** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
* 要下载 `tar.gz`，请将 URL 例如 [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) 更改为 [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

在公司中，**macOS** 系统很可能会通过 MDM 进行**管理**。因此，从攻击者的角度来看，了解**它是如何工作**的是有趣的：

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - 检查、调试和模糊测试

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## MacOS 安全防护

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## 攻击面

### 文件权限

如果**以 root 身份运行的进程写入**了用户可以控制的文件，用户可能会滥用这一点来**提升权限**。\
这可能发生在以下情况：

* 文件已由用户创建（由用户拥有）
* 文件因为组而可由用户写入
* 文件位于用户拥有的目录中（用户可以创建文件）
* 文件位于 root 拥有但用户因为组有写入权限的目录中（用户可以创建文件）

能够**创建将要被 root 使用的文件**，允许用户**利用其内容**，甚至创建**符号链接/硬链接**指向其他位置。

对于这类漏洞，不要忘记**检查易受攻击的 `.pkg` 安装程序**：

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}



### 文件扩展名和 URL 方案应用程序处理程序

可能会滥用由文件扩展名注册的奇怪应用程序，不同的应用程序可以注册以打开特定协议

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## macOS TCC / SIP 权限提升

在 macOS 中，**应用程序和二进制文件可以拥有权限**来访问使它们比其他文件更具特权的文件夹或设置。

因此，想要成功攻破 macOS 机器的攻击者将需要**提升其 TCC 权限**（或者甚至**绕过 SIP**，取决于他的需求）。

这些权限通常以应用程序签名的**权限**形式给出，或者应用程序可能请求了一些访问权限，并在**用户批准后**可以在**TCC 数据库**中找到。进程获取这些权限的另一种方式是作为具有这些**权限**的**进程的子进程**，因为它们通常是**继承的**。

请关注以下链接，找到不同的方法来[**在 TCC 中提升权限**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses)，[**绕过 TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/)，以及过去如何[**绕过 SIP**](macos-security-protections/macos-sip.md#sip-bypasses)。

## macOS 传统权限提升

当然，从红队的角度来看，您也应该对提升到 root 权限感兴趣。查看以下帖子以获取一些提示：

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}

## 参考资料

* [**OS X 事件响应：脚本和分析**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

加入 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 服务器，与经验丰富的黑客和漏洞赏金猎人交流！

**黑客洞察**\
参与深入探讨黑客技术的刺激和挑战的内容

**实时黑客新闻**\
通过实时新闻和洞察，跟上快节奏的黑客世界

**最新公告**\
通过最新的漏洞赏金发布和关键平台更新，保持信息的更新

**加入我们的** [**Discord**](https://discord.com/invite/N3FrSbmwdy) 并立即开始与顶尖黑客合作！

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 HackTricks 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>
