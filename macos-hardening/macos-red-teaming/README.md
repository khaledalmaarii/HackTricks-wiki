# macOS红队行动

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 滥用MDM

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

如果你成功**获取管理员凭证**以访问管理平台，你可以通过在机器上分发恶意软件来**潜在地控制所有计算机**。

在MacOS环境中进行红队行动时，强烈建议对MDM的工作原理有一定的了解：

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### 将MDM用作C2

MDM将具有安装、查询或删除配置文件、安装应用程序、创建本地管理员帐户、设置固件密码、更改FileVault密钥的权限...

为了运行自己的MDM，你需要**使用供应商签名的CSR**，你可以尝试通过[**https://mdmcert.download/**](https://mdmcert.download/)获取。要在Apple设备上运行自己的MDM，可以使用[**MicroMDM**](https://github.com/micromdm/micromdm)。

然而，要在已注册的设备上安装应用程序，你仍然需要使用开发者帐户进行签名...然而，在MDM注册时，**设备将MDM的SSL证书添加为受信任的CA**，因此现在你可以签署任何内容。

要将设备注册到MDM中，你需要以root身份安装一个**`mobileconfig`**文件，可以通过**pkg**文件传递（你可以将其压缩为zip文件，当从safari下载时，它将被解压缩）。

**Mythic agent Orthrus**使用了这种技术。

### 滥用JAMF PRO

JAMF可以运行**自定义脚本**（由系统管理员开发的脚本）、**本地负载**（创建本地帐户、设置EFI密码、文件/进程监视...）和**MDM**（设备配置、设备证书...）。

#### JAMF自注册

访问类似`https://<company-name>.jamfcloud.com/enroll/`的页面，查看是否启用了**自注册**。如果启用了，可能会**要求提供凭据**。

你可以使用脚本[**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py)进行密码喷洒攻击。

此外，在找到适当的凭证后，你可以使用下面的表单暴力破解其他用户名：

![](<../../.gitbook/assets/image (7) (1).png>)

#### JAMF设备认证

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

**`jamf`**二进制文件包含了打开钥匙串的秘密，该秘密在发现时是**共享**的，它是：**`jk23ucnq91jfu9aj`**。\
此外，jamf作为一个**LaunchDaemon**在**`/Library/LaunchAgents/com.jamf.management.agent.plist`**中持久存在。

#### 接管JAMF设备

**`jamf`**将使用的**JSS**（Jamf软件服务器）**URL**位于**`/Library/Preferences/com.jamfsoftware.jamf.plist`**中。\
该文件基本上包含了URL：

{% code overflow="wrap" %}
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://halbornasd.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
所以，攻击者可以放置一个恶意的软件包（`pkg`），当安装时覆盖这个文件，将URL设置为来自Typhon代理的Mythic C2监听器，从而能够滥用JAMF作为C2。
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### JAMF冒充

为了冒充设备与JMF之间的通信，您需要：

* 设备的UUID：`ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* JAMF密钥链：`/Library/Application\ Support/Jamf/JAMF.keychain`，其中包含设备证书

有了这些信息，使用**窃取的**硬件**UUID**创建一个禁用SIP的虚拟机，将**JAMF密钥链**放入其中，**hook** Jamf代理并窃取其信息。

#### 秘密窃取

<figure><img src="../../.gitbook/assets/image (11).png" alt=""><figcaption><p>a</p></figcaption></figure>

您还可以监视位置`/Library/Application Support/Jamf/tmp/`，以便管理员可能希望通过Jamf执行的**自定义脚本**，因为它们会**放置在这里，执行并删除**。这些脚本**可能包含凭据**。

但是，**凭据**可能作为**参数**传递给这些脚本，因此您需要监视`ps aux | grep -i jamf`（甚至不需要root权限）。

脚本[**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py)可以监听新添加的文件和新的进程参数。

### macOS远程访问

还有关于**MacOS**的“特殊”**网络****协议**的信息：

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

在某些情况下，您会发现**MacOS计算机连接到AD**。在这种情况下，您应该尝试像往常一样枚举活动目录。在以下页面中找到一些帮助：

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

一些可能对您有所帮助的**本地MacOS工具**是`dscl`：
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
此外，还有一些针对MacOS的工具可用于自动枚举AD并与Kerberos进行交互：

* [**Machound**](https://github.com/XMCyber/MacHound)：MacHound是Bloodhound审计工具的扩展，允许在MacOS主机上收集和摄取Active Directory关系。
* [**Bifrost**](https://github.com/its-a-feature/bifrost)：Bifrost是一个Objective-C项目，旨在与macOS上的Heimdal krb5 API进行交互。该项目的目标是使用本机API在macOS设备上实现更好的Kerberos安全测试，而无需在目标上安装任何其他框架或软件包。
* [**Orchard**](https://github.com/its-a-feature/Orchard)：用于执行Active Directory枚举的JavaScript for Automation (JXA)工具。

### 域信息
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### 用户

MacOS有三种类型的用户：

* **本地用户** - 由本地OpenDirectory服务管理，与Active Directory没有任何连接。
* **网络用户** - 需要连接到DC服务器进行身份验证的易失性Active Directory用户。
* **移动用户** - 具有本地备份凭据和文件的Active Directory用户。

关于用户和组的本地信息存储在文件夹_/var/db/dslocal/nodes/Default_中。\
例如，名为_mark_的用户的信息存储在_/var/db/dslocal/nodes/Default/users/mark.plist_中，名为_admin_的组的信息存储在_/var/db/dslocal/nodes/Default/groups/admin.plist_中。

除了使用HasSession和AdminTo边缘外，**MacHound向Bloodhound数据库添加了三个新的边缘**：

* **CanSSH** - 允许SSH连接到主机的实体
* **CanVNC** - 允许VNC连接到主机的实体
* **CanAE** - 允许在主机上执行AppleEvent脚本的实体
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
更多信息请参见[https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

## 访问钥匙串

钥匙串很可能包含敏感信息，如果在不生成提示的情况下访问，可以帮助推进红队行动：

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## 外部服务

MacOS红队行动与常规的Windows红队行动不同，通常**MacOS直接与多个外部平台集成**。MacOS的常见配置是使用**OneLogin同步凭据访问计算机，并通过OneLogin访问多个外部服务**（如github、aws...）：

![](<../../.gitbook/assets/image (563).png>)

## 杂项红队技术

### Safari

在Safari中下载文件时，如果是“安全”文件，它将被**自动打开**。因此，例如，如果您**下载一个zip文件**，它将被自动解压缩：

<figure><img src="../../.gitbook/assets/image (12) (3).png" alt=""><figcaption></figcaption></figure>

## 参考资料

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**为你的公司做广告**吗？或者你想要**获取最新版本的PEASS或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品](https://opensea.io/collection/the-peass-family)——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
