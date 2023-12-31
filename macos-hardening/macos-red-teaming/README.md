# macOS 红队行动

<details>

<summary><strong>从零开始学习 AWS 黑客攻击直到成为英雄</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果你想在 HackTricks 中看到你的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs**](https://opensea.io/collection/the-peass-family) 收藏
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享你的黑客技巧。

</details>

## 滥用 MDMs

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

如果你设法**获取管理员凭据**以访问管理平台，你可以通过在机器上分发你的恶意软件来**潜在地危害所有计算机**。

对于 MacOS 环境的红队行动，强烈建议了解 MDMs 的工作原理：

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### 将 MDM 作为 C2 使用

MDM 将有权限安装、查询或移除配置文件，安装应用程序，创建本地管理员账户，设置固件密码，更改 FileVault 密钥等...

为了运行你自己的 MDM，你需要**由供应商签名的 CSR**，你可以尝试使用 [**https://mdmcert.download/**](https://mdmcert.download/) 来获取。并且，为了运行你自己的苹果设备 MDM，你可以使用 [**MicroMDM**](https://github.com/micromdm/micromdm)。

然而，要在已注册的设备上安装应用程序，你仍然需要它由开发者账户签名... 但是，在 MDM 注册时，**设备会将 MDM 的 SSL 证书添加为受信任的 CA**，所以你现在可以签署任何东西。

要在 MDM 中注册设备，你需要以 root 身份安装 **`mobileconfig`** 文件，这可以通过 **pkg** 文件传递（你可以将其压缩成 zip，当从 safari 下载时它将被解压缩）。

**Mythic 代理 Orthrus** 使用了这种技术。

### 滥用 JAMF PRO

JAMF 可以运行**自定义脚本**（由系统管理员开发的脚本）、**原生负载**（本地账户创建、设置 EFI 密码、文件/进程监控...）和**MDM**（设备配置、设备证书...）。

#### JAMF 自助注册

访问如 `https://<company-name>.jamfcloud.com/enroll/` 的页面，查看他们是否**启用了自助注册**。如果启用了，可能会**要求凭据以访问**。

你可以使用脚本 [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) 来执行密码喷涂攻击。

此外，在找到合适的凭据后，你可以使用以下表单来暴力破解其他用户名：

![](<../../.gitbook/assets/image (7) (1) (1).png>)

#### JAMF 设备认证

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

**`jamf`** 二进制文件包含了打开钥匙链的秘密，当时的发现是**共享**给每个人的，它是：**`jk23ucnq91jfu9aj`**。\
此外，jamf 作为 **LaunchDaemon** **持久存在**于 **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### JAMF 设备接管

**JSS**（Jamf 软件服务器）**URL**，**`jamf`** 将使用位于 **`/Library/Preferences/com.jamfsoftware.jamf.plist`**。\
这个文件基本上包含了 URL：

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
{% endcode %}

因此，攻击者可以放置一个恶意包（`pkg`），在安装时**覆盖这个文件**，将**URL设置为Mythic C2监听器，来自Typhon代理**，现在可以滥用JAMF作为C2。

{% code overflow="wrap" %}
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### JAMF 伪装

为了**伪装设备与JMF通信**，你需要：

* 设备的**UUID**：`ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* **JAMF 密钥链**，位置在：`/Library/Application\ Support/Jamf/JAMF.keychain`，其中包含设备证书

有了这些信息，**创建一个虚拟机**，使用**窃取的**硬件**UUID**，并且**禁用SIP**，放置**JAMF 密钥链**，**挂钩**Jamf **代理**并窃取其信息。

#### 秘密窃取

<figure><img src="../../.gitbook/assets/image (11).png" alt=""><figcaption><p>a</p></figcaption></figure>

你也可以监控位置 `/Library/Application Support/Jamf/tmp/`，管理员可能想通过Jamf执行的**自定义脚本**会**放置在这里，执行后删除**。这些脚本**可能包含凭证**。

然而，**凭证**可能作为**参数**传递给这些脚本，所以你需要监控 `ps aux | grep -i jamf`（甚至不需要root权限）。

脚本 [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) 可以监听新文件的添加和新进程参数。

### macOS 远程访问

还有关于**MacOS** "特殊" **网络** **协议**：

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

有时你会发现**MacOS计算机连接到了AD**。在这种情况下，你应该尝试像平时一样**枚举**活动目录。在以下页面中找到一些**帮助**：

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

一些可能也会对你有帮助的**本地MacOS工具**是 `dscl`：
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
以下是为MacOS准备的一些工具，它们可以自动枚举AD并与kerberos交互：

* [**Machound**](https://github.com/XMCyber/MacHound): MacHound是Bloodhound审计工具的扩展，允许收集和摄取MacOS主机上的Active Directory关系。
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost是一个Objective-C项目，旨在与macOS上的Heimdal krb5 API交互。该项目的目标是使用原生API在macOS设备上进行更好的Kerberos安全测试，而无需在目标上安装任何其他框架或包。
* [**Orchard**](https://github.com/its-a-feature/Orchard): JavaScript for Automation (JXA)工具，用于执行Active Directory枚举。

### 域信息
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### 用户

MacOS的三种用户类型包括：

* **本地用户** — 由本地OpenDirectory服务管理，它们与Active Directory没有任何连接。
* **网络用户** — 易变的Active Directory用户，需要连接到DC服务器进行认证。
* **移动用户** — 拥有本地备份其凭证和文件的Active Directory用户。

关于用户和组的本地信息存储在 _/var/db/dslocal/nodes/Default_ 文件夹中。\
例如，名为 _mark_ 的用户信息存储在 _/var/db/dslocal/nodes/Default/users/mark.plist_ 中，而 _admin_ 组的信息在 _/var/db/dslocal/nodes/Default/groups/admin.plist_ 中。

除了使用HasSession和AdminTo边缘之外，**MacHound为Bloodhound数据库添加了三个新的边缘**：

* **CanSSH** - 允许SSH到主机的实体
* **CanVNC** - 允许VNC到主机的实体
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
更多信息请访问 [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

## 访问钥匙串

钥匙串很可能包含敏感信息，如果在不产生提示的情况下访问，可能有助于推进红队行动：

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## 外部服务

MacOS红队行动与常规Windows红队行动不同，通常**MacOS直接与多个外部平台集成**。MacOS的常见配置是使用**OneLogin同步凭证访问计算机，并通过OneLogin访问多个外部服务**（如github, aws等）：

![](<../../.gitbook/assets/image (563).png>)

## 杂项红队技术

### Safari

在Safari中下载文件时，如果是“安全”的文件，将会**自动打开**。例如，如果你**下载了一个zip文件**，它将自动解压缩：

<figure><img src="../../.gitbook/assets/image (12) (3).png" alt=""><figcaption></figcaption></figure>

## 参考资料

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击！</strong></summary>

支持HackTricks的其他方式：

* 如果您希望在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>
