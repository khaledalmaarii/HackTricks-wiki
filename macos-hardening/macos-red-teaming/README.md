# macOS 红队

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS 红队专家）</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想看到您的**公司在 HackTricks 中做广告**或**下载 PDF 版本的 HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFT**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live) 上**关注**我们。
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧**。

</details>

## 滥用 MDM

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

如果您设法**获取管理员凭据**以访问管理平台，则可以通过在计算机上分发恶意软件来**潜在地危害所有计算机**。

在 MacOS 环境中进行红队行动时，强烈建议了解 MDM 的工作原理：

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### 将 MDM 用作 C2

MDM 将获得安装、查询或删除配置文件的权限，安装应用程序，创建本地管理员帐户，设置固件密码，更改 FileVault 密钥...

为了运行您自己的 MDM，您需要**由供应商签署的 CSR**，您可以尝试使用 [**https://mdmcert.download/**](https://mdmcert.download/) 获取。要为 Apple 设备运行自己的 MDM，您可以使用 [**MicroMDM**](https://github.com/micromdm/micromdm)。

但是，要在已注册设备上安装应用程序，仍然需要由开发人员帐户签名... 但是，在 MDM 注册后，**设备将 MDM 的 SSL 证书添加为受信任的 CA**，因此现在您可以签署任何内容。

要将设备注册到 MDM，您需要以 root 身份安装一个**`mobileconfig`** 文件，该文件可以通过 **pkg** 文件交付（您可以将其压缩为 zip 文件，当从 Safari 下载时，它将被解压缩）。

**Mythic 代理 Orthrus** 使用了这种技术。

### 滥用 JAMF PRO

JAMF 可以运行**自定义脚本**（由系统管理员开发的脚本），**本机负载**（本地帐户创建，设置 EFI 密码，文件/进程监视...）和**MDM**（设备配置，设备证书...）。

#### JAMF 自注册

转到诸如 `https://<company-name>.jamfcloud.com/enroll/` 这样的页面，查看他们是否已启用**自注册**。如果启用了，可能会**要求输入凭据进行访问**。

您可以使用脚本 [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) 执行密码喷洒攻击。

此外，在找到适当的凭据后，您可能能够使用下一个表单暴力破解其他用户名：

![](<../../.gitbook/assets/image (7) (1) (1).png>)

#### JAMF 设备认证

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

**`jamf`** 二进制文件包含打开钥匙串的秘密，在发现时**共享**给所有人，即：**`jk23ucnq91jfu9aj`**。\
此外，jamf 作为**LaunchDaemon** 持久存在于 **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### JAMF 设备接管

**`jamf`** 将使用的 **JSS**（Jamf 软件服务器）**URL** 位于 **`/Library/Preferences/com.jamfsoftware.jamf.plist`**。\
该文件基本上包含 URL：

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
攻击者可以放置一个恶意软件包（`pkg`），在安装时覆盖这个文件，将**URL设置为从Typhon代理到Mythic C2监听器**，从而可以滥用JAMF作为C2。
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### JAMF模拟

为了**模拟**设备与JMF之间的通信，您需要：

* 设备的**UUID**：`ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* 来自`/Library/Application\ Support/Jamf/JAMF.keychain`的**JAMF钥匙链**，其中包含设备证书

有了这些信息，**创建一个虚拟机**，使用**窃取的**硬件**UUID**，并且**禁用SIP**，然后放置**JAMF钥匙链**，**挂钩**Jamf **代理**并窃取其信息。

#### 秘密窃取

<figure><img src="../../.gitbook/assets/image (11).png" alt=""><figcaption><p>a</p></figcaption></figure>

您还可以监视位置`/Library/Application Support/Jamf/tmp/`，因为**管理员**可能希望通过Jamf执行**自定义脚本**，这些脚本会在此处**放置、执行和删除**。这些脚本**可能包含凭据**。

但是，**凭据**可能会作为**参数**传递给这些脚本，因此您需要监视`ps aux | grep -i jamf`（甚至不需要root权限）。

脚本[**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py)可以监听新添加的文件和新的进程参数。

### macOS远程访问

还有关于**MacOS**“特殊”的**网络** **协议**：

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

在某些情况下，您会发现**MacOS计算机连接到AD**。在这种情况下，您应该尝试像往常一样**枚举**活动目录。在以下页面中找到一些帮助：

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

一些**本地MacOS工具**也可能对您有所帮助，如`dscl`：
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
还有一些针对 MacOS 准备的工具，可以自动枚举 AD 并与 kerberos 进行交互：

- [**Machound**](https://github.com/XMCyber/MacHound)：MacHound 是 Bloodhound 审计工具的扩展，允许在 MacOS 主机上收集和摄入 Active Directory 关系。
- [**Bifrost**](https://github.com/its-a-feature/bifrost)：Bifrost 是一个 Objective-C 项目，旨在与 macOS 上的 Heimdal krb5 API 进行交互。该项目的目标是利用本机 API 在 macOS 设备上实现更好的 Kerberos 安全测试，而无需在目标设备上安装任何其他框架或软件包。
- [**Orchard**](https://github.com/its-a-feature/Orchard)：用于执行 Active Directory 枚举的 JavaScript for Automation (JXA) 工具。

### 域信息
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### 用户

MacOS 有三种类型的用户：

- **本地用户** — 由本地 OpenDirectory 服务管理，与 Active Directory 没有任何连接。
- **网络用户** — 需要连接到 DC 服务器进行身份验证的易失性 Active Directory 用户。
- **移动用户** — 具有本地备份以供其凭据和文件的 Active Directory 用户。

关于用户和组的本地信息存储在文件夹 _/var/db/dslocal/nodes/Default_ 中。\
例如，名为 _mark_ 的用户的信息存储在 _/var/db/dslocal/nodes/Default/users/mark.plist_，组 _admin_ 的信息存储在 _/var/db/dslocal/nodes/Default/groups/admin.plist_ 中。

除了使用 HasSession 和 AdminTo 边缘外，**MacHound 还向 Bloodhound 数据库添加了三个新边缘**：

- **CanSSH** - 允许 SSH 到主机的实体
- **CanVNC** - 允许 VNC 到主机的实体
- **CanAE** - 允许在主机上执行 AppleEvent 脚本的实体
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
更多信息请参考[https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

## 访问钥匙串

钥匙串很可能包含敏感信息，如果在不生成提示的情况下访问，可能有助于推动红队演练的进行：

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## 外部服务

MacOS红队行动与常规Windows红队行动不同，因为通常**MacOS直接集成了几个外部平台**。 MacOS的常见配置是使用**OneLogin同步凭据访问计算机，并通过OneLogin访问多个外部服务**（如github、aws等）。

## 其他红队技术

### Safari

在Safari中下载文件时，如果是一个“安全”文件，它将会**自动打开**。例如，如果你**下载一个zip文件**，它将会自动解压缩：

<figure><img src="../../.gitbook/assets/image (12) (3).png" alt=""><figcaption></figcaption></figure>

## 参考资料

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)
