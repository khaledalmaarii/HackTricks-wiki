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

然后，选择将存储在TCC系统范围的数据库中，路径为**`/Library/Application Support/com.apple.TCC/TCC.db`**，或者对于每个用户的偏好设置，路径为**`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**。这些数据库受到SIP（系统完整性保护）的保护，但您可以读取它们。

{% hint style="danger" %}
在iOS中，TCC数据库位于**`/private/var/mobile/Library/TCC/TCC.db`**
{% endhint %}

还有一个第三个TCC数据库位于**`/var/db/locationd/clients.plist`**，用于指示允许访问位置服务的客户端。

此外，具有**完全磁盘访问权限**的进程可以编辑用户模式数据库。现在，应用程序还需要FDA（完全磁盘访问权限）来读取数据库。

{% hint style="info" %}
**通知中心UI**可以对系统TCC数据库进行更改：

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
{% tab title="系统数据库" %}
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

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{% endtab %}
{% endtabs %}

{% hint style="success" %}
检查这两个数据库，您可以查看应用程序允许、禁止或未拥有的权限（它会要求获取权限）。
{% endhint %}

* **`auth_value`** 可以有不同的值：denied(0)、unknown(1)、allowed(2)或limited(3)。
* **`auth_reason`** 可以有以下值：Error(1)、User Consent(2)、User Set(3)、System Set(4)、Service Policy(5)、MDM Policy(6)、Override Policy(7)、Missing usage string(8)、Prompt Timeout(9)、Preflight Unknown(10)、Entitled(11)、App Type Policy(12)。
* 有关表格的**其他字段**的更多信息，请参阅[**此博客文章**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)。

{% hint style="info" %}
一些 TCC 权限包括：kTCCServiceAppleEvents、kTCCServiceCalendar、kTCCServicePhotos... 没有公共列表定义了所有这些权限，但您可以查看此[**已知权限列表**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service)。

**完全磁盘访问**的名称是**`kTCCServiceSystemPolicyAllFiles`**，**`kTCCServiceAppleEvents`** 允许应用程序向常用于**自动化任务**的其他应用程序发送事件。此外，**`kTCCServiceSystemPolicySysAdminFiles`** 允许更改用户的 **`NFSHomeDirectory`** 属性，从而更改其主文件夹，因此可以**绕过 TCC**。
{% endhint %}

您还可以在`系统偏好设置 --> 安全性与隐私 --> 隐私 --> 文件和文件夹`中检查已授予应用程序的权限。

{% hint style="success" %}
请注意，即使其中一个数据库位于用户的主目录中，**由于 SIP 的限制，用户无法直接修改这些数据库**（即使您是 root）。配置或修改新规则的唯一方法是通过系统偏好设置窗格或应用程序询问用户时。

但是，请记住，用户可以使用 **`tccutil`** **删除或查询规则**。&#x20;
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

然而，对于应用程序访问某些用户文件夹（例如`~/Desktop`，`~/Downloads`和`~/Documents`）并不需要具备任何特定的权限。系统会透明地处理访问并根据需要提示用户。

苹果的应用程序不会生成提示。它们在其权限列表中包含预授予权限，这意味着它们永远不会生成弹出窗口，也不会出现在任何TCC数据库中。例如：
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
除了一些关于权限的官方文档外，还可以在[https://newosxbook.com/ent.jl](https://newosxbook.com/ent.jl)找到一些非官方的**有关权限的有趣信息**。
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
有趣的是，**`com.apple.macl`**属性由**沙箱**管理，而不是tccd。

还要注意，如果将允许计算机上某个应用程序的UUID的文件移动到另一台计算机上，因为相同的应用程序将具有不同的UID，它不会授予对该应用程序的访问权限。
{% endhint %}

扩展属性`com.apple.macl`无法像其他扩展属性一样清除，因为它受到SIP的保护。然而，正如[**在这篇文章中解释的**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)，可以通过将文件**压缩**、**删除**和**解压缩**来禁用它。

### TCC绕过

{% content-ref url="macos-tcc-bypasses/" %}
[macos-tcc-bypasses](macos-tcc-bypasses/)
{% endcontent-ref %}

## 参考资料

* [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
* [**https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command**](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
*   [**https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品](https://opensea.io/collection/the-peass-family)——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
