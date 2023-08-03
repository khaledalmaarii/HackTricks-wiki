# macOS沙盒

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 基本信息

MacOS沙盒（最初称为Seatbelt）**限制在沙盒内运行的应用程序**只能执行沙盒配置文件中指定的允许操作。这有助于确保**应用程序只能访问预期的资源**。

任何具有**`com.apple.security.app-sandbox`**权限的应用程序都将在沙盒内执行。**Apple二进制文件**通常在沙盒内执行，并且为了在**App Store**中发布，**此权限是强制性的**。因此，大多数应用程序将在沙盒内执行。

为了控制进程可以执行的操作，**沙盒在内核中的所有系统调用中都有钩子**。根据应用程序的**权限**，沙盒将**允许**特定的操作。

沙盒的一些重要组件包括：

* 内核扩展`/System/Library/Extensions/Sandbox.kext`
* 私有框架`/System/Library/PrivateFrameworks/AppSandbox.framework`
* 在用户空间运行的**守护进程**`/usr/libexec/sandboxd`
* **容器**`~/Library/Containers`

在容器文件夹中，你可以找到**每个在沙盒中执行的应用程序的文件夹**，文件夹的名称是bundle id：
```bash
ls -l ~/Library/Containers
total 0
drwx------@ 4 username  staff  128 May 23 20:20 com.apple.AMPArtworkAgent
drwx------@ 4 username  staff  128 May 23 20:13 com.apple.AMPDeviceDiscoveryAgent
drwx------@ 4 username  staff  128 Mar 24 18:03 com.apple.AVConference.Diagnostic
drwx------@ 4 username  staff  128 Mar 25 14:14 com.apple.Accessibility-Settings.extension
drwx------@ 4 username  staff  128 Mar 25 14:10 com.apple.ActionKit.BundledIntentHandler
[...]
```
在每个bundle id文件夹中，您可以找到应用程序的**plist**和**Data目录**：
```bash
cd /Users/username/Library/Containers/com.apple.Safari
ls -la
total 104
drwx------@   4 username  staff    128 Mar 24 18:08 .
drwx------  348 username  staff  11136 May 23 20:57 ..
-rw-r--r--    1 username  staff  50214 Mar 24 18:08 .com.apple.containermanagerd.metadata.plist
drwx------   13 username  staff    416 Mar 24 18:05 Data

ls -l Data
total 0
drwxr-xr-x@  8 username  staff   256 Mar 24 18:08 CloudKit
lrwxr-xr-x   1 username  staff    19 Mar 24 18:02 Desktop -> ../../../../Desktop
drwx------   2 username  staff    64 Mar 24 18:02 Documents
lrwxr-xr-x   1 username  staff    21 Mar 24 18:02 Downloads -> ../../../../Downloads
drwx------  35 username  staff  1120 Mar 24 18:08 Library
lrwxr-xr-x   1 username  staff    18 Mar 24 18:02 Movies -> ../../../../Movies
lrwxr-xr-x   1 username  staff    17 Mar 24 18:02 Music -> ../../../../Music
lrwxr-xr-x   1 username  staff    20 Mar 24 18:02 Pictures -> ../../../../Pictures
drwx------   2 username  staff    64 Mar 24 18:02 SystemData
drwx------   2 username  staff    64 Mar 24 18:02 tmp
```
{% hint style="danger" %}
请注意，即使符号链接存在以便从沙盒中"逃脱"并访问其他文件夹，应用程序仍然需要**具有权限**来访问它们。这些权限在**`.plist`**文件中。
{% endhint %}
```bash
# Get permissions
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# In this file you can find the entitlements:
<key>Entitlements</key>
<dict>
<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
<true/>
<key>com.apple.accounts.appleaccount.fullaccess</key>
<true/>
<key>com.apple.appattest.spi</key>
<true/>
[...]

# Some parameters
<key>Parameters</key>
<dict>
<key>_HOME</key>
<string>/Users/username</string>
<key>_UID</key>
<string>501</string>
<key>_USER</key>
<string>username</string>
[...]

# The paths it can access
<key>RedirectablePaths</key>
<array>
<string>/Users/username/Downloads</string>
<string>/Users/username/Documents</string>
<string>/Users/username/Library/Calendars</string>
<string>/Users/username/Desktop</string>
[...]
```
### 沙盒配置文件

沙盒配置文件是指示在该沙盒中允许/禁止的配置文件。它使用沙盒配置语言（SBPL），该语言使用[Scheme](https://en.wikipedia.org/wiki/Scheme_\(programming_language\))编程语言。

这里是一个示例：
```scheme
(version 1) ; First you get the version

(deny default) ; Then you shuold indicate the default action when no rule applies

(allow network*) ; You can use wildcards and allow everything

(allow file-read* ; You can specify where to apply the rule
(subpath "/Users/username/")
(literal "/tmp/afile")
(regex #"^/private/etc/.*")
)

(allow mach-lookup
(global-name "com.apple.analyticsd")
)
```
{% hint style="success" %}
查看这个[**研究**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **以了解更多可能被允许或拒绝的操作。**
{% endhint %}

重要的**系统服务**也在它们自己的自定义**沙盒**中运行，例如`mdnsresponder`服务。您可以在以下位置查看这些自定义**沙盒配置文件**：

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**&#x20;
* 其他沙盒配置文件可以在[https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles)中进行检查。

**App Store**应用程序使用**配置文件** **`/System/Library/Sandbox/Profiles/application.sb`**。您可以在此配置文件中查看诸如**`com.apple.security.network.server`**的权限如何允许进程使用网络。

SIP是一个名为platform\_profile的沙盒配置文件，位于/System/Library/Sandbox/rootless.conf

### 沙盒配置文件示例

要使用**特定的沙盒配置文件**启动应用程序，可以使用：
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% code title="touch.sb" %}

```plaintext
(version 1)
(deny default)
(allow file-read-metadata)
(allow file-write-metadata)
(allow file-read-data (literal "/private/var/tmp/"))
(allow file-write-data (literal "/private/var/tmp/"))
(allow file-read-data (regex #"^/private/var/folders/[^/]+/[^/]+/[C,T]/"))
(allow file-write-data (regex #"^/private/var/folders/[^/]+/[^/]+/[C,T]/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/C/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/C/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/T/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/T/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/C/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/C/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/T/C/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/T/C/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/T/C/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/T/C/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/C/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/C/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/T/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/T/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/T/T/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/T/T/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/C/T/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/C/T/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/T/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/T/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/T/C/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/T/C/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/T/C/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/T/C/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/C/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/C/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/T/T/C/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/T/T/C/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/T/T/C/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/T/T/C/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/T/C/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/T/C/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/C/T/C/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/C/T/C/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/C/C/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/C/C/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/T/T/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/T/T/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/T/T/T/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/T/T/T/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/C/T/T/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/C/T/T/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/T/T/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/T/T/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/T/C/T/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/T/C/T/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/T/C/T/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/T/C/T/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/C/T/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/C/T/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/T/T/C/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/T/T/C/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/T/T/C/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/T/T/C/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/T/C/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/T/C/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/C/T/C/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/C/T/C/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/C/C/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/C/C/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/T/T/T/C/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/T/T/T/C/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/T/T/T/C/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/T/T/T/C/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/C/T/T/C/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/C/T/T/C/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/T/T/C/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/T/T/C/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/T/C/T/C/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/T/C/T/C/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/T/C/T/C/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/T/C/T/C/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/C/T/C/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/C/T/C/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/T/T/C/T/C/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/T/T/C/T/C/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/T/T/C/T/C/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/T/T/C/T/C/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/T/C/T/C/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/T/C/T/C/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/C/T/C/T/C/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/C/T/C/T/C/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/C/C/C/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/C/C/C/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/T/T/T/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/T/T/T/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/T/T/T/T/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/T/T/T/T/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/C/T/T/T/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/C/T/T/T/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/T/T/T/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/T/T/T/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/T/C/T/T/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/T/C/T/T/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/T/C/T/T/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/T/C/T/T/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/C/T/T/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/C/T/T/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/T/T/C/T/T/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/T/T/C/T/T/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/T/T/C/T/T/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/T/T/C/T/T/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/T/C/T/T/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/C/C/T/C/T/T/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/C/T/C/T/T/T/"))
(allow file-write-data (literal "/private/var/folders/[^/]+/[^/]+/[^/]+/T/C/T/C/T/T/T/"))
(allow file-read-data (literal "/private/var/folders/[^/]+/[^/]+/
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```
{% endcode %}
```bash
# This will fail because default is denied, so it cannot execute touch
sandbox-exec -f touch.sb touch /tmp/hacktricks.txt
# Check logs
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
[...]
2023-05-26 13:42:44.136082+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) process-exec* /usr/bin/touch
2023-05-26 13:42:44.136100+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /usr/bin/touch
2023-05-26 13:42:44.136321+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
2023-05-26 13:42:52.701382+0200  localhost kernel[0]: (Sandbox) 5 duplicate reports for Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
[...]
```
{% code title="touch2.sb" %}

```plaintext
;; touch2.sb
;; Sandbox profile for the touch2 command

(version 1)
(deny default)

(allow file-write*
    (literal "/tmp/evilfile.txt"))

(allow file-read-data
    (literal "/etc/passwd"))

(allow file-read-metadata
    (literal "/usr/share/misc/magic"))

(allow file-read-metadata
    (regex #"^/usr/share/locale/[^/]+/LC_.*"))

(allow file-read-metadata
    (regex #"^/usr/share/terminfo/[^/]+/[^/]+$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/[^/]+/[^/]+$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/zone.tab$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/iso3166.tab$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/leap-seconds.list$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/leapseconds$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zoneinfo/tzdata.zi$"))

(allow file-read-metadata
    (regex #"^/usr/share/zone
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
; This will also fail because:
; 2023-05-26 13:44:59.840002+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/bin/touch
; 2023-05-26 13:44:59.840016+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin/touch
; 2023-05-26 13:44:59.840028+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin
; 2023-05-26 13:44:59.840034+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/lib/dyld
; 2023-05-26 13:44:59.840050+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) sysctl-read kern.bootargs
; 2023-05-26 13:44:59.840061+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /
```
{% code title="touch3.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% hint style="info" %}
请注意，运行在**Windows**上的**由Apple编写的软件**没有额外的安全预防措施，比如应用程序沙箱。
{% endhint %}

绕过示例：

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)（他们能够在沙箱之外写入以`~$`开头的文件）。

### 调试和绕过沙箱

**在macOS上，进程不会自动进入沙箱：与iOS不同**，在iOS上，沙箱是在程序的第一条指令执行之前由内核应用的，而在macOS上，**进程必须选择将自己置于沙箱中**。

如果进程具有`com.apple.security.app-sandbox`权限，则在启动时，进程会自动从用户空间进入沙箱。有关此过程的详细说明，请参见：

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **检查PID权限**

根据[这个视频](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s)，**`sandbox_check`**（它是一个`__mac_syscall`）可以检查特定PID中的沙箱是否允许执行某个操作。

[**工具sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c)可以检查PID是否可以执行某个操作：
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### 在App Store应用中使用自定义SBPL

公司有可能使他们的应用程序运行在**自定义沙盒配置文件**下（而不是默认配置文件）。他们需要使用授权的权限**`com.apple.security.temporary-exception.sbpl`**，该权限需要经过苹果授权。

可以在**`/System/Library/Sandbox/Profiles/application.sb:`**中检查此权限的定义。
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
这将**在此权限之后评估字符串**作为沙盒配置文件。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取最新版本的PEASS或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
