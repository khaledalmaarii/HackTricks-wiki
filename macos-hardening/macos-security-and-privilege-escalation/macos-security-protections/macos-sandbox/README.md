# macOS沙盒

<details>

<summary><strong>从零开始学习AWS黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 基本信息

macOS沙盒（最初称为Seatbelt）**限制在沙盒内运行的应用程序**只能执行应用程序正在使用的沙盒配置文件中**指定的允许操作**。这有助于确保**应用程序只访问预期的资源**。

任何具有**权限** **`com.apple.security.app-sandbox`** 的应用都将在沙盒内执行。**苹果二进制文件**通常在沙盒内执行，为了在**App Store**内发布，**这个权限是强制性的**。因此，大多数应用程序将在沙盒内执行。

为了控制进程可以或不可以做什么，**沙盒在内核的所有系统调用中都有钩子**。**根据**应用程序的**权限**，沙盒将**允许**某些操作。

沙盒的一些重要组件包括：

* **内核扩展** `/System/Library/Extensions/Sandbox.kext`
* **私有框架** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* 在用户空间运行的**守护进程** `/usr/libexec/sandboxd`
* **容器** `~/Library/Containers`

在容器文件夹内，您可以找到**每个在沙盒中执行的应用的文件夹**，名称为捆绑标识符：
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
在每个bundle id文件夹中，你可以找到App的**plist**和**Data directory**：
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
请注意，即使存在符号链接（symlinks）用于“逃离”沙盒并访问其他文件夹，应用程序仍然需要**拥有权限**来访问它们。这些权限位于**`.plist`**文件内。
{% endhint %}
```bash
# Get permissions
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# Binary sandbox profile
<key>SandboxProfileData</key>
<data>
AAAhAboBAAAAAAgAAABZAO4B5AHjBMkEQAUPBSsGPwsgASABHgEgASABHwEf...

# In this file you can find the entitlements:
<key>Entitlements</key>
<dict>
<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
<true/>
<key>com.apple.accounts.appleaccount.fullaccess</key>
<true/>
<key>com.apple.appattest.spi</key>
<true/>
<key>keychain-access-groups</key>
<array>
<string>6N38VWS5BX.ru.keepcoder.Telegram</string>
<string>6N38VWS5BX.ru.keepcoder.TelegramShare</string>
</array>
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
<key>RedirectedPaths</key>
<array/>
[...]
```
{% hint style="warning" %}
所有由沙盒应用程序创建/修改的内容都会获得**隔离属性**。这将通过触发Gatekeeper来防止沙盒空间在尝试用**`open`**执行某些操作时。
{% endhint %}

### 沙盒配置文件

沙盒配置文件是指示在该**沙盒**中什么是**允许/禁止**的配置文件。它使用了**沙盒配置文件语言（SBPL）**，该语言使用了[**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\))编程语言。

以下是一个例子：
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
查看这篇[**研究**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/)，以了解更多可能被允许或拒绝的操作。
{% endhint %}

重要的**系统服务**也在它们自己的定制**沙盒**中运行，例如 `mdnsresponder` 服务。您可以在以下位置查看这些定制的**沙盒配置文件**：

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**&#x20;
* 其他沙盒配置文件可以在 [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles) 查看。

**App Store** 应用使用**配置文件** **`/System/Library/Sandbox/Profiles/application.sb`**。您可以在此配置文件中检查，例如 **`com.apple.security.network.server`** 这样的权限是如何允许进程使用网络的。

SIP 是一个名为 platform\_profile 的沙盒配置文件，在 /System/Library/Sandbox/rootless.conf 中

### 沙盒配置文件示例

要用**特定沙盒配置文件**启动应用程序，您可以使用：
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% tabs %}
{% tab title="touch" %}
{% code title="touch.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```
Since there is no content provided between the `{% endcode %}` tags, there is nothing to translate. Please provide the relevant English text that you would like to have translated into Chinese.
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
{% endcode %}

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
请注意，运行在 **Windows** 上的 **Apple** **软件** **没有额外的安全预防措施**，例如应用程序沙盒化。
{% endhint %}

绕过示例：

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (它们能够写入沙盒外部，文件名以 `~$` 开头的文件)。

### MacOS 沙盒配置文件

macOS 在两个位置存储系统沙盒配置文件：**/usr/share/sandbox/** 和 **/System/Library/Sandbox/Profiles**。

如果第三方应用程序携带 **com.apple.security.app-sandbox** 权限，系统会将 **/System/Library/Sandbox/Profiles/application.sb** 配置文件应用到该进程。

### **iOS 沙盒配置文件**

默认配置文件称为 **container**，我们没有 SBPL 文本表示形式。在内存中，这个沙盒以允许/拒绝二叉树的形式表示每个来自沙盒的权限。

### 调试与绕过沙盒

**macOS 上的进程不是天生就在沙盒中的：与 iOS 不同**，在 iOS 上沙盒是在程序执行的第一条指令之前由内核应用的，而在 macOS 上，**进程必须选择将自己置于沙盒中。**

如果进程拥有权限：`com.apple.security.app-sandbox`，它们会在用户空间自动沙盒化。关于这个过程的详细解释，请查看：

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **检查 PID 权限**

[**根据这个**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s)，**`sandbox_check`**（它是一个 `__mac_syscall`），可以检查沙盒在某个 PID 中是否允许或不允许某项操作。

[**工具 sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) 可以检查 PID 是否可以执行某个操作：
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### App Store 应用中的自定义 SBPL

公司可能会让他们的应用程序**使用自定义沙箱配置文件**（而不是默认配置文件）运行。他们需要使用 **`com.apple.security.temporary-exception.sbpl`** 权限，这需要得到苹果的授权。

可以在 **`/System/Library/Sandbox/Profiles/application.sb:`** 中检查此权限的定义。
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
这将**在此权限之后评估字符串**作为沙盒配置文件。

<details>

<summary><strong>从零开始学习AWS黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
