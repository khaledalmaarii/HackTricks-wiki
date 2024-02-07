# macOS沙箱

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

- 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
- 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFTs收藏品](https://opensea.io/collection/the-peass-family)
- **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
- 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 基本信息

macOS沙箱（最初称为Seatbelt）**限制在沙箱内运行的应用程序**执行的操作，以**符合应用程序运行时使用的沙箱配置文件中指定的允许操作**。这有助于确保**应用程序仅访问预期资源**。

任何具有**授权** **`com.apple.security.app-sandbox`** 的应用程序将在沙箱内执行。**苹果二进制文件**通常在沙箱内执行，并且为了在**App Store**中发布，**此授权是强制性的**。因此，大多数应用程序将在沙箱内执行。

为了控制进程可以执行的操作，**沙箱在内核中的所有** **系统调用**中都有**钩子**。**根据**应用程序的**授权**，沙箱将**允许**特定操作。

沙箱的一些重要组件包括：

- **内核扩展** `/System/Library/Extensions/Sandbox.kext`
- **私有框架** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- 在用户空间运行的**守护进程** `/usr/libexec/sandboxd`
- **容器** `~/Library/Containers`

在容器文件夹中，您可以找到**为每个在沙箱中执行的应用程序**的文件夹，其名称为捆绑标识符：
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
在每个 bundle id 文件夹中，您可以找到该应用的 **plist** 和 **Data 目录**：
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
请注意，即使符号链接存在以“逃离”沙盒并访问其他文件夹，应用程序仍然需要**有权限**访问它们。这些权限位于**`.plist`**文件中。
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
所有由沙盒应用程序创建/修改的内容都将获得**隔离属性**。这将通过触发Gatekeeper来阻止沙盒应用程序尝试使用**`open`**执行某些操作。
{% endhint %}

### 沙盒配置文件

沙盒配置文件是指示在该**沙盒**中将被**允许/禁止**的内容的配置文件。它使用**沙盒配置语言（SBPL）**，该语言使用[**Scheme**](https://en.wikipedia.org/wiki/Scheme_%28programming_language%29)编程语言。

在这里，您可以找到一个示例：
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
查看这个[**研究**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **以查看更多可能被允许或拒绝的操作。**
{% endhint %}

重要的**系统服务**也在其自定义的**沙盒**中运行，例如`mdnsresponder`服务。您可以在以下位置查看这些自定义**沙盒配置文件**：

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**&#x20;
* 其他沙盒配置文件可以在[https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles)中进行检查。

**App Store** 应用程序使用**配置文件** **`/System/Library/Sandbox/Profiles/application.sb`**。您可以在此配置文件中查看诸如**`com.apple.security.network.server`**这样的授权如何允许进程使用网络。

SIP是一个名为platform\_profile的沙盒配置文件，位于/System/Library/Sandbox/rootless.conf

### 沙盒配置文件示例

要使用**特定的沙盒配置文件**启动应用程序，您可以使用：
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
请注意，运行在**Windows**上的**由苹果编写的软件**没有额外的安全预防措施，比如应用程序沙箱。
{% endhint %}

绕过示例：

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)（它们能够在沙箱之外写入以`~$`开头的文件）。

### MacOS 沙箱配置文件

macOS将系统沙箱配置文件存储在两个位置：**/usr/share/sandbox/** 和 **/System/Library/Sandbox/Profiles**。

如果第三方应用程序携带了 _**com.apple.security.app-sandbox**_ 权限，系统将应用 **/System/Library/Sandbox/Profiles/application.sb** 配置文件到该进程。

### **iOS 沙箱配置文件**

默认配置文件名为 **container**，我们没有SBPL文本表示。在内存中，此沙箱被表示为每个权限的允许/拒绝二进制树。

### 调试和绕过沙箱

在macOS上，与iOS不同，进程必须自行选择加入沙箱。这意味着在macOS上，进程在主动决定进入沙箱之前不受沙箱限制。

如果进程具有权限：`com.apple.security.app-sandbox`，则当它们启动时，进程会自动从用户空间进入沙箱。有关此过程的详细解释，请查看：

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **检查 PID 权限**

[**根据此**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s)，**`sandbox_check`**（它是一个`__mac_syscall`），可以检查在特定PID中沙箱是否允许执行某个操作。

[**工具 sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) 可以检查PID是否可以执行某个操作：
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### 在App Store应用程序中使用自定义SBPL

公司可以使他们的应用程序运行**使用自定义沙盒配置文件**（而不是默认配置文件）。他们需要使用授权的entitlement **`com.apple.security.temporary-exception.sbpl`**，这需要获得苹果的授权。

可以在**`/System/Library/Sandbox/Profiles/application.sb:`**中检查此entitlement的定义。
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
这将**评估此授权后的字符串**作为沙箱配置文件。

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **在Twitter上** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)** 上关注我**。
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
