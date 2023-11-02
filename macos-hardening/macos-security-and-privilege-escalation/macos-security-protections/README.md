# macOS安全保护

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## Gatekeeper

Gatekeeper通常用于指代**Quarantine + Gatekeeper + XProtect**的组合，这是3个macOS安全模块，它们将尝试**阻止用户执行可能具有恶意的下载软件**。

更多信息请参见：

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## 进程限制

### SIP - 系统完整性保护

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### 沙盒

MacOS沙盒**限制在沙盒内运行的应用程序**只能执行沙盒配置文件中允许的操作。这有助于确保**应用程序只能访问预期的资源**。

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - 透明度、同意和控制

**TCC（透明度、同意和控制）**是macOS中的一种机制，用于从隐私角度**限制和控制应用程序对某些功能的访问**。这可以包括位置服务、联系人、照片、麦克风、摄像头、辅助功能、完全磁盘访问等等。

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### 启动/环境限制和信任缓存

macOS中的启动限制是一种安全功能，通过定义**谁可以启动**进程、**如何启动**以及**从哪里启动**来**规范进程启动**。在macOS Ventura中引入的信任缓存中，它将系统二进制文件分类为约束类别。每个可执行二进制文件都有其**启动规则**，包括**自身**、**父进程**和**负责人**约束。在macOS Sonoma中扩展到第三方应用程序的**环境**约束，这些功能有助于通过管理进程启动条件来减轻潜在的系统利用风险。

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - 恶意软件移除工具

恶意软件移除工具（MRT）是macOS安全基础设施的另一部分。顾名思义，MRT的主要功能是**从受感染的系统中删除已知的恶意软件**。

一旦在Mac上检测到恶意软件（通过XProtect或其他方式），就可以使用MRT自动**删除恶意软件**。MRT在后台静默运行，通常在系统更新或下载新的恶意软件定义时运行（看起来MRT用于检测恶意软件的规则在二进制文件中）。

虽然XProtect和MRT都是macOS的安全措施的一部分，但它们执行不同的功能：

* **XProtect**是一种预防工具。它会在文件下载时（通过某些应用程序）**检查文件**，如果检测到任何已知类型的恶意软件，它将**阻止文件打开**，从而在第一时间防止恶意软件感染您的系统。
* 另一方面，**MRT**是一种**响应性工具**。它在系统上检测到恶意软件后运行，目标是删除有问题的软件以清理系统。

MRT应用程序位于**`/Library/Apple/System/Library/CoreServices/MRT.app`**

## 后台任务管理

**macOS**现在每次工具使用已知的**持久代码执行技术**（如登录项、守护程序等）时都会**发出警报**，因此用户可以更好地了解**哪些软件是持久的**。

<figure><img src="../../../.gitbook/assets/image (711).png" alt=""><figcaption></figcaption></figure>

这是通过位于`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd`的**守护程序**和位于`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`的**代理**来运行的。

**`backgroundtaskmanagementd`**知道某个东西是否安装在持久文件夹中的方式是通过获取FSEvents并为其创建一些处理程序。

此外，还有一个包含由苹果维护的**众所周知的应用程序**的plist文件，位于：`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
```json
[...]
"us.zoom.ZoomDaemon" => {
"AssociatedBundleIdentifiers" => [
0 => "us.zoom.xos"
]
"Attribution" => "Zoom"
"Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
"ProgramArguments" => [
0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
]
"TeamIdentifier" => "BJ4HAAB9B3"
}
[...]
```
### 枚举

可以使用Apple的命令行工具**枚举**所有配置的后台项目：
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
此外，您还可以使用[**DumpBTM**](https://github.com/objective-see/DumpBTM)列出此信息。
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
这些信息被存储在 **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** 中，终端需要 FDA。

### 干扰 BTM

当发现新的持久性时，会触发一个类型为 **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** 的事件。因此，任何阻止发送此事件或使代理程序不向用户发出警报的方法都将帮助攻击者绕过 BTM。

* **重置数据库**：运行以下命令将重置数据库（应该从头开始重建），但由于某种原因，在运行此命令后，**直到系统重新启动之前，不会有新的持久性被警报**。
* 需要 **root** 权限。
```bash
# Reset the database
sfltool resettbtm
```
* **停止代理程序**：可以向代理程序发送停止信号，这样当发现新的检测时，它就**不会向用户发出警报**。
```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```
* **漏洞**: 如果**创建持久性的进程**在它之后迅速存在，守护进程将尝试**获取有关它的信息**，**失败**，并且**无法发送事件**表示有新的持久性事物。

有关BTM的**更多信息和参考**：

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者想要**获取最新版本的PEASS或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
