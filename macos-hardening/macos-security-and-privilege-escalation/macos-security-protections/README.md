# macOS安全保护

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

- 如果您想看到您的**公司在HackTricks中被广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
- 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
- **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
- 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## Gatekeeper

Gatekeeper通常用于指代**Quarantine + Gatekeeper + XProtect**的组合，这是3个macOS安全模块，旨在**阻止用户执行可能是恶意软件的下载**。

更多信息：

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## 进程限制

### SIP - 系统完整性保护

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### 沙盒

macOS沙盒**限制在沙盒内运行的应用程序**执行沙盒配置文件中指定的**允许操作**。这有助于确保**应用程序只能访问预期的资源**。

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **透明度、同意和控制**

**TCC（透明度、同意和控制）**是一个安全框架。它旨在**管理应用程序的权限**，特别是通过规范它们对敏感功能的访问。这包括诸如**位置服务、联系人、照片、麦克风、摄像头、辅助功能和完全磁盘访问**等元素。TCC确保应用程序只能在获得明确用户同意后访问这些功能，从而增强隐私和对个人数据的控制。

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### 启动/环境约束和信任缓存

macOS中的启动约束是一项安全功能，通过将系统二进制文件分类到**信任缓存**中的约束类别，来**规范进程启动**，定义**谁可以启动**进程，**如何启动**以及**从哪里启动**。在macOS Ventura中引入，每个可执行二进制文件都有其**启动**的设定**规则**，包括**自身**、**父级**和**负责**约束。在macOS Sonoma中扩展到第三方应用程序作为**环境**约束，这些功能有助于通过管理进程启动条件来减轻潜在的系统利用。

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - 恶意软件清除工具

恶意软件清除工具（MRT）是macOS安全基础设施的另一部分。顾名思义，MRT的主要功能是**从受感染系统中删除已知的恶意软件**。

一旦在Mac上检测到恶意软件（无论是通过XProtect还是其他方式），MRT可用于自动**清除恶意软件**。MRT在后台静默运行，通常在系统更新时运行，或者在下载新的恶意软件定义时运行（看起来MRT用于检测恶意软件的规则存储在二进制文件中）。

虽然XProtect和MRT都是macOS安全措施的一部分，但它们执行不同的功能：

- **XProtect**是一种预防工具。它会在文件下载时（通过某些应用程序）**检查文件**，如果检测到任何已知类型的恶意软件，它会**阻止文件打开**，从而防止恶意软件首次感染系统。
- 另一方面，**MRT**是一种**响应式工具**。它在系统上检测到恶意软件后运行，目的是删除有问题的软件以清理系统。

MRT应用程序位于**`/Library/Apple/System/Library/CoreServices/MRT.app`**

## 后台任务管理

**macOS**现在会**提醒**每当工具使用已知的**持久代码执行技术**（如登录项、守护程序等）时，以便用户更好地了解**哪些软件是持久的**。

<figure><img src="../../../.gitbook/assets/image (1183).png" alt=""><figcaption></figcaption></figure>

这是通过位于`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd`的**守护程序**和位于`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`的**代理**来运行的。

**`backgroundtaskmanagementd`**知道某个东西安装在持久文件夹中的方式是通过**获取FSEvents**并为其创建一些**处理程序**。

此外，有一个包含由苹果维护的**众所周知的应用程序**的属性列表文件，位于：`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
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

可以使用苹果的命令行工具**枚举所有**配置的后台项目：
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
此外，您还可以使用[**DumpBTM**](https://github.com/objective-see/DumpBTM)列出这些信息。
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
这些信息被存储在 **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** 中，终端需要 FDA。

### 操纵 BTM

当发现新的持久性时，会触发一个类型为 **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** 的事件。因此，任何阻止发送此事件或使代理警告用户的方法都将帮助攻击者 _**绕过**_ BTM。

* **重置数据库**：运行以下命令将重置数据库（应该从头开始重建），但出于某种原因，在运行此命令后，**直到系统重新启动之前，不会警告任何新的持久性**。
* 需要 **root** 权限。
```bash
# Reset the database
sfltool resettbtm
```
* **停止代理程序**：可以向代理程序发送停止信号，这样当发现新的检测时，**就不会提醒用户**。
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
* **漏洞**: 如果**创建持久性的进程在其后立即存在**，守护进程将尝试**获取有关其的信息**，**失败**，并且**无法发送事件**指示有新的持久性事物。

有关BTM的**更多信息**和**参考资料**：

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)
