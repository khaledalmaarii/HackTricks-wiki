# macOS 安全保护

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF**，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上 **关注** 我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## Gatekeeper

Gatekeeper 通常用来指代 **Quarantine + Gatekeeper + XProtect** 的组合，这是 3 个 macOS 安全模块，它们会尝试 **阻止用户执行可能是恶意的下载软件**。

更多信息在：

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## 进程限制

### SIP - 系统完整性保护

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### 沙盒

macOS 沙盒 **限制在沙盒内运行的应用程序** 只能执行在沙盒配置文件中允许的 **指定操作**。这有助于确保 **应用程序只访问预期的资源**。

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **透明度、同意和控制**

**TCC (透明度、同意和控制)** 是 macOS 中的一种机制，用于 **限制和控制应用程序对某些功能的访问**，通常从隐私角度出发。这可能包括位置服务、联系人、照片、麦克风、摄像头、辅助功能、完整磁盘访问等等。

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### 启动/环境约束 & 信任缓存

macOS 中的启动约束是一种安全特性，用于 **规范进程启动**，定义 **谁可以启动** 进程、**如何启动** 以及 **从哪里启动**。在 macOS Ventura 中引入，它们将系统二进制文件分类到 **信任缓存** 中的约束类别。每个可执行二进制文件都设置了 **启动规则**，包括 **自身**、**父级** 和 **负责人** 约束。在 macOS Sonoma 中，这些特性作为 **环境** 约束扩展到第三方应用，通过管理进程启动条件来帮助缓解潜在的系统利用。

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - 恶意软件移除工具

恶意软件移除工具 (MRT) 是 macOS 安全基础设施的另一部分。顾名思义，MRT 的主要功能是 **从受感染的系统中移除已知的恶意软件**。

一旦在 Mac 上检测到恶意软件（无论是通过 XProtect 还是其他方式），MRT 可以用来自动 **移除恶意软件**。MRT 在后台默默运行，通常在系统更新或下载新的恶意软件定义时运行（看起来 MRT 检测恶意软件的规则在二进制文件内）。

虽然 XProtect 和 MRT 都是 macOS 安全措施的一部分，但它们执行不同的功能：

* **XProtect** 是一种预防工具。它 **在文件下载时检查**（通过某些应用程序），如果检测到任何已知类型的恶意软件，它会 **阻止文件打开**，从而防止恶意软件首先感染您的系统。
* **MRT** 另一方面，是一种 **反应工具**。它在系统上检测到恶意软件后运行，目的是移除有问题的软件以清理系统。

MRT 应用程序位于 **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## 后台任务管理

**macOS** 现在 **提醒** 每次工具使用众所周知的 **技术来持久化代码执行**（例如登录项、守护进程等），以便用户更好地了解 **哪些软件正在持久化**。

<figure><img src="../../../.gitbook/assets/image (711).png" alt=""><figcaption></figcaption></figure>

这是通过位于 `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` 的 **守护进程** 和位于 `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app` 的 **代理** 运行的。

**`backgroundtaskmanagementd`** 知道某些东西安装在持久文件夹中是通过 **获取 FSEvents** 并为这些事件创建一些 **处理程序**。

此外，还有一个 plist 文件，其中包含由苹果维护的 **众所周知的应用程序**，这些应用程序经常持久化，位于：`/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
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

可以使用 Apple cli 工具**枚举所有**配置的后台项目：
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
此外，还可以使用 [**DumpBTM**](https://github.com/objective-see/DumpBTM) 列出这些信息。
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
### 操作 BTM

当发现新的持久性时，会发出类型为 **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** 的事件。因此，任何阻止此**事件**发送或**代理警告**用户的方法都将帮助攻击者_**绕过**_ BTM。

* **重置数据库**：运行以下命令将重置数据库（应该从头开始重建），但是由于某种原因，在运行此命令后，**直到系统重启之前不会警告新的持久性**。
* 需要 **root** 权限。
```bash
# Reset the database
sfltool resettbtm
```
* **停止代理**: 可以向代理发送停止信号，这样它在发现新的检测时**不会警告用户**。
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
* **Bug**: 如果**创建持久性的进程在此之后快速退出**，守护进程将尝试**获取信息**，**失败**，并且**无法发送事件**指示有新的事物正在持久化。

参考和**关于 BTM 的更多信息**：

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习 AWS 黑客攻击！</strong></summary>

其他支持 HackTricks 的方式：

* 如果您希望在 HackTricks 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方的 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧**。

</details>
