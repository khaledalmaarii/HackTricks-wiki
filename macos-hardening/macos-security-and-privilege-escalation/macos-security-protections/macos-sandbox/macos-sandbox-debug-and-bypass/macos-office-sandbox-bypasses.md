# macOS Office 沙盒绕过

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 HackTricks 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

### 通过 Launch Agents 绕过 Word 沙盒

应用程序使用了一个**自定义沙盒**，使用权限**`com.apple.security.temporary-exception.sbpl`**，这个自定义沙盒允许在文件名以 `~$` 开头的情况下在任何地方写入文件：`(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

因此，绕过就像**写一个 `plist`** LaunchAgent 在 `~/Library/LaunchAgents/~$escape.plist` 中一样简单。

查看[**原始报告在这里**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### 通过登录项和 zip 绕过 Word 沙盒

记住，从第一次逃逸开始，Word 可以写入任意以 `~$` 开头的文件名，尽管在修补了之前的漏洞后，它不可能写入 `/Library/Application Scripts` 或 `/Library/LaunchAgents`。

发现在沙盒内可以创建一个**登录项**（用户登录时将执行的应用程序）。然而，这些应用程序**不会执行，除非**它们被**公证**，并且**不可能添加参数**（所以你不能只是使用 **`bash`** 运行一个反向 shell）。

从之前的沙盒绕过中，Microsoft 禁用了在 `~/Library/LaunchAgents` 中写入文件的选项。然而，发现如果你把一个**zip 文件作为登录项**，`Archive Utility` 将会在其当前位置**解压**它。所以，因为默认情况下 `~/Library` 的 `LaunchAgents` 文件夹没有被创建，所以可以**在 `LaunchAgents/~$escape.plist` 中压缩一个 plist**，然后**放置** zip 文件在 **`~/Library`** 中，当解压时它将到达持久性目的地。

查看[**原始报告在这里**](https://objective-see.org/blog/blog\_0x4B.html).

### 通过登录项和 .zshenv 绕过 Word 沙盒

（记住，从第一次逃逸开始，Word 可以写入任意以 `~$` 开头的文件名。）

然而，之前的技术有一个限制，如果文件夹 **`~/Library/LaunchAgents`** 存在，因为其他软件创建了它，它会失败。因此，为此发现了不同的登录项链。

攻击者可以创建文件 **`.bash_profile`** 和 **`.zshenv`**，其中包含要执行的有效载荷，然后将它们压缩并**写入 zip 到受害者** 用户文件夹：**`~/~$escape.zip`**。

然后，将 zip 文件添加到**登录项**，然后是**`Terminal`** 应用程序。当用户重新登录时，zip 文件将在用户文件中解压，覆盖 **`.bash_profile`** 和 **`.zshenv`**，因此，终端将执行这些文件之一（取决于使用 bash 还是 zsh）。

查看[**原始报告在这里**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).

### 通过 Open 和环境变量绕过 Word 沙盒

从沙盒进程中，仍然可以使用 **`open`** 工具调用其他进程。此外，这些进程将在**它们自己的沙盒**内运行。

发现 open 工具有一个 **`--env`** 选项，用于使用**特定的环境**变量运行应用程序。因此，可以在**沙盒内部**的文件夹中创建 **`.zshenv` 文件**，然后使用 `open` 和 `--env` 设置 **`HOME` 变量** 到那个文件夹打开 `Terminal` 应用程序，它将执行 `.zshenv` 文件（由于某种原因，还需要设置变量 `__OSINSTALL_ENVIROMENT`）。

查看[**原始报告在这里**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).

### 通过 Open 和 stdin 绕过 Word 沙盒

**`open`** 工具还支持 **`--stdin`** 参数（在之前的绕过之后，不再可能使用 `--env`）。

问题是，即使 **`python`** 被 Apple 签名，它也**不会执行**带有**`隔离`**属性的脚本。然而，可以通过 stdin 传递脚本，所以它不会检查脚本是否被隔离：&#x20;

1. 放置一个 **`~$exploit.py`** 文件，其中包含任意 Python 命令。
2. 运行 _open_ **`–stdin='~$exploit.py' -a Python`**，这将运行 Python 应用程序，我们放置的文件作为其标准输入。Python 愉快地运行我们的代码，由于它是 _launchd_ 的子进程，它不受 Word 沙盒规则的约束。

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 HackTricks 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>
