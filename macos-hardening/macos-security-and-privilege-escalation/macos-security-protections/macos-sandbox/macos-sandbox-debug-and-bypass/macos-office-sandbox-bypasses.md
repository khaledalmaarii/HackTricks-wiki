# macOS Office Sandbox Bypasses

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **在 Twitter 上关注** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}

### Word Sandbox 通过 Launch Agents 绕过

该应用程序使用 **自定义沙箱**，使用权限 **`com.apple.security.temporary-exception.sbpl`**，此自定义沙箱允许在任何地方写入文件，只要文件名以 `~$` 开头：`(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

因此，逃逸的方式就是 **在 `~/Library/LaunchAgents/~$escape.plist` 中写入一个 `plist`** 启动代理。

查看 [**原始报告**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)。

### Word Sandbox 通过登录项和 zip 绕过

请记住，从第一次逃逸开始，Word 可以写入以 `~$` 开头的任意文件，尽管在之前漏洞的修补后，无法在 `/Library/Application Scripts` 或 `/Library/LaunchAgents` 中写入。

发现从沙箱内可以创建 **登录项**（用户登录时将执行的应用程序）。但是，这些应用程序 **不会执行，除非** 它们 **经过公证**，并且 **无法添加参数**（因此不能仅使用 **`bash`** 运行反向 shell）。

在之前的沙箱绕过中，微软禁用了在 `~/Library/LaunchAgents` 中写入文件的选项。然而，发现如果将 **zip 文件作为登录项**，`Archive Utility` 将会 **解压** 到其当前位置。因此，由于默认情况下 `~/Library` 中不会创建 `LaunchAgents` 文件夹，可以 **将 plist 压缩到 `LaunchAgents/~$escape.plist` 中**，并 **将 zip 文件放置在 `~/Library` 中**，这样解压时将到达持久性目标。

查看 [**原始报告**](https://objective-see.org/blog/blog\_0x4B.html)。

### Word Sandbox 通过登录项和 .zshenv 绕过

（请记住，从第一次逃逸开始，Word 可以写入以 `~$` 开头的任意文件）。

然而，之前的技术有一个限制，如果 **`~/Library/LaunchAgents`** 文件夹存在，因为其他软件创建了它，则会失败。因此，发现了一个不同的登录项链。

攻击者可以创建 **`.bash_profile`** 和 **`.zshenv`** 文件，包含要执行的有效载荷，然后将它们压缩并 **写入受害者** 的用户文件夹：**`~/~$escape.zip`**。

然后，将 zip 文件添加到 **登录项**，然后是 **`Terminal`** 应用程序。当用户重新登录时，zip 文件将被解压到用户文件中，覆盖 **`.bash_profile`** 和 **`.zshenv`**，因此，终端将执行其中一个文件（取决于使用的是 bash 还是 zsh）。

查看 [**原始报告**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)。

### Word Sandbox 通过 Open 和 env 变量绕过

从沙箱进程中，仍然可以使用 **`open`** 工具调用其他进程。此外，这些进程将在 **自己的沙箱** 中运行。

发现 open 工具具有 **`--env`** 选项，可以使用 **特定的 env** 变量运行应用程序。因此，可以在 **沙箱内** 的文件夹中创建 **`.zshenv` 文件**，并使用 `open` 和 `--env` 将 **`HOME` 变量** 设置为该文件夹，打开 `Terminal` 应用程序，这将执行 `.zshenv` 文件（出于某种原因，还需要设置变量 `__OSINSTALL_ENVIROMENT`）。

查看 [**原始报告**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)。

### Word Sandbox 通过 Open 和 stdin 绕过

**`open`** 工具还支持 **`--stdin`** 参数（在之前的绕过后，无法再使用 `--env`）。

问题是，即使 **`python`** 是由 Apple 签名的，它也 **不会执行** 带有 **`quarantine`** 属性的脚本。然而，可以通过 stdin 传递脚本，这样就不会检查它是否被隔离：

1. 放置一个 **`~$exploit.py`** 文件，包含任意 Python 命令。
2. 运行 _open_ **`–stdin='~$exploit.py' -a Python`**，这将使用我们放置的文件作为标准输入运行 Python 应用程序。Python 高兴地运行我们的代码，并且由于它是 _launchd_ 的子进程，因此不受 Word 沙箱规则的限制。

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **在 Twitter 上关注** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}
