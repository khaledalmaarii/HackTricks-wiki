# macOS Office Sandbox Bypasses

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

### 通过启动代理绕过Word沙箱

该应用程序使用一个**自定义沙箱**，使用权限**`com.apple.security.temporary-exception.sbpl`**，这个自定义沙箱允许在文件名以`~$`开头时在任何地方写入文件：`(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

因此，绕过很容易，只需在`~/Library/LaunchAgents/~$escape.plist`中编写一个`plist`启动代理。

查看[**原始报告**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)。

### 通过登录项和zip绕过Word沙箱

请记住，从第一个逃逸开始，Word可以写入任意以`~$`开头的文件，尽管在修补了先前漏洞之后，无法在`/Library/Application Scripts`或`/Library/LaunchAgents`中写入。

在沙箱内发现可以创建一个**登录项**（用户登录时将执行的应用程序）。但是，这些应用程序**不会执行**，除非它们经过**公证**，并且**无法添加参数**（因此无法使用**`bash`**运行反向shell）。

从先前的沙箱绕过中，Microsoft禁用了在`~/Library/LaunchAgents`中写入文件的选项。但是，发现如果将**zip文件作为登录项**，`Archive Utility`将只是在当前位置解压缩它。因此，由于默认情况下`~/Library`中的`LaunchAgents`文件夹未创建，可以**在`~/Library`中压缩一个plist文件`LaunchAgents/~$escape.plist`**，并将zip文件放在**`~/Library`**中，因此在解压缩时将到达持久性目的地。

查看[**原始报告**](https://objective-see.org/blog/blog_0x4B.html)。

### 通过登录项和.zshenv绕过Word沙箱

（请记住，从第一个逃逸开始，Word可以写入任意以`~$`开头的文件）。

然而，先前的技术有一个限制，如果文件夹**`~/Library/LaunchAgents`**存在，因为其他软件创建了它，它将失败。因此，为此发现了不同的登录项链。

攻击者可以创建带有执行负载的文件**`.bash_profile`**和**`.zshenv`**，然后将它们压缩并将zip文件写入受害者的用户文件夹：**`~/~$escape.zip`**。

然后，将zip文件添加到**登录项**，然后添加**`Terminal`**应用程序。当用户重新登录时，zip文件将解压缩到用户文件中，覆盖**`.bash_profile`**和**`.zshenv`**，因此终端将执行其中一个文件（取决于使用的是bash还是zsh）。

查看[**原始报告**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)。

### 使用Open和环境变量绕过Word沙箱

从沙箱化进程仍然可以使用**`open`**实用程序调用其他进程。此外，这些进程将在其自己的沙箱中运行。

发现`open`实用程序具有**`--env`**选项，用于使用**特定环境**变量运行应用程序。因此，可以在**沙箱内的文件夹中创建`.zshenv`文件**，然后使用`open`设置**`HOME`变量**到该文件夹，打开`Terminal`应用程序，该应用程序将执行`.zshenv`文件（由于某种原因，还需要设置变量`__OSINSTALL_ENVIROMENT`）。

查看[**原始报告**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)。

### 使用Open和stdin绕过Word沙箱

**`open`**实用程序还支持**`--stdin`**参数（在先前的绕过之后，无法再使用`--env`）。

问题在于，即使**`python`**由Apple签名，它也**不会执行**带有**`quarantine`**属性的脚本。但是，可以将脚本从stdin传递给它，因此它不会检查它是否被隔离：&#x20;

1. 放置一个带有任意Python命令的**`~$exploit.py`**文件。
2. 运行_open_ **`–stdin='~$exploit.py' -a Python`**，这将使用我们放置的文件作为其标准输入运行Python应用程序。Python愉快地运行我们的代码，并且由于它是_launchd_的子进程，它不受Word沙箱规则的约束。

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
