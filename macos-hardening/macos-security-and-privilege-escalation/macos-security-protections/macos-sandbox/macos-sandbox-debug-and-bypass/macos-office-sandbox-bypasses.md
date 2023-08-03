# macOS Office沙箱绕过

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者想要获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

### 通过启动代理绕过Word沙箱

该应用程序使用一个使用权限`com.apple.security.temporary-exception.sbpl`的**自定义沙箱**，这个自定义沙箱允许在文件名以`~$`开头的任何地方写入文件：`(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

因此，绕过沙箱很容易，只需在`~/Library/LaunchAgents/~$escape.plist`中编写一个`plist`启动代理。

查看[**原始报告**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)。

### 通过登录项和zip绕过Word沙箱

（请记住，从第一个逃逸开始，Word可以写入以`~$`开头的任意文件）。

发现在沙箱内部可以创建一个**登录项**（用户登录时将执行的应用程序）。然而，这些应用程序**只有在**它们被**签名**并且**不可能添加参数**（因此无法使用**`bash`**运行反向shell）时才会执行。

从之前的沙箱绕过中，Microsoft禁用了在`~/Library/LaunchAgents`中写入文件的选项。然而，发现如果将一个**zip文件作为登录项**，`Archive Utility`将会在当前位置**解压缩**它。因此，由于默认情况下`~/Library`中的`LaunchAgents`文件夹不会被创建，所以可以将一个plist文件压缩为`LaunchAgents/~$escape.plist`并将zip文件放在`~/Library`中，这样当解压缩时就会到达持久化目标。

查看[**原始报告**](https://objective-see.org/blog/blog\_0x4B.html)。

### 通过登录项和.zshenv绕过Word沙箱

（请记住，从第一个逃逸开始，Word可以写入以`~$`开头的任意文件）。

然而，前一种技术有一个限制，如果文件夹**`~/Library/LaunchAgents`**存在，因为其他软件创建了它，它将失败。因此，发现了一种不同的登录项链来解决这个问题。

攻击者可以创建带有执行负载的文件**`.bash_profile`**和**`.zshenv`**，然后将它们压缩并将zip文件写入受害者的用户文件夹：\~/\~$escape.zip。

然后，将zip文件添加到**登录项**，然后添加**`Terminal`**应用程序。当用户重新登录时，zip文件将被解压缩到用户文件夹中，覆盖**`.bash_profile`**和**`.zshenv`**，因此终端将执行其中一个文件（取决于使用的是bash还是zsh）。

查看[**原始报告**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)。

### 通过Open和环境变量绕过Word沙箱

从沙箱化的进程中仍然可以使用**`open`**实用程序调用其他进程。此外，这些进程将在它们自己的沙箱中运行。

发现open实用程序具有**`--env`**选项，可以使用特定的环境变量运行应用程序。因此，可以在沙箱内的一个文件夹中创建**`.zshenv`文件**，然后使用`open`和`--env`将**`HOME`变量**设置为该文件夹，打开`Terminal`应用程序，它将执行`.zshenv`文件（由于某种原因，还需要设置变量`__OSINSTALL_ENVIROMENT`）。

查看[**原始报告**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)。

### 通过Open和stdin绕过Word沙箱

**`open`**实用程序还支持**`--stdin`**参数（在之前的绕过之后，无法再使用`--env`）。

问题是，即使**`python`**由Apple签名，它也**不会执行**带有**`quarantine`**属性的脚本。然而，可以将脚本从stdin传递给它，这样它就不会检查它是否被隔离：&#x20;

1. 放置一个带有任意Python命令的**`~$exploit.py`**文件。
2. 运行_open_ **`–stdin='~$exploit.py' -a Python`**，它将使用我们放置的文件作为标准输入运行Python应用程序。Python愉快地运行我们的代码，并且由于它是_launchd_的子进程，它不受Word沙箱规则的限制。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者想要获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现[**The PEASS Family**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或 **关注**我的**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>
