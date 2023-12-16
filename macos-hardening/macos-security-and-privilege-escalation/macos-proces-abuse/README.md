# macOS进程滥用

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## MacOS进程滥用

与任何其他操作系统一样，MacOS提供了各种方法和机制，用于进程之间的**交互、通信和共享数据**。虽然这些技术对于系统的高效运行至关重要，但黑客也可以滥用这些技术来**执行恶意活动**。

### 库注入

库注入是一种技术，攻击者通过它**强制一个进程加载恶意库**。一旦注入，该库在目标进程的上下文中运行，为攻击者提供与进程相同的权限和访问权限。

{% content-ref url="macos-library-injection/" %}
[macos-library-injection](macos-library-injection/)
{% endcontent-ref %}

### 函数挂钩

函数挂钩涉及**拦截软件代码中的函数调用**或消息。通过挂钩函数，攻击者可以**修改进程的行为**，观察敏感数据，甚至控制执行流程。

{% content-ref url="../mac-os-architecture/macos-function-hooking.md" %}
[macos-function-hooking.md](../mac-os-architecture/macos-function-hooking.md)
{% endcontent-ref %}

### 进程间通信

进程间通信（IPC）是指不同进程之间**共享和交换数据**的不同方法。虽然IPC对于许多合法应用程序至关重要，但它也可以被滥用以破坏进程隔离、泄露敏感信息或执行未经授权的操作。

{% content-ref url="../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Electron应用程序注入

使用特定的环境变量执行的Electron应用程序可能容易受到进程注入的攻击：

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md](macos-electron-applications-injection.md)
{% endcontent-ref %}

### Dirty NIB

NIB文件**定义应用程序中的用户界面（UI）元素及其交互**。然而，它们可以**执行任意命令**，并且如果修改了NIB文件，Gatekeeper不会阻止已经执行的应用程序再次执行。因此，它们可以用来使任意程序执行任意命令：

{% content-ref url="macos-dirty-nib.md" %}
[macos-dirty-nib.md](macos-dirty-nib.md)
{% endcontent-ref %}

### Java应用程序注入

可以滥用某些Java功能（如**`_JAVA_OPTS`**环境变量）来使Java应用程序执行**任意代码/命令**。

{% content-ref url="macos-java-apps-injection.md" %}
[macos-java-apps-injection.md](macos-java-apps-injection.md)
{% endcontent-ref %}

### .Net应用程序注入

可以通过滥用.Net调试功能（不受macOS的运行时加固等保护措施保护）将代码注入到.Net应用程序中。

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md](macos-.net-applications-injection.md)
{% endcontent-ref %}

### Perl注入

检查不同的选项，以使Perl脚本执行任意代码：

{% content-ref url="macos-perl-applications-injection.md" %}
[macos-perl-applications-injection.md](macos-perl-applications-injection.md)
{% endcontent-ref %}

### Python注入

如果设置了环境变量**`PYTHONINSPECT`**，Python进程在完成后将进入Python命令行界面。还可以使用**`PYTHONSTARTUP`**指定在交互会话开始时要执行的Python脚本。\
但是，请注意，当**`PYTHONINSPECT`**创建交互会话时，**`PYTHONSTARTUP`**脚本不会被执行。

其他环境变量，如**`PYTHONPATH`**和**`PYTHONHOME`**，也可以用于使Python命令执行任意代码。

请注意，使用**`pyinstaller`**编译的可执行文件即使使用嵌入的Python运行，也不会使用这些环境变量。

{% hint style="danger" %}
总的来说，我找不到一种滥用环境变量使Python执行任意代码的方法。\
然而，大多数人使用**Hombrew**安装Python，它会将Python安装在默认管理员用户的**可写位置**。你可以使用类似以下的方法劫持它：
```bash
mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
cat > /opt/homebrew/bin/python3 <<EOF
#!/bin/bash
# Extra hijack code
/opt/homebrew/bin/python3.old "$@"
EOF
chmod +x /opt/homebrew/bin/python3
```
即使以root身份运行python，也会运行此代码。

## 检测

### Shield

[**Shield**](https://theevilbit.github.io/shield/)（[**Github**](https://github.com/theevilbit/Shield)）是一个开源应用程序，可以**检测和阻止进程注入**操作：

* 使用**环境变量**：它将监视以下任何环境变量的存在：**`DYLD_INSERT_LIBRARIES`**，**`CFNETWORK_LIBRARY_PATH`**，**`RAWCAMERA_BUNDLE_PATH`**和**`ELECTRON_RUN_AS_NODE`**
* 使用**`task_for_pid`**调用：查找一个进程想要获取另一个进程的**任务端口**，从而允许在进程中注入代码的情况。
* **Electron应用程序参数**：某人可以使用**`--inspect`**，**`--inspect-brk`**和**`--remote-debugging-port`**命令行参数以调试模式启动Electron应用程序，从而注入代码。
* 使用**符号链接**或**硬链接**：通常最常见的滥用是**使用我们的用户权限**放置一个链接，并将其指向更高权限的位置。对于硬链接和符号链接，检测非常简单。如果创建链接的进程具有**不同的权限级别**，我们会创建一个**警报**。不幸的是，在符号链接的情况下，阻止是不可能的，因为我们在创建之前没有关于链接目标的信息。这是Apple的EndpointSecuriy框架的一个限制。

### 其他进程发出的调用

在[**这篇博文**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)中，您可以了解如何使用函数**`task_name_for_pid`**获取有关其他**在进程中注入代码的进程**的信息，然后获取有关该其他进程的信息。

请注意，要调用该函数，您需要具有与运行进程相同的uid或**root**（它返回有关进程的信息，而不是注入代码的方法）。

## 参考资料

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks衣物**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>
