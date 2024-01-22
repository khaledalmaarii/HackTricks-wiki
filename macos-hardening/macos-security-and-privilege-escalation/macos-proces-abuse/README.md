# macOS 进程滥用

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 HackTricks 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## MacOS 进程滥用

MacOS，像其他操作系统一样，提供了多种方法和机制，用于**进程之间的互动、通信和数据共享**。虽然这些技术对于系统的高效运行至关重要，但它们也可能被威胁行为者滥用，以**执行恶意活动**。

### 库注入

库注入是一种技术，攻击者**强制进程加载恶意库**。一旦注入，库就会在目标进程的上下文中运行，为攻击者提供与进程相同的权限和访问能力。

{% content-ref url="macos-library-injection/" %}
[macos-library-injection](macos-library-injection/)
{% endcontent-ref %}

### 函数挂钩

函数挂钩涉及**拦截软件代码中的函数调用**或消息。通过挂钩函数，攻击者可以**修改进程的行为**，观察敏感数据，甚至控制执行流程。

{% content-ref url="../mac-os-architecture/macos-function-hooking.md" %}
[macos-function-hooking.md](../mac-os-architecture/macos-function-hooking.md)
{% endcontent-ref %}

### 进程间通信

进程间通信（IPC）指的是不同进程**共享和交换数据**的不同方法。虽然 IPC 对许多合法应用程序至关重要，但它也可能被滥用，以破坏进程隔离，泄露敏感信息或执行未授权的操作。

{% content-ref url="../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Electron 应用程序注入

使用特定环境变量执行的 Electron 应用程序可能容易受到进程注入的攻击：

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md](macos-electron-applications-injection.md)
{% endcontent-ref %}

### Dirty NIB

NIB 文件**定义用户界面（UI）元素**及其在应用程序中的交互。然而，它们可以**执行任意命令**，并且**Gatekeeper 不会阻止**已经执行的应用程序被执行，如果**NIB 文件被修改**。因此，它们可以被用来使任意程序执行任意命令：

{% content-ref url="macos-dirty-nib.md" %}
[macos-dirty-nib.md](macos-dirty-nib.md)
{% endcontent-ref %}

### Java 应用程序注入

可以滥用某些 Java 能力（如 **`_JAVA_OPTS`** 环境变量）使 Java 应用程序执行**任意代码/命令**。

{% content-ref url="macos-java-apps-injection.md" %}
[macos-java-apps-injection.md](macos-java-apps-injection.md)
{% endcontent-ref %}

### .Net 应用程序注入

可以通过**滥用 .Net 调试功能**（不受 macOS 保护，如运行时加固）来注入代码到 .Net 应用程序中。

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md](macos-.net-applications-injection.md)
{% endcontent-ref %}

### Perl 注入

检查不同的选项，使 Perl 脚本在以下位置执行任意代码：

{% content-ref url="macos-perl-applications-injection.md" %}
[macos-perl-applications-injection.md](macos-perl-applications-injection.md)
{% endcontent-ref %}

### Ruby 注入

也可以滥用 Ruby 环境变量，使任意脚本执行任意代码：

{% content-ref url="macos-ruby-applications-injection.md" %}
[macos-ruby-applications-injection.md](macos-ruby-applications-injection.md)
{% endcontent-ref %}

### Python 注入

如果设置了环境变量 **`PYTHONINSPECT`**，Python 进程在结束后会进入 Python 命令行界面。也可以使用 **`PYTHONSTARTUP`** 来指示在交互式会话开始时执行的 Python 脚本。\
但是，请注意，当 **`PYTHONINSPECT`** 创建交互式会话时，**`PYTHONSTARTUP`** 脚本不会被执行。

其他环境变量，如 **`PYTHONPATH`** 和 **`PYTHONHOME`**，也可以用来使 Python 命令执行任意代码。

请注意，使用 **`pyinstaller`** 编译的可执行文件即使在使用嵌入式 Python 运行时也不会使用这些环境变量。

{% hint style="danger" %}
总的来说，我没有找到一种方法可以通过滥用环境变量使 Python 执行任意代码。\
然而，大多数人使用 **Homebrew** 安装 Python，这将在默认管理员用户的**可写位置**安装 Python。您可以用类似的方法劫持它：
```bash
mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
cat > /opt/homebrew/bin/python3 <<EOF
#!/bin/bash
# Extra hijack code
/opt/homebrew/bin/python3.old "$@"
EOF
chmod +x /opt/homebrew/bin/python3
```
即使是**root**在运行python时也会运行这段代码。
{% endhint %}

## 检测

### Shield

[**Shield**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)) 是一个开源应用程序，可以**检测并阻止进程注入**行为：

* 使用**环境变量**：它会监控以下任何环境变量的存在：**`DYLD_INSERT_LIBRARIES`**、**`CFNETWORK_LIBRARY_PATH`**、**`RAWCAMERA_BUNDLE_PATH`** 和 **`ELECTRON_RUN_AS_NODE`**
* 使用 **`task_for_pid`** 调用：找出一个进程何时想要获取**另一个进程的任务端口**，这允许向进程中注入代码。
* **Electron 应用参数**：有人可以使用 **`--inspect`**、**`--inspect-brk`** 和 **`--remote-debugging-port`** 命令行参数来启动 Electron 应用程序的调试模式，从而向其中注入代码。
* 使用**符号链接**或**硬链接**：通常最常见的滥用是**用我们的用户权限放置一个链接**，并**指向更高权限**的位置。对于硬链接和符号链接，检测非常简单。如果创建链接的进程与目标文件的**权限级别不同**，我们会创建一个**警报**。不幸的是，在符号链接的情况下，阻止是不可能的，因为我们在创建之前没有关于链接目的地的信息。这是苹果的 EndpointSecuriy 框架的一个限制。

### 由其他进程发起的调用

在[**这篇博客文章**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)中，你可以找到如何使用函数 **`task_name_for_pid`** 来获取有关其他**进程在进程中注入代码**的信息，然后获取有关那个其他进程的信息。

请注意，要调用该函数，你需要与运行进程的用户具有**相同的 uid**或者是**root**（它返回有关进程的信息，而不是注入代码的方法）。

## 参考资料

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> 从零开始学习 AWS 黑客攻击！</strong></summary>

支持 HackTricks 的其他方式：

* 如果你想在 **HackTricks** 中看到你的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs**](https://opensea.io/collection/the-peass-family) 收藏品
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享你的黑客技巧**。

</details>
