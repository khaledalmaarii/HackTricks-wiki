# macOS安装程序滥用

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## Pkg基本信息

macOS **安装程序包**（也称为`.pkg`文件）是macOS用于**分发软件**的文件格式。这些文件就像一个**包含了软件安装和运行所需的一切**的盒子。

安装程序包本身是一个存档文件，其中包含了将要安装在目标计算机上的**文件和目录的层次结构**。它还可以包括在安装之前和之后执行任务的**脚本**，例如设置配置文件或清理旧版本的软件。

### 层次结构

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt=""><figcaption></figcaption></figure>

* **Distribution (xml)**: 自定义内容（标题，欢迎文本...）和脚本/安装检查
* **PackageInfo (xml)**: 信息，安装要求，安装位置，运行脚本的路径
* **Bill of materials (bom)**: 要安装、更新或删除的文件列表及其文件权限
* **Payload (CPIO归档gzip压缩)**: 要安装在PackageInfo中的`install-location`中的文件
* **Scripts (CPIO归档gzip压缩)**: 预安装和后安装脚本以及更多资源，提取到临时目录以供执行。

### 解压缩
```bash
# Tool to directly get the files inside a package
pkgutil —expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files ina. more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
## DMG基本信息

DMG文件，或称为Apple Disk Images，是苹果的macOS使用的磁盘映像文件格式。DMG文件实际上是一个可挂载的磁盘映像（它包含自己的文件系统），其中包含通常经过压缩和有时加密的原始块数据。当您打开一个DMG文件时，macOS会将其挂载为一个物理磁盘，使您能够访问其内容。

### 层次结构

<figure><img src="../../../.gitbook/assets/image (12) (2).png" alt=""><figcaption></figcaption></figure>

DMG文件的层次结构可以根据内容的不同而不同。然而，对于应用程序DMG文件，它通常遵循以下结构：

* 顶层：这是磁盘映像的根目录。它通常包含应用程序以及可能链接到应用程序文件夹的链接。
* 应用程序（.app）：这是实际的应用程序。在macOS中，应用程序通常是一个包，其中包含许多组成应用程序的单个文件和文件夹。
* 应用程序链接：这是指向macOS中应用程序文件夹的快捷方式。其目的是使您能够轻松安装应用程序。您可以将.app文件拖到此快捷方式以安装应用程序。

## 通过pkg滥用提权

### 从公共目录执行

如果一个预安装或后安装脚本例如从**`/var/tmp/Installerutil`**执行，并且攻击者可以控制该脚本，那么他可以在每次执行时提升权限。或者另一个类似的例子：

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt=""><figcaption></figcaption></figure>

### AuthorizationExecuteWithPrivileges

这是一个[公共函数](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg)，许多安装程序和更新程序将调用它来以root权限执行某些操作。该函数接受要执行的文件的路径作为参数，然而，如果攻击者可以修改此文件，他将能够滥用其以root权限执行，从而提升权限。
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
有关更多信息，请查看此演讲：[https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### 通过挂载执行

如果安装程序写入`/tmp/fixedname/bla/bla`，则可以使用无所有者的方式在`/tmp/fixedname`上**创建一个挂载点**，从而可以在安装过程中**修改任何文件**以滥用安装过程。

一个例子是**CVE-2021-26089**，它成功地**覆盖了一个周期性脚本**以获取以root权限执行的能力。有关更多信息，请参阅演讲：[**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg作为恶意软件

### 空负载

可以只生成一个没有任何负载的**`.pkg`**文件，其中包含**预安装和后安装脚本**。

### Distribution xml中的JS

可以在软件包的**distribution xml**文件中添加**`<script>`**标签，该代码将被执行，并且可以使用**`system.run`**来**执行命令**：

<figure><img src="../../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

## 参考资料

* [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**为你的公司做广告**吗？或者你想要**获取最新版本的PEASS或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
