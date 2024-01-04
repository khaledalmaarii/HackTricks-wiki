# macOS 安装程序滥用

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 HackTricks 中看到您的**公司广告**或**下载 HackTricks 的 PDF 版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## Pkg 基本信息

macOS **安装程序包**（也称为 `.pkg` 文件）是 macOS 用来**分发软件**的文件格式。这些文件就像一个**盒子，包含了软件安装和正确运行所需的一切**。

包文件本身是一个存档，包含了将要安装在目标计算机上的**文件和目录层次结构**。它还可以包括在安装前后执行任务的**脚本**，比如设置配置文件或清理软件的旧版本。

### 层次结构

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt=""><figcaption></figcaption></figure>

* **Distribution (xml)**：自定义（标题，欢迎文本等）和脚本/安装检查
* **PackageInfo (xml)**：信息，安装要求，安装位置，运行脚本的路径
* **Bill of materials (bom)**：列出要安装、更新或删除的文件及其文件权限
* **Payload (CPIO 归档 gzip 压缩)**：从 PackageInfo 中的 `install-location` 安装的文件
* **Scripts (CPIO 归档 gzip 压缩)**：安装前后脚本和更多资源，提取到临时目录中执行。

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
## DMG 基础信息

DMG 文件，或称为 Apple 磁盘映像，是 Apple 的 macOS 用于磁盘映像的文件格式。DMG 文件本质上是一个**可挂载的磁盘映像**（它包含自己的文件系统），通常包含原始块数据，这些数据通常是压缩的，有时是加密的。当你打开一个 DMG 文件时，macOS 会**将其挂载，就像它是一个物理磁盘一样**，允许你访问其内容。

### 层级结构

<figure><img src="../../../.gitbook/assets/image (12) (2).png" alt=""><figcaption></figcaption></figure>

DMG 文件的层级结构可以根据内容的不同而有所不同。然而，对于应用程序 DMG，它通常遵循以下结构：

* 顶层：这是磁盘映像的根目录。它通常包含应用程序，可能还有一个链接到应用程序文件夹。
* 应用程序 (.app)：这是实际的应用程序。在 macOS 中，应用程序通常是一个包，包含许多构成应用程序的单个文件和文件夹。
* 应用程序链接：这是 macOS 中应用程序文件夹的快捷方式。其目的是为了让你轻松安装应用程序。你可以将 .app 文件拖动到这个快捷方式上以安装应用程序。

## 通过 pkg 滥用提权

### 从公共目录执行

如果一个安装前或安装后的脚本例如是从 **`/var/tmp/Installerutil`** 执行的，攻击者可以控制该脚本，以便在执行时提升权限。或者另一个类似的例子：

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt=""><figcaption></figcaption></figure>

### AuthorizationExecuteWithPrivileges

这是一个[公共函数](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg)，许多安装程序和更新程序会调用它来**以 root 身份执行某些操作**。这个函数接受**文件**的**路径**作为参数来**执行**，然而，如果攻击者可以**修改**这个文件，他将能够**滥用**以 root 执行的权限来**提升权限**。
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
有关更多信息，请查看此演讲：[https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### 通过挂载执行

如果安装程序写入 `/tmp/fixedname/bla/bla`，可以在 `/tmp/fixedname` 上**创建一个挂载**并设置 noowners，这样你就可以在安装过程中**修改任何文件**来滥用安装过程。

这方面的一个例子是 **CVE-2021-26089**，它成功地**覆盖了一个周期性脚本**以获得 root 权限的执行。更多信息请查看演讲：[**OBTS v4.0：“Mount(ain) of Bugs” - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## 将 pkg 用作恶意软件

### 空负载

可以仅生成一个带有**安装前和安装后脚本**的 **`.pkg`** 文件，而无需任何负载。

### Distribution xml 中的 JS

可以在包的 **distribution xml** 文件中添加 **`<script>`** 标签，该代码将被执行，并且可以使用 **`system.run`** **执行命令**：

<figure><img src="../../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

## 参考资料

* [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0_zobQ)
* [**OBTS v4.0：“macOS 安装程序的狂野世界” - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)

<details>

<summary><strong>从零开始学习 AWS 黑客攻击直到成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果你想在 **HackTricks** 中看到你的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享你的黑客技巧**。

</details>
