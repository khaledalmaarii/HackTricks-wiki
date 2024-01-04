# macOS 文件、文件夹、二进制文件和内存

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks** 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## 文件层次结构布局

* **/Applications**: 已安装的应用程序应该在这里。所有用户都将能够访问它们。
* **/bin**: 命令行二进制文件
* **/cores**: 如果存在，用于存储核心转储
* **/dev**: 一切都被视为文件，因此您可能会在这里看到硬件设备。
* **/etc**: 配置文件
* **/Library**: 这里可以找到许多与偏好设置、缓存和日志相关的子目录和文件。根目录和每个用户的目录中都存在一个 Library 文件夹。
* **/private**: 未记录，但许多提到的文件夹都是指向私有目录的符号链接。
* **/sbin**: 与管理相关的基本系统二进制文件
* **/System**: 使 OS X 运行的文件。您应该在这里找到主要是 Apple 特定的文件（非第三方）。
* **/tmp**: 文件在 3 天后被删除（它是指向 /private/tmp 的软链接）
* **/Users**: 用户的主目录。
* **/usr**: 配置和系统二进制文件
* **/var**: 日志文件
* **/Volumes**: 挂载的驱动器将出现在这里。
* **/.vol**: 运行 `stat a.txt` 时，您会得到类似 `16777223 7545753 -rw-r--r-- 1 username wheel ...` 的内容，其中第一个数字是文件所在卷的 id 号，第二个数字是 inode 号。您可以通过 /.vol/ 使用这些信息运行 `cat /.vol/16777223/7545753` 来访问此文件的内容

### 应用程序文件夹

* **系统应用程序** 位于 `/System/Applications`
* **已安装** 应用程序通常安装在 `/Applications` 或 `~/Applications`
* **应用程序数据** 可以在 `/Library/Application Support` 中找到，用于以 root 身份运行的应用程序，以及 `~/Library/Application Support` 中，用于以用户身份运行的应用程序。
* 第三方应用程序 **守护进程** 需要以 root 身份运行，通常位于 `/Library/PrivilegedHelperTools/`
* **沙盒化** 应用程序映射到 `~/Library/Containers` 文件夹。每个应用程序都有一个根据应用程序包 ID 命名的文件夹（`com.apple.Safari`）。
* **内核** 位于 `/System/Library/Kernels/kernel`
* **Apple 的内核扩展** 位于 `/System/Library/Extensions`
* **第三方内核扩展** 存储在 `/Library/Extensions`

### 包含敏感信息的文件

MacOS 在多个位置存储密码等信息：

{% content-ref url="macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-sensitive-locations.md)
{% endcontent-ref %}

### 易受攻击的 pkg 安装程序

{% content-ref url="macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-installers-abuse.md)
{% endcontent-ref %}

## OS X 特定扩展

* **`.dmg`**: Apple 磁盘映像文件对于安装程序来说非常常见。
* **`.kext`**: 它必须遵循特定的结构，它是 OS X 版本的驱动程序。（它是一个包）
* **`.plist`**: 也称为属性列表，以 XML 或二进制格式存储信息。
* 可以是 XML 或二进制。二进制文件可以用以下方式读取：
* `defaults read config.plist`
* `/usr/libexec/PlistBuddy -c print config.plsit`
* `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
* `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
* `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
* **`.app`**: 遵循目录结构的 Apple 应用程序（它是一个包）。
* **`.dylib`**: 动态库（类似于 Windows DLL 文件）
* **`.pkg`**: 与 xar（可扩展存档格式）相同。安装命令可以用来安装这些文件的内容。
* **`.DS_Store`**: 每个目录中都有这个文件，它保存了目录的属性和自定义。
* **`.Spotlight-V100`**: 这个文件夹出现在系统上每个卷的根目录。
* **`.metadata_never_index`**: 如果这个文件位于卷的根目录，Spotlight 将不会索引该卷。
* **`.noindex`**: 带有此扩展名的文件和文件夹不会被 Spotlight 索引。

### macOS 包

基本上，包是文件系统中的**目录结构**。有趣的是，默认情况下，这个目录在 Finder 中**看起来像一个单一对象**（如 `.app`）。&#x20;

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Dyld 共享缓存

在 macOS（和 iOS）上，所有系统共享库，如框架和 dylibs，都**合并成一个文件**，称为 **dyld 共享缓存**。这提高了性能，因为代码可以更快地加载。

类似于 dyld 共享缓存，内核和内核扩展也被编译成内核缓存，在启动时加载。

为了从单个文件 dylib 共享缓存中提取库，过去可以使用二进制文件 [dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip)，但现在可能不再工作，您也可以使用 [**dyldextractor**](https://github.com/arandomdev/dyldextractor)：

{% code overflow="wrap" %}
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
{% endcode %}

在旧版本中，你可能能在 **`/System/Library/dyld/`** 找到 **共享缓存**。

在iOS中，你可以在 **`/System/Library/Caches/com.apple.dyld/`** 找到它们。

{% hint style="success" %}
请注意，即使 `dyld_shared_cache_util` 工具不起作用，你也可以将 **共享的 dyld 二进制文件传递给 Hopper**，Hopper 将能够识别所有库并让你 **选择** 你想要调查的库：
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (680).png" alt="" width="563"><figcaption></figcaption></figure>

## 特殊文件权限

### 文件夹权限

在一个 **文件夹** 中，**读** 权限允许 **列出内容**，**写** 权限允许 **删除** 和 **写入** 文件，而 **执行** 权限允许 **遍历** 目录。所以，例如，一个用户对目录内的 **文件有读权限**，但如果他在该目录中 **没有执行权限**，他 **将无法读取** 该文件。

### 标志修饰符

有些标志可以设置在文件上，这将使文件的行为不同。你可以用 `ls -lO /path/directory` **检查** 目录内文件的标志

* **`uchg`**: 也称为 **uchange** 标志，将 **防止任何更改** 或删除 **文件** 的操作。设置它请执行：`chflags uchg file.txt`
* 根用户可以 **移除标志** 并修改文件
* **`restricted`**: 此标志使文件受到 **SIP 保护**（你不能向文件添加此标志）。
* **`Sticky bit`**: 如果目录设置了 sticky bit，**只有** 目录所有者或根用户可以重命名或删除文件。通常这在 /tmp 目录上设置，以防止普通用户删除或移动其他用户的文件。

### **文件 ACLs**

文件 **ACLs** 包含 **ACE**（访问控制条目），可以为不同用户分配更 **细粒度的权限**。

可以授予 **目录** 这些权限：`list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`。\
对于 **文件**：`read`, `write`, `append`, `execute`。

当文件包含 ACLs 时，你会在列出权限时 **发现一个 "+"，如下所示**：
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
你可以使用以下命令**读取文件的 ACLs**：
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
你可以使用以下方法找到**所有带有ACLs的文件**（这个方法非常慢）：
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### 资源分叉 | macOS ADS

这是在**MacOS**机器中获取**Alternate Data Streams**的方法。您可以通过将内容保存在名为**com.apple.ResourceFork**的扩展属性中的文件里，通过保存在**file/..namedfork/rsrc**中来实现。
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
你可以**找到所有包含此扩展属性的文件**，使用：

{% code overflow="wrap" %}
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
{% endcode %}

## **通用二进制文件 &** Mach-o 格式

Mac OS 二进制文件通常被编译为**通用二进制文件**。一个**通用二进制文件**可以在同一个文件中**支持多个架构**。

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## macOS 内存转储

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## 风险类别文件 Mac OS

文件 `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` 包含了根据文件扩展名划分的文件相关风险。

可能的类别包括以下几种：

* **LSRiskCategorySafe**: **完全** **安全**；Safari 下载后会自动打开
* **LSRiskCategoryNeutral**: 没有警告，但**不会自动打开**
* **LSRiskCategoryUnsafeExecutable**: **触发**警告 “这个文件是一个应用程序...”
* **LSRiskCategoryMayContainUnsafeExecutable**: 用于可能包含可执行文件的存档之类的文件。除非 Safari 能确定所有内容都是安全或中性的，否则**会触发警告**。

## 日志文件

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: 包含下载文件的信息，比如它们的下载来源 URL。
* **`/var/log/system.log`**: OSX 系统的主日志。com.apple.syslogd.plist 负责执行系统日志记录（你可以通过在 `launchctl list` 中查找 "com.apple.syslogd" 来检查它是否被禁用）。
* **`/private/var/log/asl/*.asl`**: 这些是 Apple 系统日志，可能包含有趣的信息。
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: 存储通过 "Finder" 访问的最近文件和应用程序。
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: 存储系统启动时要启动的项目
* **`$HOME/Library/Logs/DiskUtility.log`**: DiskUtility 应用的日志文件（包括 USB 等驱动器的信息）
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: 关于无线接入点的数据。
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: 被停用的守护进程列表。

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>从零开始学习 AWS 黑客攻击！</strong></summary>

支持 HackTricks 的其他方式：

* 如果你想在 **HackTricks** 中看到你的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享你的黑客技巧**。

</details>
