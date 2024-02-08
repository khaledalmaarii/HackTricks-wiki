# macOS文件夹、文件和二进制文件 & 内存

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 文件层次结构

* **/Applications**：已安装的应用程序应位于此处。所有用户都可以访问它们。
* **/bin**：命令行二进制文件
* **/cores**：如果存在，用于存储核心转储
* **/dev**：一切都被视为文件，因此您可能会在此处看到存储的硬件设备。
* **/etc**：配置文件
* **/Library**：可以在此处找到许多与首选项、缓存和日志相关的子目录和文件。根目录和每个用户目录中都存在一个Library文件夹。
* **/private**：未记录，但许多提到的文件夹是符号链接到private目录。
* **/sbin**：基本系统二进制文件（与管理相关）
* **/System**：使OS X运行的文件。您应该在这里主要找到Apple特定的文件（而不是第三方文件）。
* **/tmp**：文件将在3天后被删除（这是指向/private/tmp的软链接）
* **/Users**：用户的主目录。
* **/usr**：配置和系统二进制文件
* **/var**：日志文件
* **/Volumes**：挂载的驱动器将出现在这里。
* **/.vol**：运行`stat a.txt`，您将获得类似`16777223 7545753 -rw-r--r-- 1 username wheel ...`的内容，其中第一个数字是文件存在的卷的ID号，第二个数字是索引节点号。您可以通过/.vol/访问具有该信息的文件的内容，运行`cat /.vol/16777223/7545753`

### 应用程序文件夹

* **系统应用程序**位于`/System/Applications`下
* **已安装的**应用程序通常安装在`/Applications`或`~/Applications`中
* **应用程序数据**可以在`/Library/Application Support`中找到，用于以root身份运行的应用程序，以及在`~/Library/Application Support`中找到，用于以用户身份运行的应用程序。
* **需要以root身份运行的第三方应用程序守护程序**通常位于`/Library/PrivilegedHelperTools/`
* **沙箱**应用程序映射到`~/Library/Containers`文件夹。每个应用程序都有一个根据应用程序的捆绑ID（`com.apple.Safari`）命名的文件夹。
* **内核**位于`/System/Library/Kernels/kernel`
* **Apple的内核扩展**位于`/System/Library/Extensions`
* **第三方内核扩展**存储在`/Library/Extensions`

### 包含敏感信息的文件

MacOS在多个位置存储诸如密码之类的信息：

{% content-ref url="macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-sensitive-locations.md)
{% endcontent-ref %}

### 有漏洞的pkg安装程序

{% content-ref url="macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-installers-abuse.md)
{% endcontent-ref %}

## OS X特定扩展

* **`.dmg`**：苹果磁盘映像文件在安装程序中非常常见。
* **`.kext`**：它必须遵循特定结构，是驱动程序的OS X版本（它是一个捆绑包）
* **`.plist`**：也称为属性列表，以XML或二进制格式存储信息。
* 可以是XML或二进制。可以使用以下命令读取二进制文件：
* `defaults read config.plist`
* `/usr/libexec/PlistBuddy -c print config.plsit`
* `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
* `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
* `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
* **`.app`**：遵循目录结构的苹果应用程序（它是一个捆绑包）。
* **`.dylib`**：动态库（类似于Windows的DLL文件）
* **`.pkg`**：与xar（eXtensible Archive格式）相同。可以使用installer命令安装这些文件的内容。
* **`.DS_Store`**：每个目录中都有此文件，它保存目录的属性和自定义。
* **`.Spotlight-V100`**：此文件夹出现在系统上每个卷的根目录中。
* **`.metadata_never_index`**：如果此文件位于卷的根目录中，Spotlight将不会索引该卷。
* **`.noindex`**：具有此扩展名的文件和文件夹不会被Spotlight索引。

### macOS捆绑包

捆绑包是一个**看起来像Finder中的对象的目录**（`*.app`文件是捆绑包的一个示例）。

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Dyld共享缓存

在macOS（和iOS）中，所有系统共享库，如框架和dylibs，都**合并到一个单个文件**中，称为**dyld共享缓存**。这提高了性能，因为代码可以更快地加载。

与dyld共享缓存类似，内核和内核扩展也编译到内核缓存中，在启动时加载。

为了从单个文件dylib共享缓存中提取库，可以使用二进制文件[dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip)，这可能在现在无法工作，但您也可以使用[**dyldextractor**](https://github.com/arandomdev/dyldextractor)：
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
{% endcode %}

在旧版本中，你可能会在 **`/System/Library/dyld/`** 中找到 **共享缓存**。

在 iOS 中，你可以在 **`/System/Library/Caches/com.apple.dyld/`** 中找到它们。

{% hint style="success" %}
请注意，即使 `dyld_shared_cache_util` 工具无法工作，你可以将 **共享 dyld 二进制文件传递给 Hopper**，Hopper 将能够识别所有库，并让你 **选择要调查的库**：
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (680).png" alt="" width="563"><figcaption></figcaption></figure>

## 特殊文件权限

### 文件夹权限

在一个 **文件夹** 中，**读取** 允许 **列出它**，**写入** 允许 **删除** 和 **写入** 文件，**执行** 允许 **遍历** 目录。因此，例如，一个用户具有 **文件夹内文件的读取权限**，但他 **没有执行权限** 的目录中，他将 **无法读取** 该文件。

### 标志修饰符

有一些标志可以设置在文件中，这些标志会使文件的行为不同。你可以使用 `ls -lO /path/directory` 命令来 **检查目录中文件的标志**

* **`uchg`**：被称为 **uchange** 标志，将 **阻止任何更改或删除** **文件** 的操作。要设置它，请执行：`chflags uchg file.txt`
* root 用户可以 **移除该标志** 并修改文件
* **`restricted`**：此标志使文件受到 **SIP 保护**（你无法将此标志添加到文件）。
* **`Sticky bit`**：如果一个目录具有粘性位，**只有** 目录的 **所有者或 root 用户可以重命名或删除** 文件。通常在 /tmp 目录上设置此标志，以防止普通用户删除或移动其他用户的文件。

### **文件 ACLs**

文件 **ACLs** 包含 **ACE**（访问控制条目），可以为不同用户分配更 **精细的权限**。

可以授予一个 **目录** 这些权限：`list`、`search`、`add_file`、`add_subdirectory`、`delete_child`、`delete_child`。\
对于一个 **文件**：`read`、`write`、`append`、`execute`。

当文件包含 ACLs 时，你将在列出权限时 **找到一个 "+"**，就像下面这样：
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
您可以使用以下命令**读取文件的 ACLs**：
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
您可以使用以下命令查找**所有具有ACL的文件**（这非常慢）：
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### 资源叉 | macOS ADS

这是在 macOS 机器上获取**备用数据流**的一种方法。您可以通过将内容保存在文件的**file/..namedfork/rsrc**中的扩展属性**com.apple.ResourceFork**中来保存文件内的内容。
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
您可以使用以下命令找到所有包含此扩展属性的文件：

{% code overflow="wrap" %}
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
## **通用二进制文件和** Mach-o 格式

Mac OS 二进制文件通常被编译为**通用二进制文件**。**通用二进制文件**可以在同一个文件中**支持多种架构**。

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## macOS 内存转储

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## Mac OS 风险类别文件

目录 `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` 存储了关于**不同文件扩展名风险**的信息。该目录将文件分类为不同的风险级别，影响 Safari 在下载后处理这些文件的方式。分类如下：

- **LSRiskCategorySafe**：此类文件被认为是**完全安全**的。Safari 将在下载后自动打开这些文件。
- **LSRiskCategoryNeutral**：这些文件没有警告，Safari **不会自动打开**它们。
- **LSRiskCategoryUnsafeExecutable**：此类文件会**触发警告**，指示该文件是一个应用程序。这是一项安全措施，用于警示用户。
- **LSRiskCategoryMayContainUnsafeExecutable**：此类文件为可能包含可执行文件的文件，例如存档文件。除非 Safari 能够验证所有内容是安全或中立，否则将**触发警告**。

## 日志文件

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**：包含有关已下载文件的信息，如下载它们的 URL。
* **`/var/log/system.log`**：OSX 系统的主要日志。com.apple.syslogd.plist 负责执行系统日志记录（您可以通过在 `launchctl list` 中查找 "com.apple.syslogd" 来检查是否已禁用）。
* **`/private/var/log/asl/*.asl`**：这些是可能包含有趣信息的 Apple 系统日志。
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**：存储通过“Finder”最近访问的文件和应用程序。
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**：存储系统启动时要启动的项目。
* **`$HOME/Library/Logs/DiskUtility.log`**：DiskUtility 应用程序的日志文件（包含有关驱动器的信息，包括 USB 设备）。
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**：关于无线接入点的数据。
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**：已停用的守护进程列表。
