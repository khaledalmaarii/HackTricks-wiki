# macOS文件夹、文件和二进制文件与内存

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

- 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
- 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品
- **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
- 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 文件层次结构

- **/Applications**：已安装的应用程序应位于此处。所有用户都可以访问它们。
- **/bin**：命令行二进制文件
- **/cores**：如果存在，用于存储核心转储
- **/dev**：一切都被视为文件，因此您可能会在此处看到存储的硬件设备。
- **/etc**：配置文件
- **/Library**：可以在此处找到许多与首选项、缓存和日志相关的子目录和文件。根目录和每个用户目录中都存在一个Library文件夹。
- **/private**：未记录，但许多提到的文件夹是符号链接到私有目录的。
- **/sbin**：基本系统二进制文件（与管理相关）
- **/System**：使OS X运行的文件。您应该在这里主要只找到Apple特定的文件（而不是第三方文件）。
- **/tmp**：文件将在3天后被删除（这是指向/private/tmp的软链接）
- **/Users**：用户的主目录。
- **/usr**：配置和系统二进制文件
- **/var**：日志文件
- **/Volumes**：挂载的驱动器将出现在这里。
- **/.vol**：运行`stat a.txt`，您将获得类似`16777223 7545753 -rw-r--r-- 1 username wheel ...`的内容，其中第一个数字是文件所在卷的ID号，第二个数字是索引节点号。您可以通过/.vol/访问具有该信息的文件的内容，运行`cat /.vol/16777223/7545753`

### 应用程序文件夹

- **系统应用程序**位于`/System/Applications`
- **已安装的**应用程序通常安装在`/Applications`或`~/Applications`
- **应用程序数据**可以在`/Library/Application Support`中找到，用于以root身份运行的应用程序，以及在`~/Library/Application Support`中找到，用于以用户身份运行的应用程序。
- **需要以root身份运行**的第三方应用程序**守护程序**通常位于`/Library/PrivilegedHelperTools/`
- **沙箱**应用程序映射到`~/Library/Containers`文件夹。每个应用程序都有一个根据应用程序的捆绑ID（`com.apple.Safari`）命名的文件夹。
- **内核**位于`/System/Library/Kernels/kernel`
- **Apple的内核扩展**位于`/System/Library/Extensions`
- **第三方内核扩展**存储在`/Library/Extensions`

### 包含敏感信息的文件

macOS在几个位置存储诸如密码之类的信息：

{% content-ref url="macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-sensitive-locations.md)
{% endcontent-ref %}

### 有漏洞的pkg安装程序

{% content-ref url="macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-installers-abuse.md)
{% endcontent-ref %}

## OS X特定扩展

- **`.dmg`**：苹果磁盘映像文件在安装程序中非常常见。
- **`.kext`**：它必须遵循特定结构，是驱动程序的OS X版本（它是一个捆绑包）。
- **`.plist`**：也称为属性列表，以XML或二进制格式存储信息。
- 可以是XML或二进制。可以使用以下命令读取二进制文件：
  - `defaults read config.plist`
  - `/usr/libexec/PlistBuddy -c print config.plsit`
  - `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
  - `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
  - `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**：遵循目录结构的苹果应用程序（它是一个捆绑包）。
- **`.dylib`**：动态库（类似于Windows的DLL文件）
- **`.pkg`**：与xar（可扩展存档格式）相同。可以使用installer命令安装这些文件的内容。
- **`.DS_Store`**：每个目录中都有此文件，它保存目录的属性和自定义。
- **`.Spotlight-V100`**：此文件夹出现在系统上每个卷的根目录上。
- **`.metadata_never_index`**：如果此文件位于卷的根目录中，Spotlight将不会索引该卷。
- **`.noindex`**：具有此扩展名的文件和文件夹不会被Spotlight索引。
- **`.sdef`**：捆绑包中的文件指定如何从AppleScript与应用程序进行交互。

### macOS捆绑包

捆绑包是一个**看起来像Finder中的对象的目录**（`*.app`文件是捆绑包的一个示例）。

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Dyld共享缓存

在macOS（和iOS）中，所有系统共享库，如框架和dylibs，都**合并到一个单个文件**中，称为**dyld共享缓存**。这提高了性能，因为代码可以更快地加载。

与dyld共享缓存类似，内核和内核扩展也编译到内核缓存中，在引导时加载。

为了从单个文件dylib共享缓存中提取库，可以使用二进制文件[dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip)，这可能在现在无法工作，但您也可以使用[**dyldextractor**](https://github.com/arandomdev/dyldextractor)：
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
{% endcode %}

在旧版本中，您可能会在 **`/System/Library/dyld/`** 中找到 **共享缓存**。

在 iOS 中，您可以在 **`/System/Library/Caches/com.apple.dyld/`** 中找到它们。

{% hint style="success" %}
请注意，即使 `dyld_shared_cache_util` 工具无法工作，您也可以将 **共享 dyld 二进制文件传递给 Hopper**，Hopper 将能够识别所有库并让您 **选择要调查的库**：
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (1149).png" alt="" width="563"><figcaption></figcaption></figure>

## 特殊文件权限

### 文件夹权限

在一个 **文件夹** 中，**读取** 允许 **列出它**，**写入** 允许 **删除** 和 **写入** 文件，**执行** 允许 **遍历** 目录。因此，例如，一个用户对目录中的 **文件具有读取权限**，但他 **没有执行权限**，则 **无法读取** 该文件。

### 标志修饰符

有一些标志可以设置在文件中，使文件的行为不同。您可以使用 `ls -lO /path/directory` 命令 **检查目录中文件的标志**

* **`uchg`**：被称为 **uchange** 标志，将 **阻止任何更改或删除** **文件** 的操作。要设置它，请执行：`chflags uchg file.txt`
* root 用户可以 **移除该标志** 并修改文件
* **`restricted`**：此标志使文件受到 SIP 的保护（无法将此标志添加到文件）。
* **`Sticky bit`**：如果一个目录具有粘性位，**只有** 目录的 **所有者或 root 可以重命名或删除** 文件。通常在 /tmp 目录上设置此标志，以防止普通用户删除或移动其他用户的文件。

所有标志都可以在文件 `sys/stat.h` 中找到（使用 `mdfind stat.h | grep stat.h` 查找），包括：

* `UF_SETTABLE` 0x0000ffff：可更改所有者标志的掩码。
* `UF_NODUMP` 0x00000001：不要转储文件。
* `UF_IMMUTABLE` 0x00000002：文件不得更改。
* `UF_APPEND` 0x00000004：只能追加写入文件。
* `UF_OPAQUE` 0x00000008：目录对于联合是不透明的。
* `UF_COMPRESSED` 0x00000020：文件已压缩（某些文件系统）。
* `UF_TRACKED` 0x00000040：设置此标志的文件不会收到删除/重命名的通知。
* `UF_DATAVAULT` 0x00000080：需要读取和写入的授权。
* `UF_HIDDEN` 0x00008000：提示不应在 GUI 中显示此项。
* `SF_SUPPORTED` 0x009f0000：超级用户支持的标志掩码。
* `SF_SETTABLE` 0x3fff0000：超级用户可更改的标志掩码。
* `SF_SYNTHETIC` 0xc0000000：系统只读合成标志的掩码。
* `SF_ARCHIVED` 0x00010000：文件已存档。
* `SF_IMMUTABLE` 0x00020000：文件不得更改。
* `SF_APPEND` 0x00040000：只能追加写入文件。
* `SF_RESTRICTED` 0x00080000：需要写入的授权。
* `SF_NOUNLINK` 0x00100000：项目不得被移除、重命名或挂载。
* `SF_FIRMLINK` 0x00800000：文件是一个 firmlink。
* `SF_DATALESS` 0x40000000：文件是无数据对象。

### **文件 ACLs**

文件 **ACLs** 包含 **ACE**（访问控制条目），可以为不同用户分配更多 **细粒度权限**。

可以授予一个 **目录** 这些权限：`list`、`search`、`add_file`、`add_subdirectory`、`delete_child`、`delete_child`。\
对于一个 **文件**：`read`、`write`、`append`、`execute`。

当文件包含 ACLs 时，您将在列出权限时 **找到一个 "+"**，就像在下面的示例中一样：
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
您可以使用以下命令**读取文件的 ACL**：
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
您可以使用以下命令查找**所有具有ACL的文件**（这非常慢）：
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### 扩展属性

扩展属性具有名称和任何所需的值，可以使用 `ls -@` 查看，并使用 `xattr` 命令进行操作。一些常见的扩展属性包括：

- `com.apple.resourceFork`: 资源叉兼容性。也可在 `filename/..namedfork/rsrc` 中看到
- `com.apple.quarantine`: MacOS: Gatekeeper 隔离机制 (III/6)
- `metadata:*`: MacOS: 各种元数据，如 `_backup_excludeItem` 或 `kMD*`
- `com.apple.lastuseddate` (#PS): 最后使用日期
- `com.apple.FinderInfo`: MacOS: Finder 信息（例如，颜色标签）
- `com.apple.TextEncoding`: 指定 ASCII 文本文件的文本编码
- `com.apple.logd.metadata`: 由 `/var/db/diagnostics` 中的 logd 在文件上使用
- `com.apple.genstore.*`: 生成存储 (`/.DocumentRevisions-V100` 在文件系统根目录中)
- `com.apple.rootless`: MacOS: 由系统完整性保护使用以标记文件 (III/10)
- `com.apple.uuidb.boot-uuid`: 具有唯一 UUID 的引导时期的 logd 标记
- `com.apple.decmpfs`: MacOS: 透明文件压缩 (II/7)
- `com.apple.cprotect`: \*OS: 每个文件的加密数据 (III/11)
- `com.apple.installd.*`: \*OS: installd 使用的元数据，例如 `installType`、`uniqueInstallID`

### 资源叉 | macOS ADS

这是在 MacOS 机器中获取**备用数据流**的一种方法。您可以通过将内容保存在名为 **com.apple.ResourceFork** 的扩展属性中的文件中来保存在 **file/..namedfork/rsrc** 中。
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
{% endcode %}

### decmpfs

扩展属性 `com.apple.decmpfs` 表示文件已加密，`ls -l` 将报告**大小为 0**，压缩数据位于此属性中。每当访问文件时，它将在内存中解密。

可以使用 `ls -lO` 查看此属性，因为压缩文件还会标记为标志 `UF_COMPRESSED`。如果删除压缩文件，则使用 `chflags nocompressed </path/to/file>` 删除此标志，系统将不知道文件已被压缩，因此无法解压缩和访问数据（系统会认为文件实际上是空的）。

工具 afscexpand 可用于强制解压缩文件。

## **通用二进制文件 &** Mach-o 格式

Mac OS 二进制文件通常编译为**通用二进制文件**。**通用二进制文件** 可以**在同一文件中支持多个架构**。

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## macOS 内存转储

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## Mac OS 风险类别文件

目录 `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` 存储有关不同文件扩展名的**风险级别信息**。该目录将文件分类为不同的风险级别，影响 Safari 在下载后如何处理这些文件。分类如下：

* **LSRiskCategorySafe**：此类文件被认为**完全安全**。Safari 将在下载后自动打开这些文件。
* **LSRiskCategoryNeutral**：这些文件没有警告，Safari **不会自动打开**它们。
* **LSRiskCategoryUnsafeExecutable**：此类文件会**触发警告**，指示文件是一个应用程序。这是一项安全措施，用于提醒用户。
* **LSRiskCategoryMayContainUnsafeExecutable**：此类文件，如存档文件，可能包含可执行文件。除非 Safari 可以验证所有内容是安全或中立，否则 Safari 将**触发警告**。

## 日志文件

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**：包含有关下载文件的信息，如下载文件的 URL。
* **`/var/log/system.log`**：OSX 系统的主要日志。com.apple.syslogd.plist 负责执行系统日志记录（您可以通过在 `launchctl list` 中查找 "com.apple.syslogd" 来检查是否已禁用）。
* **`/private/var/log/asl/*.asl`**：这些是可能包含有趣信息的 Apple 系统日志。
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**：存储通过“Finder”最近访问的文件和应用程序。
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**：存储系统启动时要启动的项目。
* **`$HOME/Library/Logs/DiskUtility.log`**：DiskUtility 应用程序的日志文件（包含有关驱动器的信息，包括 USB 设备）。
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**：关于无线访问点的数据。
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**：已停用的守护进程列表。
