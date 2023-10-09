# macOS文件、文件夹、二进制文件和内存

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 文件层次结构布局

* **/Applications**：已安装的应用程序应位于此处。所有用户都可以访问它们。
* **/bin**：命令行二进制文件
* **/cores**：如果存在，用于存储核心转储文件
* **/dev**：一切都被视为文件，因此您可能会在此处看到存储的硬件设备。
* **/etc**：配置文件
* **/Library**：可以在此处找到与首选项、缓存和日志相关的许多子目录和文件。根目录和每个用户目录中都存在一个Library文件夹。
* **/private**：未记录，但是许多提到的文件夹都是指向private目录的符号链接。
* **/sbin**：关键系统二进制文件（与管理相关）
* **/System**：使OS X运行的文件。您应该在这里找到主要是Apple特定文件（而不是第三方文件）。
* **/tmp**：文件将在3天后被删除（它是指向/private/tmp的软链接）
* **/Users**：用户的主目录。
* **/usr**：配置和系统二进制文件
* **/var**：日志文件
* **/Volumes**：挂载的驱动器将显示在此处。
* **/.vol**：运行`stat a.txt`，您将获得类似于`16777223 7545753 -rw-r--r-- 1 username wheel ...`的内容，其中第一个数字是文件所在卷的ID号，第二个数字是inode号。您可以通过/.vol/和这些信息访问此文件的内容，运行`cat /.vol/16777223/7545753`

### 应用程序文件夹

* **系统应用程序**位于`/System/Applications`下
* **已安装的**应用程序通常安装在`/Applications`或`~/Applications`中
* **应用程序数据**可以在`/Library/Application Support`中找到，用于以root身份运行的应用程序，以及在`~/Library/Application Support`中找到，用于以用户身份运行的应用程序。
* 需要以root身份运行的**第三方应用程序守护程序**通常位于`/Library/PrivilegedHelperTools/`中
* **沙盒化**的应用程序映射到`~/Library/Containers`文件夹中。每个应用程序都有一个根据应用程序的bundle ID（`com.apple.Safari`）命名的文件夹。
* **内核**位于`/System/Library/Kernels/kernel`
* **Apple的内核扩展**位于`/System/Library/Extensions`中
* **第三方内核扩展**存储在`/Library/Extensions`中

### 包含敏感信息的文件

MacOS将密码等信息存储在多个位置：

{% content-ref url="macos-sensitive-locations.md" %}
[macos-sensitive-locations.md](macos-sensitive-locations.md)
{% endcontent-ref %}

### 有漏洞的pkg安装程序

{% content-ref url="macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-installers-abuse.md)
{% endcontent-ref %}

## OS X特定扩展名

* **`.dmg`**：Apple磁盘映像文件在安装程序中非常常见。
* **`.kext`**：它必须遵循特定的结构，是驱动程序的OS X版本（它是一个bundle）。
* **`.plist`**：也称为属性列表，以XML或二进制格式存储信息。
* 可以是XML或二进制。可以使用以下命令读取二进制文件：
* `defaults read config.plist`
* `/usr/libexec/PlistBuddy -c print config.plsit`
* `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
* `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
* `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
* **`.app`**：遵循目录结构的Apple应用程序（它是一个bundle）。
* **`.dylib`**：动态库（类似于Windows的DLL文件）
* **`.pkg`**：与xar（可扩展存档格式）相同。可以使用installer命令安装这些文件的内容。
* **`.DS_Store`**：此文件位于每个目录中，保存目录的属性和自定义设置。
* **`.Spotlight-V100`**：此文件夹出现在系统上每个卷的根目录中。
* **`.metadata_never_index`**：如果此文件位于卷的根目录中，Spotlight将不会对该卷进行索引。
* **`.noindex`**：具有此扩展名的文件和文件夹将不会被Spotlight索引。
### macOS捆绑包

基本上，捆绑包是文件系统中的一个**目录结构**。有趣的是，默认情况下，这个目录在Finder中**看起来像一个单一的对象**（比如`.app`）。&#x20;

{% content-ref url="macos-bundles.md" %}
[macos-bundles.md](macos-bundles.md)
{% endcontent-ref %}

## Dyld共享缓存

在macOS（和iOS）中，所有系统共享库（如框架和dylib）都被**合并到一个单一文件**中，称为**dyld共享缓存**。这样可以提高性能，因为代码可以更快地加载。

类似于dyld共享缓存，内核和内核扩展也被编译成内核缓存，在启动时加载。

为了从单一文件dylib共享缓存中提取库，可以使用二进制工具[dyld\_shared\_cache\_util](https://www.mbsplugins.de/files/dyld\_shared\_cache\_util-dyld-733.8.zip)，但现在可能无法正常工作，您也可以使用[**dyldextractor**](https://github.com/arandomdev/dyldextractor)：

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

在旧版本中，您可能会在**`/System/Library/dyld/`**中找到**共享缓存**。

在iOS中，您可以在**`/System/Library/Caches/com.apple.dyld/`**中找到它们。

{% hint style="success" %}
请注意，即使`dyld_shared_cache_util`工具不起作用，您也可以将**共享dyld二进制文件传递给Hopper**，Hopper将能够识别所有库并让您**选择要调查的库**：
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (680).png" alt="" width="563"><figcaption></figcaption></figure>

## 特殊文件权限

### 文件夹权限

在**文件夹**中，**读取**允许**列出**它，**写入**允许**删除**和**写入**文件，**执行**允许**遍历**目录。因此，例如，一个用户对目录中的文件具有**读取权限**，但他对目录**没有执行权限**，则**无法读取**该文件。

### 标志修饰符

文件中可以设置一些标志，这些标志会使文件的行为不同。您可以使用`ls -lO /path/directory`命令**检查目录中文件的标志**。

* **`uchg`**：被称为**uchange**标志，将**阻止任何更改或删除文件的操作**。要设置它，请执行：`chflags uchg file.txt`
* root用户可以**删除该标志**并修改文件
* **`restricted`**：此标志使文件受到**SIP保护**（您无法将此标志添加到文件）。
* **`Sticky bit`**：如果目录具有粘性位，则**只有**目录的**所有者或root用户可以重命名或删除**文件。通常，这在/tmp目录上设置，以防止普通用户删除或移动其他用户的文件。

### **文件ACL**

文件**ACL**包含**ACE**（访问控制项），可以为不同的用户分配更**精细的权限**。

可以为**目录**授予以下权限：`list`、`search`、`add_file`、`add_subdirectory`、`delete_child`、`delete_child`。\
对于**文件**：`read`、`write`、`append`、`execute`。

当文件包含ACL时，您将在列出权限时**找到一个"+"**，如下所示：
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
您可以使用以下命令**读取文件的ACL**：
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
您可以使用以下命令（这个命令非常慢）找到**所有具有ACL的文件**：
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### 资源分支 | macOS ADS

这是一种在MacOS机器上获取**备用数据流(Alternate Data Streams)**的方法。您可以通过将内容保存在名为**com.apple.ResourceFork**的扩展属性中，并将其保存在**file/..namedfork/rsrc**中的文件中。
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
您可以使用以下命令**查找包含此扩展属性的所有文件**：

{% code overflow="wrap" %}
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
{% endcode %}

## **通用二进制文件和**Mach-o格式

Mac OS二进制文件通常被编译为**通用二进制文件**。**通用二进制文件**可以在同一个文件中**支持多个架构**。

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## macOS内存转储

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## 风险类别文件 Mac OS

文件`/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System`包含与文件扩展名相关的风险。

可能的类别包括以下内容：

* **LSRiskCategorySafe**：**完全安全**；Safari将在下载后自动打开
* **LSRiskCategoryNeutral**：没有警告，但**不会自动打开**
* **LSRiskCategoryUnsafeExecutable**：**触发**“此文件是应用程序...”的警告
* **LSRiskCategoryMayContainUnsafeExecutable**：适用于包含可执行文件的存档等内容。除非Safari可以确定所有内容都是安全或中性的，否则会**触发警告**。

## 日志文件

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**：包含有关下载文件的信息，例如下载文件的URL。
* **`/var/log/system.log`**：OSX系统的主要日志。com.apple.syslogd.plist负责执行syslogging（您可以通过查找`launchctl list`中的“com.apple.syslogd”来检查是否已禁用）。
* **`/private/var/log/asl/*.asl`**：这些是可能包含有趣信息的Apple系统日志。
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**：存储通过“Finder”最近访问的文件和应用程序。
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**：存储在系统启动时要启动的项目
* **`$HOME/Library/Logs/DiskUtility.log`**：DiskUtility应用程序的日志文件（包含有关驱动器（包括USB驱动器）的信息）
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**：关于无线访问点的数据。
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**：已停用的守护程序列表。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想获得最新版本的PEASS或下载PDF格式的HackTricks吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks衣物**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>
