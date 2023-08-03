# euid, ruid, suid

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品The PEASS Family](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>

**本文摘自** [**https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail**](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)

## **`*uid`**

* **`ruid`**: 这是启动进程的用户的**真实用户ID**。
* **`euid`**: 这是**有效用户ID**，是系统在决定**进程应具有的特权**时查找的值。在大多数情况下，`euid`将与`ruid`相同，但SetUID二进制文件是一个例外情况，它们的值不同。当SetUID二进制文件启动时，**`euid`设置为文件的所有者**，这使得这些二进制文件能够正常工作。
* `suid`: 这是**保存的用户ID**，当特权进程（大多数情况下以root身份运行）需要**放弃特权**以执行某些操作，但需要**恢复**到特权状态时使用。

{% hint style="info" %}
如果**非root进程**想要**更改其`euid`**，它只能将其设置为**`ruid`**、**`euid`**或**`suid`**的当前值。
{% endhint %}

## set\*uid

乍一看，很容易认为系统调用**`setuid`**会设置`ruid`。实际上，对于特权进程来说，确实如此。但在一般情况下，它实际上是**设置`euid`**。根据[man页面](https://man7.org/linux/man-pages/man2/setuid.2.html)：

> setuid() **设置调用进程的有效用户ID**。如果调用进程具有特权（更准确地说：如果进程在其用户命名空间中具有CAP\_SETUID功能），则还会设置实际UID和保存的设置用户ID。

因此，在以root身份运行`setuid(0)`的情况下，它将所有ID设置为root，并基本上将其锁定（因为`suid`为0，它丢失了任何先前用户的信息 - 当然，root进程可以更改为任何用户）。

两个不太常见的系统调用**`setreuid`**（`re`表示真实和有效）和**`setresuid`**（`res`包括保存的）设置了特定的ID。在非特权进程中，这些调用受到限制（来自[man页面](https://man7.org/linux/man-pages/man2/setresuid.2.html)对于`setresuid`，尽管`setreuid`的[页面](https://man7.org/linux/man-pages/man2/setreuid.2.html)有类似的语言）：

> 非特权进程可以将其**真实UID、有效UID和保存的设置用户ID**更改为以下之一：当前真实UID、当前有效UID或当前保存的设置用户ID。
>
> 特权进程（在Linux上，具有CAP\_SETUID功能的进程）可以将其真实UID、有效UID和保存的设置用户ID设置为任意值。

重要的是要记住，这些不是作为安全功能存在的，而是反映了预期的工作流程。当程序想要切换到另一个用户时，它会更改有效用户ID，以便可以以该用户的身份执行操作。

作为攻击者，很容易养成只调用`setuid`的坏习惯，因为最常见的情况是切换到root用户，在这种情况下，`setuid`实际上与`setresuid`相同。

## 执行

### **execve（和其他execs）**

`execve`系统调用执行第一个参数中指定的程序。第二个和第三个参数是数组，分别是参数（`argv`）和环境（`envp`）。还有几个基于`execve`的系统调用，称为`exec`（[man页面](https://man7.org/linux/man-pages/man3/exec.3.html)）。它们只是在`execve`之上提供不同的快捷方式调用`execve`的包装器。

关于它的工作原理，[man页面](https://man7.org/linux/man-pages/man2/execve.2.html)上有很多详细信息。简而言之，当**`execve`启动一个程序**时，它使用与调用程序相同的内存空间，替换该程序，并新启动堆栈、堆和数据段。它清除程序的代码并将新程序写入该空间。

那么，在调用`execve`时，`ruid`、`euid`和`suid`会发生什么变化？它不会更改与进程关联的元数据。man页面明确说明：

> 进程的真实UID和真实GID以及其附加组ID在调用execve()时**不会更改**。

对于`euid`有更多细微差别的描述，有一个更长的段落描述了发生的情况。不过，它主要关注新程序是否设置了SetUID位。假设不是这种情况，那么`execve`也不会更改`euid`。

在调用`execve`时，`suid`从`euid`复制过来：

> 进程的有效用户ID被复制到保存的设置用户ID；类似地，有效组ID被复制到保存的设置组ID。这种复制发生在由于设置用户ID和设置组ID模式位而发生的任何有效ID更改之后。
### **system**

`system`是一种完全不同的启动新进程的方法。`execve`在同一进程内的进程级别上操作，而**`system`使用`fork`创建一个子进程**，然后使用`execl`在该子进程中执行：

> ```
> execl("/bin/sh", "sh", "-c", command, (char *) NULL);
> ```

`execl`只是`execve`的一个包装器，它将字符串参数转换为`argv`数组并调用`execve`。需要注意的是**`system`使用`sh`来调用命令**。

### sh和bash的SUID <a href="#sh-and-bash-suid" id="sh-and-bash-suid"></a>

**`bash`**有一个**`-p`选项**，[man页面](https://linux.die.net/man/1/bash)将其描述为：

> 打开_特权_模式。在此模式下，**不处理$ENV和$BASH_ENV文件**，不从环境中继承shell函数，如果环境中出现**SHELLOPTS**、**BASHOPTS**、**CDPATH**和**GLOBIGNORE**变量，则忽略它们。如果shell以有效用户（组）ID不等于实际用户（组）ID启动，并且没有提供**-p选项**，则执行这些操作，并将**有效用户ID设置为实际用户ID**。如果在启动时提供了**-p**选项，则**不会重置有效用户ID**。关闭此选项会将有效用户和组ID设置为实际用户和组ID。

简而言之，如果没有`-p`，当运行Bash时，`euid`将设置为`ruid`。**`-p`可以防止这种情况**。

**`sh`** shell**没有类似的功能**。[man页面](https://man7.org/linux/man-pages/man1/sh.1p.html)没有提到“用户ID”，除非使用`-i`选项，该选项说明如下：

> \-i 指定shell为交互式；请参见下文。如果调用进程的实际用户ID不等于有效用户ID，或者实际组ID不等于有效组ID，则实现可能将指定-i选项视为错误。

## 测试

### setuid / system <a href="#setuid--system" id="setuid--system"></a>

有了这些背景知识，我将使用这段代码并逐步介绍在Jail（HTB）上发生的情况。
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
system("id");
return 0;
}
```
这个程序在NFS上编译并设置为SetUID在Jail中：
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
...[snip]...
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```
作为root用户，我可以看到这个文件：
```
[root@localhost nfsshare]# ls -l a
-rwsr-xr-x. 1 frank frank 16736 May 30 04:58 a
```
当我以nobody身份运行此命令时，`id`命令也会以nobody身份运行：
```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
该程序开始时，`ruid`为99（nobody），`euid`为1000（frank）。当它达到`setuid`调用时，这些值被设置。

然后调用`system`，我期望看到`uid`为99，但也有一个`euid`为1000。为什么没有呢？问题在于在这个发行版中，**`sh`被符号链接到`bash`**。
```
$ ls -l /bin/sh
lrwxrwxrwx. 1 root root 4 Jun 25  2017 /bin/sh -> bash
```
所以`system`调用`/bin/sh sh -c id`，实际上是`/bin/bash bash -c id`。当调用`bash`时，没有`-p`选项，它会看到`ruid`为99和`euid`为1000，并将`euid`设置为99。

### setreuid / system <a href="#setreuid--system" id="setreuid--system"></a>

为了验证这个理论，我将尝试用`setreuid`替换`setuid`：
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setreuid(1000, 1000);
system("id");
return 0;
}
```
编译和权限：
```
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
现在在Jail中，现在`id`命令返回的是uid为1000的值：
```
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
`setreuid`调用将`ruid`和`euid`都设置为1000，因此当`system`调用`bash`时，它们匹配，事情就像是frank一样继续进行。

### setuid / execve <a href="#setuid--execve" id="setuid--execve"></a>

如果我上面的理解是正确的，那么我也可以不用担心搞乱用户ID，而是调用`execve`，因为它会继承现有的ID。这样做是可行的，但也有陷阱。例如，常见的代码可能如下所示：
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/usr/bin/id", NULL, NULL);
return 0;
}
```
没有环境变量（为了简单起见，我传递了NULL），我需要在`id`上使用完整路径。这样可以正常工作，返回我期望的结果：
```
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
`[r]uid` 是99，但 `euid` 是1000。

如果我尝试从中获取一个shell，我必须小心。例如，只是调用 `bash`：
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/bin/bash", NULL, NULL);
return 0;
}
```
我将编译它并设置SetUID：
```
oxdf@hacky$ gcc d.c -o /mnt/nfsshare/d
oxdf@hacky$ chmod 4755 /mnt/nfsshare/d
```
然而，这将返回所有的nobody用户：
```
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
如果是`setuid(0)`，那么它将正常工作（假设进程有权限执行此操作），因为它会将所有三个ID都更改为0。但作为非root用户，这只会将`euid`设置为1000（它本来就是1000），然后调用`sh`。但是在Jail中，`sh`是`bash`。当`bash`以99的`ruid`和1000的`euid`启动时，它会将`euid`降回99。

为了解决这个问题，我将调用`bash -p`：
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
setuid(1000);
execve(paramList[0], paramList, NULL);
return 0;
}
```
这次有 `euid`：
```
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
或者我可以调用`setreuid`或`setresuid`而不是`setuid`。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud仓库](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>
