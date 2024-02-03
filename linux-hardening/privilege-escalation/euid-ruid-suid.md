# euid, ruid, suid

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 如果您在**网络安全公司**工作，想在**HackTricks**中看到您的**公司广告**，或者想要获取**PEASS的最新版本或下载HackTricks的PDF**？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS & HackTricks周边商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud仓库](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>

### 用户身份变量

- **`ruid`**: **真实用户ID**表示启动进程的用户。
- **`euid`**: 作为**有效用户ID**，它代表系统用来确定进程权限的用户身份。通常，`euid`与`ruid`相同，除非执行SetUID二进制文件时，`euid`会承担文件所有者的身份，从而授予特定的操作权限。
- **`suid`**: **保存的用户ID**在高权限进程（通常以root身份运行）需要临时放弃其权限以执行某些任务，然后再重新获得其最初的提升状态时至关重要。

#### 重要说明
非root操作的进程只能将其`euid`修改为当前的`ruid`、`euid`或`suid`。

### 理解set*uid函数

- **`setuid`**: 与最初的假设相反，`setuid`主要修改的是`euid`而不是`ruid`。具体来说，对于有权限的进程，它会将`ruid`、`euid`和`suid`与指定的用户（通常是root）对齐，由于覆盖了`suid`，这些ID因此变得固定。更多详细信息可以在[setuid手册页](https://man7.org/linux/man-pages/man2/setuid.2.html)中找到。
- **`setreuid`** 和 **`setresuid`**: 这些函数允许对`ruid`、`euid`和`suid`进行微妙的调整。然而，它们的能力取决于进程的权限级别。对于非root进程，修改限于`ruid`、`euid`和`suid`的当前值。相比之下，root进程或具有`CAP_SETUID`能力的进程可以为这些ID分配任意值。更多信息可以从[setresuid手册页](https://man7.org/linux/man-pages/man2/setresuid.2.html)和[setreuid手册页](https://man7.org/linux/man-pages/man2/setreuid.2.html)中获得。

这些功能的设计不是作为安全机制，而是为了促进预期的操作流程，例如当程序通过改变其有效用户ID来采用另一个用户的身份时。

值得注意的是，虽然`setuid`可能是提升到root权限的常用方法（因为它将所有ID对齐到root），但区分这些函数对于理解和操纵不同场景中的用户ID行为至关重要。

### Linux中的程序执行机制

#### **`execve` 系统调用**
- **功能**: `execve`通过第一个参数确定程序，并启动它。它接受两个数组参数，`argv`用于参数，`envp`用于环境。
- **行为**: 它保留调用者的内存空间，但刷新堆栈、堆和数据段。程序的代码被新程序替换。
- **用户ID保留**:
- `ruid`、`euid`和补充组ID保持不变。
- 如果新程序设置了SetUID位，`euid`可能会有细微变化。
- 执行后，`suid`从`euid`更新。
- **文档**: 更多详细信息可以在[`execve`手册页](https://man7.org/linux/man-pages/man2/execve.2.html)中找到。

#### **`system` 函数**
- **功能**: 与`execve`不同，`system`使用`fork`创建子进程，并使用`execl`在该子进程中执行命令。
- **命令执行**: 通过`sh`执行命令，使用`execl("/bin/sh", "sh", "-c", command, (char *) NULL);`。
- **行为**: 由于`execl`是`execve`的一种形式，它以类似的方式操作，但在新子进程的上下文中。
- **文档**: 更多洞见可以从[`system`手册页](https://man7.org/linux/man-pages/man3/system.3.html)中获得。

#### **带有SUID的`bash`和`sh`的行为**
- **`bash`**:
- 有一个`-p`选项，影响`euid`和`ruid`的处理方式。
- 没有`-p`时，如果`euid`和`ruid`最初不同，`bash`会将`euid`设置为`ruid`。
- 使用`-p`时，保留初始`euid`。
- 更多细节可以在[`bash`手册页](https://linux.die.net/man/1/bash)中找到。
- **`sh`**:
- 没有类似于`bash`中的`-p`机制。
- 关于用户ID的行为没有明确提及，除了在`-i`选项下，强调保持`euid`和`ruid`的相等。
- 额外信息可以在[`sh`手册页](https://man7.org/linux/man-pages/man1/sh.1p.html)中找到。

这些机制在操作上各不相同，为执行和转换程序提供了多样化的选择，具有在如何管理和保留用户ID方面的特定细微差别。

### 测试执行中的用户ID行为

示例取自https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail，更多信息请查看该网站

#### 案例1：结合`setuid`和`system`使用

**目标**: 理解结合`system`和作为`sh`的`bash`时`setuid`的效果。

**C代码**:
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
**编译和权限：**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**分析:**

* `ruid` 和 `euid` 分别以 99 (nobody) 和 1000 (frank) 开始。
* `setuid` 将两者都对齐到 1000。
* `system` 通过从 sh 到 bash 的符号链接执行 `/bin/bash -c id`。
* `bash`，如果没有 `-p`，会调整 `euid` 以匹配 `ruid`，导致两者都变为 99 (nobody)。

#### 案例 2: 使用 setreuid 与 system

**C 代码**:
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
**编译和权限：**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**执行和结果：**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**分析：**

* `setreuid` 将 ruid 和 euid 都设置为 1000。
* `system` 调用 bash，由于用户 ID 相等，bash 保持这些 ID，有效地作为 frank 操作。

#### 案例 3：结合 setuid 与 execve 使用
目标：探索 setuid 与 execve 之间的交互。
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/usr/bin/id", NULL, NULL);
return 0;
}
```
**执行和结果：**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**分析：**

* `ruid` 保持为 99，但 euid 被设置为 1000，符合 setuid 的效果。

**C 代码示例 2（调用 Bash）：**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/bin/bash", NULL, NULL);
return 0;
}
```
**执行和结果：**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**分析：**

* 尽管 `setuid` 将 `euid` 设置为1000，但由于缺少 `-p`，`bash` 将 euid 重置为 `ruid` (99)。
```bash
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
**执行和结果：**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
# 参考资料
* [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 如果你在一家**网络安全公司**工作，想在**HackTricks**上看到你的**公司广告**，或者想要获取**PEASS最新版本或下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)收藏。
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud仓库](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧。**

</details>
