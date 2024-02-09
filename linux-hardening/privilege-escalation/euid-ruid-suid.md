# euid, ruid, suid

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

* 您在**网络安全公司**工作吗？ 想要看到您的**公司在HackTricks中做广告**吗？ 或者想要访问**PEASS的最新版本或下载PDF格式的HackTricks**吗？ 请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 探索[**PEASS Family**](https://opensea.io/collection/the-peass-family)，我们独家[NFTs的收藏品**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上**关注**我 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>

### 用户识别变量

- **`ruid`**：**真实用户ID**表示启动进程的用户。
- **`euid`**：被称为**有效用户ID**，代表系统用于确定进程特权的用户身份。通常情况下，`euid`与`ruid`相同，除了像执行SetUID二进制文件这样的情况，其中`euid`会承担文件所有者的身份，从而授予特定的操作权限。
- **`suid`**：这个**保存的用户ID**在高特权进程（通常以root身份运行）需要暂时放弃特权以执行某些任务时至关重要，然后再恢复其初始的提升状态。

#### 重要说明
一个未以root身份运行的进程只能修改其`euid`以匹配当前的`ruid`、`euid`或`suid`。

### 理解set*uid函数

- **`setuid`**：与最初的假设相反，`setuid`主要修改`euid`而不是`ruid`。特别是对于特权进程，它将`ruid`、`euid`和`suid`与指定用户（通常是root）对齐，有效地由于覆盖`suid`而巩固这些ID。详细见[setuid man页面](https://man7.org/linux/man-pages/man2/setuid.2.html)。
- **`setreuid`**和**`setresuid`**：这些函数允许对`ruid`、`euid`和`suid`进行微妙的调整。但是，它们的功能取决于进程的特权级别。对于非root进程，修改受限于`ruid`、`euid`和`suid`的当前值。相反，具有`CAP_SETUID`能力的root进程或这些进程可以将这些ID分配任意值。更多信息请参阅[setresuid man页面](https://man7.org/linux/man-pages/man2/setresuid.2.html)和[setreuid man页面](https://man7.org/linux/man-pages/man2/setreuid.2.html)。

这些功能的设计不是作为安全机制，而是为了促进预期的操作流程，例如当程序通过更改其有效用户ID采用另一个用户的身份时。

值得注意的是，虽然`setuid`可能是提升到root的特权的常见选择（因为它将所有ID都与root对齐），但区分这些函数对于理解和操纵不同情况下的用户ID行为至关重要。

### Linux中的程序执行机制

#### **`execve`系统调用**
- **功能**：`execve`启动一个由第一个参数确定的程序。它接受两个数组参数，`argv`用于参数，`envp`用于环境。
- **行为**：保留调用者的内存空间，但刷新堆栈、堆和数据段。程序的代码被新程序替换。
- **用户ID保留**：
- `ruid`、`euid`和附加组ID保持不变。
- 如果新程序设置了SetUID位，`euid`可能会有微妙的变化。
- `suid`在执行后从`euid`更新。
- **文档**：详细信息请参阅[`execve` man页面](https://man7.org/linux/man-pages/man2/execve.2.html)。

#### **`system`函数**
- **功能**：与`execve`不同，`system`使用`fork`创建一个子进程，并在该子进程中使用`execl`执行命令。
- **命令执行**：通过`execl("/bin/sh", "sh", "-c", command, (char *) NULL);`执行命令。
- **行为**：由于`execl`是`execve`的一种形式，它的操作类似，但在新的子进程的上下文中进行。
- **文档**：更多见[`system` man页面](https://man7.org/linux/man-pages/man3/system.3.html)。

#### **`bash`和`sh`在SUID下的行为**
- **`bash`**：
- 具有`-p`选项影响`euid`和`ruid`的处理方式。
- 没有`-p`，如果`bash`最初设置`euid`与`ruid`不同，则将`euid`设置为`ruid`。
- 使用`-p`，保留初始`euid`。
- 更多细节请参阅[`bash` man页面](https://linux.die.net/man/1/bash)。
- **`sh`**：
- 不具有类似于`bash`中的`-p`机制。
- 关于用户ID的行为没有明确说明，除了在`-i`选项下，强调保持`euid`和`ruid`的相等性。
- 更多信息请参阅[`sh` man页面](https://man7.org/linux/man-pages/man1/sh.1p.html)。

这些机制在操作上各有不同，为执行和在程序之间转换提供了多样的选项，特定情况下对用户ID的管理和保留方式也有特定的细微差别。

### 在执行中测试用户ID行为

示例取自https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail，查看更多信息

#### 情况1：使用`setuid`与`system`

**目标**：了解`setuid`与`system`和`bash`作为`sh`结合的效果。

**C代码**：
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

* `ruid` 和 `euid` 起始值分别为 99 (nobody) 和 1000 (frank)。
* `setuid` 将两者都设置为 1000。
* 由于从 sh 到 bash 的符号链接，`system` 执行 `/bin/bash -c id`。
* `bash` 在没有 `-p` 的情况下，调整 `euid` 以匹配 `ruid`，导致两者都变为 99 (nobody)。

#### 情况 2: 使用 setreuid 与 system

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
**执行和结果:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**分析:**

* `setreuid` 将 ruid 和 euid 都设置为 1000。
* `system` 调用 bash，由于它们相等，有效地作为 frank 运行。

#### 情况 3: 使用 setuid 与 execve
目标: 探索 setuid 和 execve 之间的交互。
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
**执行和结果:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**分析:**

* `ruid` 保持为99，但 `euid` 被设置为1000，符合 `setuid` 的效果。

**C 代码示例 2 (调用 Bash):**
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
**分析:**

* 尽管`setuid`将`euid`设置为1000，但由于缺少`-p`，`bash`会将euid重置为`ruid`（99）。

**C代码示例3（使用bash -p）:**
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
## 参考资料
* [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


<details>

<summary><strong>从零开始学习AWS黑客技术</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* 您在**网络安全公司**工作吗？ 想要看到您的**公司在HackTricks中做广告**？ 或者您想要访问**PEASS的最新版本或下载HackTricks的PDF**？ 请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 发现我们的独家[NFTs收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS & HackTricks周边**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>
