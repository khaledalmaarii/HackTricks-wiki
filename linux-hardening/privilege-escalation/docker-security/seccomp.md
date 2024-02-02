# Seccomp

<details>

<summary><strong>从零到英雄学习AWS黑客技术</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 基本信息

**Seccomp** 或安全计算模式，简而言之，是Linux内核的一个特性，可以作为**系统调用过滤器**。\
Seccomp有两种模式。

**seccomp**（即**安全计算模式**）是**Linux** **内核**中的一项计算机安全设施。seccomp允许进程一次性过渡到一个“安全”状态，在这个状态下，**它不能进行任何系统调用，除了** `exit()`、`sigreturn()`、`read()` 和 `write()` 到**已经打开的**文件描述符。如果它尝试进行任何其他系统调用，**内核**将用SIGKILL或SIGSYS**终止**该**进程**。从这个意义上讲，它不是虚拟化系统资源，而是完全隔离了进程和它们。

seccomp模式是**通过`prctl(2)`系统调用**使用`PR_SET_SECCOMP`参数启用的，或者（自Linux内核3.17版本起）通过`seccomp(2)`系统调用启用。seccomp模式过去是通过写入一个文件`/proc/self/seccomp`来启用的，但这种方法已被`prctl()`取代。在某些内核版本中，seccomp禁用了`RDTSC` x86指令，该指令返回自开机以来经过的处理器周期数，用于高精度计时。

**seccomp-bpf** 是seccomp的扩展，它允许**使用可配置的策略过滤系统调用**，该策略使用伯克利数据包过滤器规则实现。它被OpenSSH和vsftpd以及Chrome OS和Linux上的Google Chrome/Chromium网络浏览器使用。（在这方面，seccomp-bpf实现了类似的功能，但具有更大的灵活性和更高的性能，与较旧的systrace相比——后者似乎不再支持Linux。）

### **原始/严格模式**

在这种模式下，Seccomp **只允许系统调用** `exit()`、`sigreturn()`、`read()` 和 `write()` 到已经打开的文件描述符。如果进行了任何其他系统调用，进程将使用SIGKILL被杀死

{% code title="seccomp_strict.c" %}
```c
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>

//From https://sysdig.com/blog/selinux-seccomp-falco-technical-discussion/
//gcc seccomp_strict.c -o seccomp_strict

int main(int argc, char **argv)
{
int output = open("output.txt", O_WRONLY);
const char *val = "test";

//enables strict seccomp mode
printf("Calling prctl() to set seccomp strict mode...\n");
prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);

//This is allowed as the file was already opened
printf("Writing to an already open file...\n");
write(output, val, strlen(val)+1);

//This isn't allowed
printf("Trying to open file for reading...\n");
int input = open("output.txt", O_RDONLY);

printf("You will not see this message--the process will be killed first\n");
}
```
```markdown
{% endcode %}

### Seccomp-bpf

此模式允许**使用可配置策略过滤系统调用**，该策略使用 Berkeley Packet Filter 规则实现。

{% code title="seccomp_bpf.c" %}
```
```c
#include <seccomp.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

//https://security.stackexchange.com/questions/168452/how-is-sandboxing-implemented/175373
//gcc seccomp_bpf.c -o seccomp_bpf -lseccomp

void main(void) {
/* initialize the libseccomp context */
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);

/* allow exiting */
printf("Adding rule : Allow exit_group\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

/* allow getting the current pid */
//printf("Adding rule : Allow getpid\n");
//seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);

printf("Adding rule : Deny getpid\n");
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);
/* allow changing data segment size, as required by glibc */
printf("Adding rule : Allow brk\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);

/* allow writing up to 512 bytes to fd 1 */
printf("Adding rule : Allow write upto 512 bytes to FD 1\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
SCMP_A0(SCMP_CMP_EQ, 1),
SCMP_A2(SCMP_CMP_LE, 512));

/* if writing to any other fd, return -EBADF */
printf("Adding rule : Deny write to any FD except 1 \n");
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,
SCMP_A0(SCMP_CMP_NE, 1));

/* load and enforce the filters */
printf("Load rules and enforce \n");
seccomp_load(ctx);
seccomp_release(ctx);
//Get the getpid is denied, a weird number will be returned like
//this process is -9
printf("this process is %d\n", getpid());
}
```
## Docker 中的 Seccomp

**Seccomp-bpf** 被 **Docker** 支持，用于有效限制容器中的 **系统调用**，从而减少了攻击面。您可以在 [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) 找到 **默认情况下被阻止的系统调用**，并且可以在这里找到 **默认的 seccomp 配置文件** [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)。\
您可以使用以下命令运行一个具有 **不同 seccomp** 策略的 docker 容器：
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
如果您想要**禁止**容器执行某些**系统调用**，如 `uname`，您可以从 [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) 下载默认配置文件，并从列表中**移除 `uname` 字符串**。\
如果您想确保**某个二进制文件在 docker 容器内不起作用**，您可以使用 strace 列出该二进制文件正在使用的系统调用，然后禁止它们。\
在以下示例中，发现了 `uname` 的**系统调用**：
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
{% hint style="info" %}
如果您仅使用 **Docker 来启动应用程序**，您可以使用 **`strace`** 对其进行**分析**，并**仅允许它需要的系统调用**
{% endhint %}

### 示例 Seccomp 策略

为了说明 Seccomp 功能，让我们创建一个 Seccomp 配置文件，如下所示，禁用“chmod”系统调用。
```json
{
"defaultAction": "SCMP_ACT_ALLOW",
"syscalls": [
{
"name": "chmod",
"action": "SCMP_ACT_ERRNO"
}
]
}
```
在上述配置文件中，我们将默认操作设置为“允许”，并创建了一个黑名单来禁用“chmod”。为了更加安全，我们可以将默认操作设置为拒绝，并创建一个白名单来有选择地启用系统调用。
以下输出显示了“chmod”调用返回错误，因为它在seccomp配置文件中被禁用了。
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
以下输出显示了“docker inspect”显示的配置文件：
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
],
```
### 在Docker中停用它

启动容器时使用标志：**`--security-opt seccomp=unconfined`**

从Kubernetes 1.19开始，**所有Pods默认启用seccomp**。然而，应用于Pods的默认seccomp配置文件是"**RuntimeDefault**"配置文件，该配置文件是由**容器运行时**提供的（例如，Docker, containerd）。"RuntimeDefault"配置文件允许大多数系统调用，同时阻止一些被认为是危险的或通常不被容器所需的调用。

<details>

<summary><strong>从零开始学习AWS黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您希望在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
