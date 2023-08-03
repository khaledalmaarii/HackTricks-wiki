# Seccomp

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 基本信息

**Seccomp**或安全计算模式，简而言之，是Linux内核的一个功能，可以充当**系统调用过滤器**。\
Seccomp有两种模式。

**seccomp**（安全计算模式）是Linux内核中的一种计算机安全功能。seccomp允许进程进入“安全”状态，其中**除了**`exit()`、`sigreturn()`、`read()`和`write()`之外，**它不能进行任何系统调用**。如果尝试进行其他系统调用，内核将使用SIGKILL或SIGSYS终止进程。从这个意义上说，它不会虚拟化系统的资源，而是完全将进程与它们隔离开来。

seccomp模式是通过使用`prctl(2)`系统调用启用的，使用`PR_SET_SECCOMP`参数，或者（自Linux内核3.17以来）通过`seccomp(2)`系统调用启用。seccomp模式曾经通过写入文件`/proc/self/seccomp`来启用，但这种方法已被`prctl()`取代。在某些内核版本中，seccomp禁用了`RDTSC` x86指令，该指令返回自上电以来经过的处理器周期数，用于高精度计时。

**seccomp-bpf**是seccomp的扩展，它允许使用可配置策略的Berkeley Packet Filter规则对系统调用进行过滤。它被OpenSSH和vsftpd以及Chrome OS和Linux上的Google Chrome/Chromium Web浏览器使用。（在这方面，seccomp-bpf实现了类似的功能，但具有更高的灵活性和性能，与不再支持Linux的旧版systrace相似。）

### **原始/严格模式**

在此模式下，Seccomp**仅允许使用**`exit()`、`sigreturn()`、`read()`和`write()`这些系统调用来操作已打开的文件描述符。如果进行了任何其他系统调用，进程将被使用SIGKILL终止。

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
### Seccomp-bpf

此模式允许使用可配置的策略来实现基于Berkeley Packet Filter规则的系统调用过滤。

{% code title="seccomp_bpf.c" %}
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
{% endcode %}

## Docker中的Seccomp

**Seccomp-bpf**被**Docker**支持，可以限制容器中的**系统调用**，从而有效减少攻击面。您可以在[https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/)找到**默认情况下被阻止的系统调用**，并且默认的seccomp配置文件可以在[https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)找到。\
您可以使用以下命令在docker容器中运行具有**不同seccomp策略**的容器：
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
如果你想禁止容器执行一些像 `uname` 这样的 **系统调用**，你可以从 [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) 下载默认配置文件，并从列表中**删除 `uname` 字符串**。\
如果你想确保**某个二进制文件在 Docker 容器内无法运行**，你可以使用 strace 列出二进制文件使用的系统调用，然后禁止它们。\
以下示例中发现了 `uname` 的**系统调用**：
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
{% hint style="info" %}
如果您只是使用Docker来启动一个应用程序，您可以使用`strace`对其进行**分析**，并**仅允许**它所需的系统调用
{% endhint %}

### 示例Seccomp策略

为了说明Seccomp功能，让我们创建一个禁用“chmod”系统调用的Seccomp配置文件，如下所示。
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
在上面的配置文件中，我们将默认操作设置为“允许”，并创建了一个黑名单来禁用“chmod”。为了更安全，我们可以将默认操作设置为“丢弃”，并创建一个白名单来选择性地启用系统调用。\
下面的输出显示了“chmod”调用返回错误，因为它在seccomp配置文件中被禁用了。
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
以下输出显示了“docker inspect”命令显示的配置文件：

```plaintext
$ docker inspect <container_id> -f '{{.HostConfig.SecurityOpt}}'
[
    "seccomp:unconfined"
]
```

The output above indicates that the container is running with the "seccomp:unconfined" security profile.
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
],
```
### 在Docker中禁用seccomp

使用标志`--security-opt seccomp=unconfined`启动一个容器。

从Kubernetes 1.19开始，**seccomp默认对所有Pod启用**。然而，默认应用于Pod的seccomp配置文件是由容器运行时（例如Docker、containerd）提供的“RuntimeDefault”配置文件。该“RuntimeDefault”配置文件允许大多数系统调用，同时阻止一些被认为是危险的或容器通常不需要的系统调用。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**Telegram群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
