# Docker 安全性

<details>

<summary><strong>从零到英雄学习 AWS 黑客技术，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧**。

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) 轻松构建并**自动化工作流程**，由世界上**最先进的**社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## **基本的 Docker 引擎安全性**

Docker 引擎负责运行和管理容器。Docker 引擎使用 Linux 内核功能，如 **Namespaces** 和 **Cgroups**，为容器提供基本的**隔离**。它还使用 **Capabilities dropping**、**Seccomp**、**SELinux/AppArmor** 等功能来实现更好的隔离。

最后，可以使用 **auth 插件**来**限制**用户可以执行的操作。

![](<../../../.gitbook/assets/image (625) (1) (1).png>)

### **Docker 引擎安全访问**

Docker 客户端可以通过 Unix 套接字本地访问 Docker 引擎，或者通过 http 机制远程访问。要远程使用它，需要使用 https 和 **TLS**，以确保保密性、完整性和认证。

默认情况下，它监听 Unix 套接字 `unix:///var/`\
`run/docker.sock`，在 Ubuntu 发行版中，Docker 启动选项在 `/etc/default/docker` 中指定。为了允许 Docker API 和客户端远程访问 Docker 引擎，我们需要**通过 http 套接字暴露 Docker 守护进程**。这可以通过以下方式完成：
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H
tcp://192.168.56.101:2376" -> add this to /etc/default/docker
Sudo service docker restart -> Restart Docker daemon
```
```markdown
通过http暴露Docker守护进程不是一个好做法，需要使用https来保护连接。有两个选项：第一个选项是**客户端验证服务器身份**，第二个选项是**客户端和服务器相互验证彼此的身份**。证书建立了服务器的身份。要查看这两个选项的示例，请[**查看此页面**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)。

### **容器镜像安全**

容器镜像存储在私有仓库或公共仓库中。以下是Docker提供的用于存储容器镜像的选项：

* [Docker hub](https://hub.docker.com) – 这是Docker提供的公共注册服务
* [Docker registry](https://github.com/%20docker/distribution) – 这是一个开源项目，用户可以用它来托管自己的注册表。
* [Docker trusted registry](https://www.docker.com/docker-trusted-registry) – 这是Docker的商业实现版本的Docker注册表，它提供基于角色的用户认证以及LDAP目录服务集成。

### 镜像扫描

容器可能因为基础镜像或者安装在基础镜像之上的软件而存在**安全漏洞**。Docker正在开发一个名为**Nautilus**的项目，该项目对容器进行安全扫描并列出漏洞。Nautilus通过将每个容器镜像层与漏洞仓库进行比较来识别安全漏洞。

要了解更多[**信息请阅读这个**](https://docs.docker.com/engine/scan/)。

* **`docker scan`**

**`docker scan`** 命令允许您使用镜像名称或ID扫描现有的Docker镜像。例如，运行以下命令来扫描hello-world镜像：
```
```bash
docker scan hello-world

Testing hello-world...

Organization:      docker-desktop-test
Package manager:   linux
Project name:      docker-image|hello-world
Docker image:      hello-world
Licenses:          enabled

✓ Tested 0 dependencies for known issues, no vulnerable paths found.

Note that we do not currently have vulnerability data for your image.
```
* [**`trivy`**](https://github.com/aquasecurity/trivy)
```bash
trivy -q -f json <ontainer_name>:<tag>
```
* [**`snyk`**](https://docs.snyk.io/snyk-cli/getting-started-with-the-cli)
```bash
snyk container test <image> --json-file-output=<output file> --severity-threshold=high
```
* [**`clair-scanner`**](https://github.com/arminc/clair-scanner)
```bash
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
### Docker 镜像签名

Docker 容器镜像可以存储在公共或私有注册表中。需要**签名**容器镜像以确认镜像未被篡改。内容**发布者**负责**签名**容器镜像并将其推送到注册表。\
以下是一些关于 Docker 内容信任的详细信息：

* Docker 内容信任是 [Notary 开源项目](https://github.com/docker/notary)的实现。Notary 开源项目基于 [The Update Framework (TUF) 项目](https://theupdateframework.github.io)。
* 通过 `export DOCKER_CONTENT_TRUST=1` **启用** Docker 内容**信任**。从 Docker 版本 1.10 开始，默认情况下**不启用**内容信任。
* **当**内容信任**启用**时，我们只能**拉取已签名的镜像**。推送镜像时，我们需要输入标签密钥。
* 当发布者**首次**使用 docker push **推送**镜像时，需要为**根密钥和标签密钥**输入**密码短语**。其他密钥会自动生成。
* Docker 还增加了对使用 Yubikey 的硬件密钥的支持，详情可查看[此处](https://blog.docker.com/2015/11/docker-content-trust-yubikey/)。

以下是**启用内容信任且镜像未签名**时我们会收到的**错误**。
```shell-session
$ docker pull smakam/mybusybox
Using default tag: latest
No trust data for latest
```
以下输出显示了**启用签名**的容器**镜像被推送到Docker hub**。由于这不是第一次，因此用户只被要求输入仓库密钥的密码短语。
```shell-session
$ docker push smakam/mybusybox:v2
The push refers to a repository [docker.io/smakam/mybusybox]
a7022f99b0cc: Layer already exists
5f70bf18a086: Layer already exists
9508eff2c687: Layer already exists
v2: digest: sha256:8509fa814029e1c1baf7696b36f0b273492b87f59554a33589e1bd6283557fc9 size: 2205
Signing and pushing trust metadata
Enter passphrase for repository key with ID 001986b (docker.io/smakam/mybusybox):
```
```markdown
需要将根密钥、仓库密钥以及密码短语存放在安全的地方。以下命令可用于备份私钥：
```
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
当我更换 Docker 主机时，我不得不将根密钥和仓库密钥移动到新主机上以进行操作。

***

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) 可以轻松构建并**自动化工作流程**，这些工作流程由世界上**最先进的**社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 容器安全特性

<details>

<summary>容器安全特性概述</summary>

**命名空间**

命名空间对于隔离项目非常有用，它可以隔离进程通信、网络、挂载等。它有助于将 Docker 进程与其他进程隔离（甚至是 `/proc` 文件夹），因此它不能通过滥用其他进程来逃逸。

使用二进制文件 **`unshare`**（它使用 **`unshare`** 系统调用）可能会“逃逸”，或者更确切地说，**创建新的命名空间**。Docker 默认情况下会阻止这种行为，但 Kubernetes 不会（在本文写作时）。\
无论如何，这有助于创建新的命名空间，但**无法返回到宿主机的默认命名空间**（除非你能访问宿主机命名空间内的某些 `/proc`，在那里你可以使用 **`nsenter`** 进入宿主机的命名空间。）。

**CGroups**

这允许限制资源，并且不影响进程隔离的安全性（除了 `release_agent` 可能被用来逃逸）。

**能力丢弃**

我认为这是关于进程隔离安全的**最重要**特性之一。这是因为，即使进程以 root 身份运行，如果没有这些能力，**你将无法执行某些特权操作**（因为被调用的 **`syscall`** 会返回权限错误，因为进程没有所需的能力）。

这些是进程丢弃其他能力后**剩余的能力**：

{% code overflow="wrap" %}
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
{% endcode %}

**Seccomp**

默认情况下在Docker中启用。它有助于**进一步限制进程可以调用的系统调用**。
可以在此处找到**默认的Docker Seccomp配置文件**：[https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)

**AppArmor**

Docker有一个你可以激活的模板：[https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

这将允许减少能力、系统调用、访问文件和文件夹等...

</details>

### Namespaces

**Namespaces** 是Linux内核的一个特性，它**划分内核资源**，使得一组**进程**看到一组资源，而**另一组**进程看到**不同**的资源集。该特性通过为一组资源和进程设置相同的命名空间来工作，但这些命名空间指向不同的资源。资源可能存在于多个空间中。

Docker利用以下Linux内核Namespaces来实现容器隔离：

* pid命名空间
* 挂载命名空间
* 网络命名空间
* ipc命名空间
* UTS命名空间

有关**更多关于命名空间的信息**，请查看以下页面：

{% content-ref url="namespaces/" %}
[namespaces](namespaces/)
{% endcontent-ref %}

### cgroups

Linux内核特性**cgroups**提供了能力来**限制像cpu、内存、io、网络带宽等资源**在一组进程之间。Docker允许使用cgroup特性创建容器，这允许对特定容器的资源进行控制。
以下是一个创建的容器，其用户空间内存限制为500m，内核内存限制为50m，cpu份额为512，blkioweight为400。CPU份额是一个控制容器CPU使用的比率。它的默认值为1024，范围在0到1024之间。如果三个容器有相同的CPU份额1024，在CPU资源争用的情况下，每个容器可以使用多达33%的CPU。blkio-weight是一个控制容器IO的比率。它的默认值为500，范围在10到1000之间。
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
要获取容器的 cgroup，您可以执行：
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
有关更多信息，请查看：

{% content-ref url="cgroups.md" %}
[cgroups.md](cgroups.md)
{% endcontent-ref %}

### Capabilities

Capabilities 允许对 root 用户可以允许的能力进行**更细致的控制**。Docker 使用 Linux 内核的 capability 功能来**限制容器内部可以执行的操作**，无论用户类型如何。

当运行 docker 容器时，**进程会放弃敏感的 capabilities，这些 capabilities 可能被用来逃离隔离**。这样尝试确保进程无法执行敏感操作并逃脱：

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

### Docker 中的 Seccomp

这是一个安全特性，允许 Docker **限制** 容器内部可以使用的系统调用：

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

### Docker 中的 AppArmor

**AppArmor** 是一种内核增强功能，用于将**容器**限制在一组**有限的**资源中，并具有**每个程序的配置文件**：

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

### Docker 中的 SELinux

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) 是一个**标签**系统。每个**进程**和每个文件系统对象都有一个**标签**。SELinux 策略定义了关于进程标签可以对系统上的所有其他标签执行哪些操作的规则。

容器引擎以单一受限的 SELinux 标签（通常为 `container_t`）启动**容器进程**，然后设置容器内部的容器被标记为 `container_file_t`。SELinux 策略规则基本上说，**`container_t` 进程只能读/写/执行标记为 `container_file_t` 的文件**。

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

### AuthZ & AuthN

授权插件根据当前的**认证**上下文和**命令**上下文**批准**或**拒绝**对 Docker **守护进程**的**请求**。**认证**上下文包含所有**用户详细信息**和**认证**方法。**命令上下文**包含所有相关的**请求**数据。

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## 容器导致的 DoS

如果你没有适当限制容器可以使用的资源，一个受损的容器可能会对其运行的宿主机进行 DoS 攻击。

* CPU DoS
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
* 带宽DoS
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## 有趣的 Docker 标志

### --privileged 标志

在以下页面中，您可以了解 **`--privileged` 标志的含义**：

{% content-ref url="docker-privileged.md" %}
[docker-privileged.md](docker-privileged.md)
{% endcontent-ref %}

### --security-opt

#### no-new-privileges

如果您运行的容器中，攻击者设法以低权限用户的身份获取访问权限。如果您有**配置错误的 suid 二进制文件**，攻击者可能会滥用它并**在容器内提升权限**。这可能允许他从中逃脱。

使用 **`no-new-privileges`** 选项启动容器将**防止这种类型的权限提升**。
```
docker run -it --security-opt=no-new-privileges:true nonewpriv
```
#### 其他
```bash
#You can manually add/drop capabilities with
--cap-add
--cap-drop

# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined

# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined

# You can manually disable selinux in docker with
--security-opt label:disable
```
```markdown
有关更多 **`--security-opt`** 选项，请查看：[https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## 其他安全考虑

### 管理秘密

首先，**不要将它们放入你的镜像中！**

同样，**不要使用环境变量**来存储你的敏感信息。任何可以运行 `docker inspect` 或进入容器的 `exec` 的人都能找到你的秘密。

Docker 卷更好。它们是 Docker 文档中推荐的访问敏感信息的方式。你可以**使用卷作为内存中的临时文件系统**。卷消除了 `docker inspect` 和日志记录的风险。然而，**root 用户仍然可以看到秘密，任何可以进入容器的 `exec` 的人也可以**。

甚至**比卷更好的是使用 Docker 秘密**。

如果你只需要在镜像中**保留秘密**，你可以使用 **BuildKit**。BuildKit 大幅缩短了构建时间，并且具有其他好处，包括 **构建时秘密支持**。

现在有三种方法指定 BuildKit 后端以便你可以使用它的功能：

1. 通过 `export DOCKER_BUILDKIT=1` 设置为环境变量。
2. 用 `DOCKER_BUILDKIT=1` 开始你的 `build` 或 `run` 命令。
3. 默认启用 BuildKit。在 /_etc/docker/daemon.json_ 中设置配置为 _true_：`{ "features": { "buildkit": true } }`。然后重启 Docker。
4. 然后你可以在构建时使用 `--secret` 标志，像这样：
```
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
在您的文件中指定密钥-值对作为您的秘密。

这些秘密不包括在镜像构建缓存中，也不包括在最终镜像中。

如果您需要在**运行中的容器**中使用您的**秘密**，而不仅仅是在构建镜像时，使用**Docker Compose或Kubernetes**。

使用Docker Compose时，将秘密的键值对添加到服务中，并指定秘密文件。感谢[Stack Exchange 回答](https://serverfault.com/a/936262/535325)提供的Docker Compose秘密技巧，下面的示例就是根据它改编的。

带有秘密的`docker-compose.yml`示例：
```yaml
version: "3.7"

services:

my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret

secrets:
my_secret:
file: ./my_secret_file.txt
```
```markdown
然后像往常一样使用 `docker-compose up --build my_service` 启动 Compose。

如果您正在使用 [Kubernetes](https://kubernetes.io/docs/concepts/configuration/secret/)，它支持 secrets。[Helm-Secrets](https://github.com/futuresimple/helm-secrets) 可以帮助简化在 K8s 中的 secrets 管理。此外，K8s 有基于角色的访问控制（RBAC） - Docker Enterprise 也是如此。RBAC 使得团队对 Secrets 管理更加容易和更安全。

### gVisor

**gVisor** 是一个用 Go 编写的应用程序内核，实现了 Linux 系统表面的大部分。它包括一个名为 `runsc` 的 [开放容器倡议 (OCI)](https://www.opencontainers.org) 运行时，提供了**应用程序与宿主内核之间的隔离边界**。`runsc` 运行时与 Docker 和 Kubernetes 集成，使得运行沙盒化容器变得简单。

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers** 是一个开源社区，致力于构建一个安全的容器运行时，使用轻量级虚拟机，这些虚拟机感觉和表现像容器，但使用硬件虚拟化技术作为第二层防御提供**更强的工作负载隔离**。

{% embed url="https://katacontainers.io/" %}

### 总结提示

* **不要使用 `--privileged` 标志或在容器内挂载** [**Docker 套接字**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**。** Docker 套接字允许生成容器，因此它是完全控制宿主的一种简单方式，例如，通过运行另一个带有 `--privileged` 标志的容器。
* **不要在容器内以 root 身份运行。使用** [**不同的用户**](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user) **和** [**用户命名空间**](https://docs.docker.com/engine/security/userns-remap/)**。** 容器中的 root 与宿主上的相同，除非使用用户命名空间重新映射。它主要受 Linux 命名空间、能力和 cgroups 的轻微限制。
* [**放弃所有能力**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`) 并仅启用所需的能力** (`--cap-add=...`)。许多工作负载不需要任何能力，添加它们会增加潜在攻击的范围。
* [**使用“no-new-privileges”安全选项**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) 防止进程获得更多权限，例如通过 suid 二进制文件。
* [**限制容器可用的资源**](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)**。** 资源限制可以保护机器免受拒绝服务攻击。
* **调整** [**seccomp**](https://docs.docker.com/engine/security/seccomp/)**,** [**AppArmor**](https://docs.docker.com/engine/security/apparmor/) **(或 SELinux)** 配置文件，将容器可用的操作和系统调用限制为最小所需。
* **使用** [**官方 docker 镜像**](https://docs.docker.com/docker-hub/official_images/) **并要求签名** 或基于它们构建自己的镜像。不要继承或使用 [后门](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/) 镜像。同时将根密钥、密码短语存放在安全的地方。Docker 计划使用 UCP 管理密钥。
* **定期** **重建** 镜像以**应用安全补丁到宿主和镜像。**
* 智能管理您的**秘密**，使攻击者难以访问它们。
* 如果您**暴露了 docker 守护进程，请使用 HTTPS** 并进行客户端和服务器认证。
* 在 Dockerfile 中，**优先使用 COPY 而不是 ADD**。ADD 会自动解压缩文件，并且可以从 URL 复制文件。COPY 没有这些功能。尽可能避免使用 ADD，以免受到远程 URL 和 Zip 文件的攻击。
* 为每个微服务**分别使用容器**
* **不要在容器内放置 ssh**，可以使用 “docker exec” 来 ssh 到容器。
* 有**更小**的容器**镜像**

## Docker Breakout / Privilege Escalation

如果您**在 docker 容器内**或者您有权访问**docker 组**中的用户，您可以尝试**逃逸和提升权限**：

{% content-ref url="docker-breakout-privilege-escalation/" %}
[docker-breakout-privilege-escalation](docker-breakout-privilege-escalation/)
{% endcontent-ref %}

## Docker Authentication Plugin Bypass

如果您有权访问 docker 套接字或者您有权访问**docker 组**中的用户，但您的操作受到 docker auth 插件的限制，请检查您是否可以**绕过它**：

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## 加固 Docker

* 工具 [**docker-bench-security**](https://github.com/docker/docker-bench-security) 是一个脚本，它检查了在生产中部署 Docker 容器时的几十个常见最佳实践。所有测试都是自动的，并基于 [CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/)。\
您需要从运行 docker 的宿主或具有足够权限的容器中运行该工具。了解**如何在 README 中运行它**：[**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security)。

## 参考资料

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://twitter.com/_fel1x/status/1151487051986087936](https://twitter.com/_fel1x/status/1151487051986087936)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/)
* [https://en.wikipedia.org/wiki/Linux_namespaces](https://en.wikipedia.org/wiki/Linux_namespaces)
* [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) 轻松构建和**自动化工作流程**，由世界上**最先进**的社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>从零开始学习 AWS 黑客攻击直到成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

其他支持 HackTricks 的方式：

* 如果您想在 HackTricks 中看到您的**公司广告**或**下载 HackTricks 的 PDF 版本**，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs**](https://opensea.io/collection/the-peass-family) 收藏
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>
```
