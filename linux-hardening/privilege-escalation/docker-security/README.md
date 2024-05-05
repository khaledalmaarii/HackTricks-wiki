# Docker安全

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT收藏品](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和**自动化工作流程**，使用世界上**最先进**的社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## **基本Docker引擎安全性**

**Docker引擎**利用Linux内核的**命名空间**和**Cgroups**来隔离容器，提供基本的安全层。通过**降低权限**、**Seccomp**和**SELinux/AppArmor**提供额外的保护，增强容器隔离性。**认证插件**可以进一步限制用户操作。

![Docker安全](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### 安全访问Docker引擎

Docker引擎可以通过Unix套接字本地访问，也可以通过HTTP远程访问。对于远程访问，必须使用HTTPS和**TLS**来确保机密性、完整性和身份验证。

默认情况下，Docker引擎在Unix套接字`unix:///var/run/docker.sock`上监听。在Ubuntu系统上，Docker的启动选项定义在`/etc/default/docker`中。要启用对Docker API和客户端的远程访问，请添加以下设置：
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
然而，由于安全问题，不建议通过HTTP公开Docker守护程序。建议使用HTTPS来保护连接。有两种主要方法来保护连接：

1. 客户端验证服务器的身份。
2. 客户端和服务器相互验证彼此的身份。

证书用于确认服务器的身份。有关这两种方法的详细示例，请参考[**此指南**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)。

### 容器镜像的安全性

容器镜像可以存储在私有或公共存储库中。Docker为容器镜像提供了几种存储选项：

* [**Docker Hub**](https://hub.docker.com)：Docker提供的公共注册服务。
* [**Docker Registry**](https://github.com/docker/distribution)：允许用户托管自己的注册表的开源项目。
* [**Docker Trusted Registry**](https://www.docker.com/docker-trusted-registry)：Docker的商业注册服务，具有基于角色的用户身份验证和与LDAP目录服务集成的功能。

### 镜像扫描

容器可能存在**安全漏洞**，这可能是由于基础镜像或安装在基础镜像之上的软件导致的。Docker正在开发一个名为**Nautilus**的项目，用于对容器进行安全扫描并列出漏洞。Nautilus通过将每个容器镜像层与漏洞存储库进行比较来识别安全漏洞。

有关更多[**信息，请阅读此处**](https://docs.docker.com/engine/scan/)。

* **`docker scan`**

**`docker scan`**命令允许您使用镜像名称或ID扫描现有的Docker镜像。例如，运行以下命令来扫描hello-world镜像：
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
trivy -q -f json <container_name>:<tag>
```
* [**`snyk`**](https://docs.snyk.io/snyk-cli/getting-started-with-the-cli)
```bash
snyk container test <image> --json-file-output=<output file> --severity-threshold=high
```
* [**`clair-scanner`**](https://github.com/arminc/clair-scanner)
```bash
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
### Docker镜像签名

Docker镜像签名确保容器中使用的镜像的安全性和完整性。以下是简要说明：

- **Docker内容信任**利用Notary项目，基于The Update Framework (TUF)，来管理镜像签名。有关更多信息，请参阅[Notary](https://github.com/docker/notary)和[TUF](https://theupdateframework.github.io)。
- 要激活Docker内容信任，请设置 `export DOCKER_CONTENT_TRUST=1`。此功能在Docker版本1.10及更高版本中默认处于关闭状态。
- 启用此功能后，只能下载已签名的镜像。初始镜像推送需要为根密钥和标记密钥设置密码，Docker还支持Yubikey以提高安全性。更多详细信息可在[此处](https://blog.docker.com/2015/11/docker-content-trust-yubikey/)找到。
- 在启用内容信任的情况下尝试拉取未签名的镜像会导致“最新版本无信任数据”错误。
- 对于第一次之后的镜像推送，Docker会要求输入存储库密钥的密码以对镜像进行签名。

要备份您的私钥，请使用以下命令：
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
在切换Docker主机时，需要移动根密钥和存储库密钥以保持运行。

***

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) 可以轻松构建和**自动化工作流**，利用世界上**最先进**的社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 容器安全功能

<details>

<summary>容器安全功能摘要</summary>

**主要进程隔离功能**

在容器化环境中，隔离项目及其进程对于安全和资源管理至关重要。以下是关键概念的简化解释：

**命名空间**

* **目的**：确保资源（如进程、网络和文件系统）的隔离。特别是在Docker中，命名空间将容器的进程与主机和其他容器分开。
* **`unshare`的用途**：使用`unshare`命令（或底层系统调用）来创建新的命名空间，提供额外的隔离层。然而，尽管Kubernetes本身不会阻止此操作，但Docker会。
* **限制**：创建新的命名空间不允许进程恢复到主机的默认命名空间。要穿透主机命名空间，通常需要访问主机的`/proc`目录，并使用`nsenter`进行进入。

**控制组（CGroups）**

* **功能**：主要用于在进程之间分配资源。
* **安全方面**：CGroups本身并不提供隔离安全性，除了`release_agent`功能，如果配置不当，可能会被利用以获取未经授权的访问权限。

**能力降级**

* **重要性**：对于进程隔离是一个关键的安全功能。
* **功能**：通过放弃某些能力，限制根进程可以执行的操作。即使进程以root权限运行，如果缺少必要的能力，由于权限不足，系统调用将失败，从而阻止执行特权操作。

这些是进程放弃其他能力后的**剩余能力**：

{% code overflow="wrap" %}
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
{% endcode %}

### Seccomp

默认情况下在Docker中启用。它有助于**进一步限制**进程可以调用的系统调用。\
**默认的Docker Seccomp配置文件**可以在[https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)找到

### AppArmor

Docker有一个可以激活的模板：[https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

这将允许减少功能、系统调用、对文件和文件夹的访问...

</details>

### 命名空间

**命名空间**是Linux内核的一个功能，**将内核资源分区**，使得一组**进程**看到一组**资源**，而**另一组**进程看到**不同**的资源。该功能通过为一组资源和进程使用相同的命名空间，但这些命名空间指的是不同的资源来实现。资源可以存在于多个空间中。

Docker利用以下Linux内核命名空间来实现容器隔离：

* pid命名空间
* mount命名空间
* network命名空间
* ipc命名空间
* UTS命名空间

有关**命名空间的更多信息**，请查看以下页面：

{% content-ref url="namespaces/" %}
[namespaces](namespaces/)
{% endcontent-ref %}

### cgroups

Linux内核功能**cgroups**提供了限制资源（如CPU、内存、IO、网络带宽等）在一组进程中的能力。Docker允许使用cgroup功能创建容器，从而实现对特定容器的资源控制。\
以下是一个使用用户空间内存限制为500m、内核内存限制为50m、CPU份额为512、blkioweight为400创建的容器。CPU份额是控制容器CPU使用率的比率。它的默认值为1024，范围在0到1024之间。如果三个容器的CPU份额都是1024，则在CPU资源争用的情况下，每个容器最多可以占用CPU的33%。blkio-weight是控制容器IO的比率。它的默认值为500，范围在10到1000之间。
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
要获取容器的 cgroup，您可以执行：
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
### 权限

权限允许对root用户允许的权限进行更精细的控制。Docker使用Linux内核的权限功能来限制容器内可以执行的操作，无论用户类型如何。

当运行docker容器时，进程会放弃敏感权限，这些权限可以用来逃离隔离。这样可以确保进程无法执行敏感操作并逃脱：

[linux-capabilities.md](../linux-capabilities.md)

### Docker中的Seccomp

这是一个安全功能，允许Docker限制容器内可以使用的系统调用：

[seccomp.md](seccomp.md)

### Docker中的AppArmor

AppArmor是一个内核增强功能，用于将容器限制在一组有限的资源和每个程序的配置文件中：

[apparmor.md](apparmor.md)

### Docker中的SELinux

* **标签系统**：SELinux为每个进程和文件系统对象分配唯一标签。
* **策略执行**：它执行定义了进程标签在系统中可以对其他标签执行的操作的安全策略。
* **容器进程标签**：当容器引擎启动容器进程时，它们通常被分配一个受限SELinux标签，通常是`container_t`。
* **容器内的文件标签**：容器内的文件通常被标记为`container_file_t`。
* **策略规则**：SELinux策略主要确保具有`container_t`标签的进程只能与标记为`container_file_t`的文件交互（读取、写入、执行）。

这种机制确保即使容器内的进程被入侵，也仅限于与具有相应标签的对象交互，从而显著限制了此类妥协可能造成的潜在损害。

[selinux.md](../selinux.md)

### AuthZ & AuthN

在Docker中，授权插件通过检查两个关键上下文来决定是否允许或阻止对Docker守护程序的请求。这一决定是通过检查两个关键上下文来做出的：

* **认证上下文**：包括有关用户的全面信息，例如他们是谁以及如何进行身份验证。
* **命令上下文**：包括与正在进行的请求相关的所有相关数据。

这些上下文有助于确保只有经过身份验证的用户的合法请求才会被处理，增强Docker操作的安全性。

[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)

## 容器的DoS

如果没有正确限制容器可以使用的资源，一个被入侵的容器可能会对其运行的主机进行DoS攻击。

* CPU DoS
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
* 带宽 DoS
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## 有趣的 Docker 标志

### --privileged 标志

在下面的页面中，您可以了解 **`--privileged` 标志意味着什么**：

{% content-ref url="docker-privileged.md" %}
[docker-privileged.md](docker-privileged.md)
{% endcontent-ref %}

### --security-opt

#### no-new-privileges

如果您正在运行一个容器，攻击者设法以低特权用户的身份访问。如果您有一个**配置错误的 suid 二进制文件**，攻击者可能会滥用它并**在容器内升级权限**。这可能允许他逃离容器。

使用启用了**`no-new-privileges`**选项运行容器将**防止这种特权升级**。
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
要查看更多**`--security-opt`**选项，请访问：[https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## 其他安全考虑

### 管理机密信息：最佳实践

避免直接嵌入Docker镜像或使用环境变量存储机密信息至关重要，因为这些方法会将您的敏感信息暴露给通过诸如`docker inspect`或`exec`等命令访问容器的任何人。

**Docker卷**是一个更安全的替代方案，建议用于访问敏感信息。它们可以被用作内存中的临时文件系统，减轻了与`docker inspect`和日志记录相关的风险。但是，root用户和具有对容器的`exec`访问权限的用户仍然可以访问这些机密信息。

**Docker机密**提供了一种更安全的处理敏感信息的方法。对于在镜像构建阶段需要机密信息的情况，**BuildKit**提供了一个高效的解决方案，支持构建时机密信息，提高构建速度并提供额外功能。

要利用BuildKit，可以通过以下三种方式激活它：

1. 通过环境变量：`export DOCKER_BUILDKIT=1`
2. 通过添加前缀命令：`DOCKER_BUILDKIT=1 docker build .`
3. 通过在Docker配置中默认启用它：`{ "features": { "buildkit": true } }`，然后重新启动Docker。

BuildKit允许使用`--secret`选项处理构建时机密信息，确保这些机密信息不包含在镜像构建缓存或最终镜像中，使用类似以下命令：
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
对于运行容器中需要的机密信息，**Docker Compose 和 Kubernetes** 提供了强大的解决方案。Docker Compose 利用服务定义中的 `secrets` 键来指定机密文件，如在 `docker-compose.yml` 示例中所示：
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
这个配置允许在使用Docker Compose启动服务时使用secrets。

在Kubernetes环境中，secrets得到原生支持，并可以通过诸如[Helm-Secrets](https://github.com/futuresimple/helm-secrets)之类的工具进一步管理。Kubernetes的基于角色的访问控制（RBAC）增强了秘钥管理安全性，类似于Docker Enterprise。

### gVisor

**gVisor**是一个用Go编写的应用程序内核，实现了Linux系统表面的大部分功能。它包括一个名为`runsc`的[Open Container Initiative (OCI)](https://www.opencontainers.org)运行时，提供了应用程序和主机内核之间的**隔离边界**。`runsc`运行时与Docker和Kubernetes集成，使得运行沙盒容器变得简单。

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers**是一个开源社区，致力于构建一个安全的容器运行时，使用轻量级虚拟机，感觉和表现像容器，但通过硬件虚拟化技术提供**更强大的工作负载隔离**作为第二层防御。

{% embed url="https://katacontainers.io/" %}

### 总结提示

* **不要使用`--privileged`标志或在容器内挂载** [**Docker套接字**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**。** Docker套接字允许生成容器，因此通过使用`--privileged`标志运行另一个容器是获取主机完全控制的简单方法。
* **不要在容器内以root身份运行。使用** [**不同的用户**](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user) **和** [**用户命名空间**](https://docs.docker.com/engine/security/userns-remap/)**。** 容器中的root与主机上的root相同，除非使用用户命名空间重新映射。它仅受到Linux命名空间、功能和cgroups的轻微限制。
* [**放弃所有功能**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`)，仅启用所需功能** (`--cap-add=...`)。许多工作负载不需要任何功能，添加功能会增加潜在攻击的范围。
* [**使用“no-new-privileges”安全选项**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) **防止进程获取更多权限，例如通过suid二进制文件。**
* [**限制容器可用的资源**](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)**。** 资源限制可以保护机器免受拒绝服务攻击。
* **调整** [**seccomp**](https://docs.docker.com/engine/security/seccomp/)**，** [**AppArmor**](https://docs.docker.com/engine/security/apparmor/) **（或SELinux）**配置文件，将容器可用的操作和系统调用限制为最低所需。
* **使用** [**官方Docker镜像**](https://docs.docker.com/docker-hub/official_images/) **并要求签名**，或者基于它们构建自己的镜像。不要继承或使用[后门](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/)镜像。还要将根密钥、密码存储在安全位置。Docker计划使用UCP管理密钥。
* **定期** **重建**您的镜像以**应用安全补丁到主机和镜像**。
* 明智地管理您的**secrets**，使攻击者难以访问它们。
* 如果**暴露Docker守护程序，请使用HTTPS**进行客户端和服务器身份验证。
* 在Dockerfile中，**优先使用COPY而不是ADD**。ADD会自动解压缩文件并可以从URL复制文件。COPY不具备这些功能。尽量避免使用ADD，以免通过远程URL和Zip文件遭受攻击。
* 为每个微服务**使用单独的容器**
* **不要在容器内放置ssh**，“docker exec”可用于ssh到容器。
* 使用**更小**的容器**镜像**

## Docker越狱/权限提升

如果您**在Docker容器内**或者您可以访问**docker组中的用户**，您可以尝试**逃逸和提升权限**：

{% content-ref url="docker-breakout-privilege-escalation/" %}
[docker-breakout-privilege-escalation](docker-breakout-privilege-escalation/)
{% endcontent-ref %}

## Docker身份验证插件绕过

如果您可以访问docker套接字或者可以访问**docker组中的用户，但您的操作受到docker身份验证插件的限制**，请检查是否可以**绕过它**：

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## 加固Docker

* 工具[**docker-bench-security**](https://github.com/docker/docker-bench-security)是一个脚本，检查在生产环境中部署Docker容器周围的几十个常见最佳实践。这些测试都是自动化的，基于[CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/)。\
您需要从运行docker的主机或具有足够权限的容器中运行该工具。了解**如何在README中运行它：** [**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security)。

## 参考资料

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/\_fel1x/status/1151487051986087936)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/)
* [https://en.wikipedia.org/wiki/Linux\_namespaces](https://en.wikipedia.org/wiki/Linux\_namespaces)
* [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)
* [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)
* [https://docs.docker.com/engine/extend/plugins\_authorization](https://docs.docker.com/engine/extend/plugins\_authorization)
* [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)
* [https://resources.experfy.com/bigdata-cloud/top-20-docker-security-tips/](https://resources.experfy.com/bigdata-cloud/top-20-docker-security-tips/)

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和**自动化工作流程**，使用全球**最先进**的社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式:
* 如果您想看到您的**公司在HackTricks中被广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上**关注**我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。
