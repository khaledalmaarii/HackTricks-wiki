# Docker安全

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和**自动化工作流程**，使用世界上最先进的社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}


## **基本的Docker引擎安全**

Docker引擎负责运行和管理容器。Docker引擎使用Linux内核的**命名空间**和**Cgroups**功能，提供容器之间的基本**隔离**。它还使用**能力降低**、**Seccomp**、**SELinux/AppArmor**等功能来实现更好的隔离。

最后，可以使用**认证插件**来**限制用户的操作**。

![](<../../../.gitbook/assets/image (625) (1) (1).png>)

### **Docker引擎安全访问**

Docker客户端可以通过Unix套接字本地访问Docker引擎，也可以通过http远程访问。要进行远程访问，需要使用https和**TLS**，以确保机密性、完整性和身份验证。

默认情况下，监听Unix套接字`unix:///var/`\
`run/docker.sock`，在Ubuntu发行版中，Docker启动选项在`/etc/default/docker`中指定。要允许Docker API和客户端远程访问Docker引擎，我们需要**使用http套接字暴露Docker守护程序**。可以通过以下方式完成：
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H
tcp://192.168.56.101:2376" -> add this to /etc/default/docker
Sudo service docker restart -> Restart Docker daemon
```
使用http暴露Docker守护程序不是一个好的做法，需要使用https来保护连接。有两个选项：第一个选项是**客户端验证服务器身份**，第二个选项是**客户端和服务器相互验证身份**。证书用于建立服务器的身份。有关这两个选项的示例，请[**查看此页面**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)。

### **容器镜像安全性**

容器镜像可以存储在私有仓库或公共仓库中。Docker提供以下选项来存储容器镜像：

* [Docker Hub](https://hub.docker.com) - 这是Docker提供的公共注册服务
* [Docker Registry](https://github.com/%20docker/distribution) - 这是一个开源项目，用户可以使用它来托管自己的注册表。
* [Docker Trusted Registry](https://www.docker.com/docker-trusted-registry) - 这是Docker的商业实现，提供基于角色的用户身份验证以及LDAP目录服务集成。

### 镜像扫描

容器可能存在**安全漏洞**，这可能是由于基础镜像或安装在基础镜像之上的软件引起的。Docker正在开发一个名为**Nautilus**的项目，用于对容器进行安全扫描并列出漏洞。Nautilus通过将每个容器镜像层与漏洞库进行比较，以识别安全漏洞。

有关更多[**信息，请阅读此文档**](https://docs.docker.com/engine/scan/)。

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
### Docker镜像签名

Docker容器镜像可以存储在公共或私有注册表中。为了确认镜像没有被篡改，需要对容器镜像进行签名。内容发布者负责对容器镜像进行签名并将其推送到注册表中。以下是关于Docker内容信任的一些详细信息：

- Docker内容信任是[Notary开源项目](https://github.com/docker/notary)的一种实现。Notary开源项目基于[The Update Framework (TUF)项目](https://theupdateframework.github.io)。
- 使用`export DOCKER_CONTENT_TRUST=1`启用Docker内容信任。从Docker版本1.10开始，默认情况下未启用内容信任。
- 当内容信任被启用时，我们只能拉取已签名的镜像。在推送镜像时，需要输入标记密钥。
- 当发布者首次使用docker push推送镜像时，需要为根密钥和标记密钥输入密码短语。其他密钥将自动生成。
- Docker还添加了对使用Yubikey的硬件密钥的支持，详细信息可在[这里](https://blog.docker.com/2015/11/docker-content-trust-yubikey/)找到。

以下是当启用内容信任但镜像未签名时出现的错误信息。
```shell-session
$ docker pull smakam/mybusybox
Using default tag: latest
No trust data for latest
```
以下输出显示启用签名的容器映像正在推送到Docker Hub。由于这不是第一次推送，用户只需输入存储库密钥的密码短语。
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
需要将根密钥、存储库密钥以及密码短语保存在安全的地方。可以使用以下命令备份私钥：
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
当我更改Docker主机时，我不得不将根密钥和仓库密钥移动到新主机上进行操作。

***

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和自动化由全球最先进的社区工具提供支持的工作流程。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 容器安全功能

<details>

<summary>容器安全功能摘要</summary>

**命名空间**

命名空间对于将项目与其他项目隔离开来非常有用，可以隔离进程通信、网络、挂载等。它对于将Docker进程与其他进程（甚至/proc文件夹）隔离开来非常有用，因此它无法滥用其他进程来逃逸。

可以使用二进制文件**`unshare`**（使用**`unshare`**系统调用）来“逃逸”或更准确地说是**创建新的命名空间**。Docker默认情况下会阻止此操作，但Kubernetes不会（在撰写本文时）。\
无论如何，这对于创建新的命名空间非常有帮助，但**无法返回到主机默认的命名空间**（除非您可以访问主机命名空间中的某些`/proc`，在其中可以使用**`nsenter`**进入主机命名空间）。

**CGroups**

这允许限制资源，并且不会影响进程隔离的安全性（除了`release_agent`可能被用于逃逸）。

**能力降级**

我认为这是关于进程隔离安全性最重要的功能之一。这是因为没有这些能力，即使进程以root身份运行，**您也无法执行某些特权操作**（因为调用的**`syscall`**将返回权限错误，因为进程没有所需的能力）。

这些是进程放弃其他能力后的**剩余能力**：

{% code overflow="wrap" %}
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
{% endcode %}

**Seccomp**

默认情况下，Docker启用了Seccomp。它有助于**进一步限制进程可以调用的系统调用**。\
**默认的Docker Seccomp配置文件**可以在[https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)找到。

**AppArmor**

Docker有一个可以激活的模板：[https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

这将允许减少功能、系统调用、对文件和文件夹的访问...

</details>

### 命名空间

**命名空间**是Linux内核的一个功能，它将内核资源进行**分区**，使得一组**进程**看到一组**资源**，而**另一组进程**看到另一组**资源**。该功能通过为一组资源和进程使用相同的命名空间，但这些命名空间指向不同的资源来实现。资源可以存在于多个空间中。

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

Linux内核功能**cgroups**提供了对一组进程的资源（如CPU、内存、IO、网络带宽）进行限制的能力。Docker允许使用cgroup功能创建容器，从而实现对特定容器的资源控制。\
以下是一个创建的容器，其中用户空间内存限制为500m，内核内存限制为50m，CPU份额为512，blkioweight为400。CPU份额是一个控制容器CPU使用率的比例。它的默认值为1024，范围在0到1024之间。如果三个容器具有相同的CPU份额1024，每个容器在CPU资源争用的情况下最多可以占用33%的CPU。blkio-weight是一个控制容器IO的比例。它的默认值为500，范围在10到1000之间。
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
要获取容器的cgroup，可以执行以下操作：
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
更多信息请查看：

{% content-ref url="cgroups.md" %}
[cgroups.md](cgroups.md)
{% endcontent-ref %}

### 权限提升

权限提升允许对root用户可以允许的权限进行更精细的控制。Docker使用Linux内核的能力功能来限制容器内部可以执行的操作，而不管用户类型如何。

当运行Docker容器时，进程会放弃敏感的能力，这些能力可以用来逃离隔离。这样可以确保进程无法执行敏感操作并逃离：

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

### Docker中的Seccomp

这是一种安全功能，允许Docker限制容器内部可以使用的系统调用：

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

### Docker中的AppArmor

AppArmor是一种内核增强功能，用于将容器限制在一组有限的资源和每个程序的配置文件中。

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

### Docker中的SELinux

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux)是一个标签系统。每个进程和每个文件系统对象都有一个标签。SELinux策略定义了关于进程标签在系统上可以做什么的规则。

容器引擎使用单个受限的SELinux标签启动容器进程，通常为`container_t`，然后将容器内部的容器设置为标记为`container_file_t`。SELinux策略规则基本上表示**`container_t`进程只能读取/写入/执行标记为`container_file_t`的文件**。

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

### AuthZ和AuthN

授权插件根据当前的身份验证上下文和命令上下文来批准或拒绝对Docker守护程序的请求。身份验证上下文包含所有用户详细信息和身份验证方法。命令上下文包含所有相关的请求数据。

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## 容器的DoS攻击

如果您没有正确限制容器可以使用的资源，被入侵的容器可能会对其运行的主机进行DoS攻击。

* CPU DoS
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
* 带宽拒绝服务攻击

带宽拒绝服务攻击（Bandwidth DoS）是一种网络攻击技术，旨在通过消耗目标系统的带宽资源来使其无法正常运行。攻击者通过发送大量的网络流量到目标系统，超过其带宽容量的限制，从而导致目标系统无法处理正常的网络请求。这种攻击可以导致目标系统的网络连接变得缓慢或完全中断，从而影响其正常的功能和服务。为了防止带宽拒绝服务攻击，网络管理员可以采取一系列的防御措施，如流量监测、流量过滤和带宽限制等。
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## 有趣的Docker标志

### --privileged标志

在下面的页面中，您可以了解**`--privileged`标志意味着什么**：

{% content-ref url="docker-privileged.md" %}
[docker-privileged.md](docker-privileged.md)
{% endcontent-ref %}

### --security-opt

#### no-new-privileges

如果您正在运行一个容器，攻击者以低权限用户的身份获得访问权限。如果您有一个**配置错误的suid二进制文件**，攻击者可能会滥用它并在容器内**提升权限**。这可能使他能够逃离容器。

使用启用了**`no-new-privileges`**选项的容器将**防止此类权限提升**。
```
docker run -it --security-opt=no-new-privileges:true nonewpriv
```
#### 其他

In addition to the security measures mentioned above, there are a few other steps you can take to further harden your Docker environment:

1. **Limit container capabilities**: By default, Docker containers have a wide range of capabilities, which can potentially be exploited by attackers. You can restrict these capabilities by using the `--cap-drop` and `--cap-add` flags when running containers. Only allow the necessary capabilities for your containers to function properly.

2. **Use seccomp profiles**: Seccomp (secure computing mode) is a Linux kernel feature that allows you to restrict the system calls that a process can make. By using seccomp profiles, you can further limit the attack surface of your containers. Docker provides a default seccomp profile, but you can also create custom profiles based on your specific requirements.

3. **Enable AppArmor or SELinux**: AppArmor and SELinux are mandatory access control (MAC) systems that provide an additional layer of security by enforcing strict access controls on processes and files. By enabling and configuring either of these systems, you can further enhance the security of your Docker environment.

4. **Regularly update Docker and its dependencies**: Docker releases regular updates that include security patches and bug fixes. It is important to keep your Docker installation up to date to ensure that you have the latest security enhancements.

5. **Monitor Docker logs**: Monitoring Docker logs can help you detect any suspicious activities or potential security breaches. Configure a centralized logging system to collect and analyze Docker logs for better visibility into your environment.

By implementing these additional security measures, you can significantly reduce the risk of privilege escalation and other security vulnerabilities in your Docker environment.
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
有关更多**`--security-opt`**选项，请查看：[https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## 其他安全考虑

### 管理机密信息

首先，**不要将它们放在镜像中！**

此外，也不要使用环境变量存储敏感信息。任何可以运行`docker inspect`或`exec`进入容器的人都可以找到你的机密信息。

Docker卷是更好的选择。它们是Docker文档中推荐的访问敏感信息的方式。你可以将卷用作内存中的临时文件系统。卷可以消除`docker inspect`和日志记录的风险。然而，root用户仍然可以看到机密信息，任何可以`exec`进入容器的人也可以看到。

比卷更好的选择是使用Docker secrets。

如果你只需要将机密信息放在镜像中，可以使用BuildKit。BuildKit可以显著缩短构建时间，并具有其他很好的功能，包括构建时的机密信息支持。

有三种方法可以指定BuildKit后端，以便立即使用其功能：

1. 使用`export DOCKER_BUILDKIT=1`将其设置为环境变量。
2. 在`build`或`run`命令前加上`DOCKER_BUILDKIT=1`。
3. 默认启用BuildKit。在/_etc/docker/daemon.json_中将配置设置为`true`：`{ "features": { "buildkit": true } }`。然后重新启动Docker。
4. 然后，您可以使用`--secret`标志在构建时使用机密信息，如下所示：
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
在您的文件中，将您的秘密指定为键值对。

这些秘密将从镜像构建缓存中排除，并且不会出现在最终镜像中。

如果您需要在运行的容器中使用您的秘密，而不仅仅是在构建镜像时，请使用Docker Compose或Kubernetes。

使用Docker Compose，将秘密键值对添加到服务中，并指定秘密文件。感谢[Stack Exchange答案](https://serverfault.com/a/936262/535325)提供的Docker Compose秘密提示，下面的示例是根据该答案进行调整的。

带有秘密的示例`docker-compose.yml`：
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
然后像往常一样使用`docker-compose up --build my_service`启动Compose。

如果您正在使用[Kubernetes](https://kubernetes.io/docs/concepts/configuration/secret/)，它支持密钥管理。[Helm-Secrets](https://github.com/futuresimple/helm-secrets)可以帮助简化Kubernetes中的密钥管理。此外，Kubernetes和Docker Enterprise都支持基于角色的访问控制（RBAC）。RBAC使得密钥管理对团队来说更易管理和更安全。

### gVisor

**gVisor**是一个用Go编写的应用程序内核，它实现了Linux系统的大部分功能。它包括一个名为`runsc`的[Open Container Initiative (OCI)](https://www.opencontainers.org)运行时，提供了应用程序和主机内核之间的**隔离边界**。`runsc`运行时与Docker和Kubernetes集成，使得运行沙盒容器变得简单。

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers**是一个开源社区，致力于构建一个安全的容器运行时，使用轻量级虚拟机来提供与容器相似的性能和体验，同时使用硬件虚拟化技术作为第二层防御来提供**更强大的工作负载隔离**。

{% embed url="https://katacontainers.io/" %}

### 总结提示

* **不要使用`--privileged`标志或在容器内挂载**[**Docker套接字**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**。** Docker套接字允许生成容器，因此通过使用`--privileged`标志运行另一个容器是控制主机的简单方法。
* **不要在容器内以root身份运行。使用**[**不同的用户**](https://docs.docker.com/develop/develop-images/dockerfile\_best-practices/#user)**和**[**用户命名空间**](https://docs.docker.com/engine/security/userns-remap/)**。**容器中的root与主机上的root相同，除非使用用户命名空间重新映射。它仅受到Linux命名空间、能力和cgroups的轻微限制。
* [**丢弃所有能力**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities)**（`--cap-drop=all`），仅启用所需的能力**（`--cap-add=...`）。许多工作负载不需要任何能力，添加能力会增加潜在攻击的范围。
* [**使用“no-new-privileges”安全选项**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/)防止进程获取更多特权，例如通过suid二进制文件。
* [**限制容器可用的资源**](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)**。**资源限制可以保护机器免受拒绝服务攻击。
* **调整**[**seccomp**](https://docs.docker.com/engine/security/seccomp/)**、**[**AppArmor**](https://docs.docker.com/engine/security/apparmor/)**（或SELinux）**配置文件，将容器可用的操作和系统调用限制为最小。
* **使用**[**官方的Docker镜像**](https://docs.docker.com/docker-hub/official\_images/)**并要求签名**，或者基于官方镜像构建自己的镜像。不要继承或使用[后门](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/)镜像。还要将根密钥和密码短语存放在安全的地方。Docker计划使用UCP来管理密钥。
* **定期重新构建**您的镜像，以**应用安全补丁到主机和镜像**。
* 明智地**管理您的密钥**，使攻击者难以访问它们。
* 如果**公开了Docker守护程序，请使用HTTPS**进行客户端和服务器身份验证。
* 在Dockerfile中，**优先使用COPY而不是ADD**。ADD会自动解压缩文件并可以从URL复制文件。COPY没有这些功能。尽量避免使用ADD，以免受到通过远程URL和Zip文件进行的攻击。
* 为每个微服务**使用单独的容器**。
* **不要在容器中放置ssh**，“docker exec”可用于通过ssh连接到容器。
* 使用**较小的**容器**镜像**

## Docker越权/权限提升

如果您**在Docker容器内部**或者您可以访问**docker组中的用户**，您可以尝试**逃逸和提升权限**：

{% content-ref url="docker-breakout-privilege-escalation/" %}
[docker-breakout-privilege-escalation](docker-breakout-privilege-escalation/)
{% endcontent-ref %}

## Docker身份验证插件绕过

如果您可以访问docker套接字或者可以访问**docker组中的用户，但是您的操作受到docker身份验证插件的限制**，请检查是否可以**绕过它**：

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## 加固Docker

* 工具[**docker-bench-security**](https://github.com/docker/docker-bench-security)是一个脚本，用于检查在生产环境中部署Docker容器时的许多常见最佳实践。这些测试都是自动化的，并基于[CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/)。\
您需要从运行Docker的主机或具有足够权限的容器中运行该工具。了解**如何在README中运行它：**[**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security)。

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

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)轻松构建和自动化由全球**最先进**的社区工具提供支持的工作流程。
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要访问**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
