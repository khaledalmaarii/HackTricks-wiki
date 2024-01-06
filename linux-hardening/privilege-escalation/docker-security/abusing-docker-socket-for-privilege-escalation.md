# 利用 Docker Socket 进行权限提升

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>从零开始学习 AWS 黑客攻击！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks** 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现我们的独家[**NFTs 集合**](https://opensea.io/collection/the-peass-family)，[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)上**关注**我。
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧**。

</details>

有些情况下，您只能**访问 docker socket**，并希望使用它来**提升权限**。有些操作可能非常可疑，您可能希望避免它们，因此在这里您可以找到不同的标志，这些标志对于提升权限可能有用：

### 通过挂载

您可以**挂载**文件系统的不同部分到以 root 身份运行的容器中，并**访问**它们。\
您还可以**滥用挂载来在容器内提升权限**。

* **`-v /:/host`** -> 在容器中挂载宿主机的文件系统，以便您可以**读取宿主机的文件系统。**
* 如果您想在容器中**感觉像在宿主机上**，您可以使用以下标志禁用其他防御机制：
* `--privileged`
* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `-security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> 这与前一种方法类似，但在这里我们正在**挂载设备磁盘**。然后，在容器内运行 `mount /dev/sda1 /mnt`，您可以在 `/mnt` 中**访问** **宿主机的文件系统**
* 在宿主机上运行 `fdisk -l` 来找到要挂载的 `</dev/sda1>` 设备
* **`-v /tmp:/host`** -> 如果由于某种原因您只能**挂载宿主机的某个目录**，并且您在宿主机内部有访问权限。挂载它并在挂载的目录中创建一个具有 **suid** 的 **`/bin/bash`**，以便您可以**从宿主机执行它并提升为 root**。

{% hint style="info" %}
请注意，您可能无法挂载 `/tmp` 文件夹，但您可以挂载**不同的可写文件夹**。您可以使用以下命令找到可写目录：`find / -writable -type d 2>/dev/null`

**请注意，并非所有 Linux 机器上的目录都支持 suid 位！** 为了检查哪些目录支持 suid 位，请运行 `mount | grep -v "nosuid"` 例如，通常 `/dev/shm`、`/run`、`/proc`、`/sys/fs/cgroup` 和 `/var/lib/lxcfs` 不支持 suid 位。

还请注意，如果您可以**挂载 `/etc`** 或任何其他**包含配置文件的文件夹**，您可以从 docker 容器中以 root 身份更改它们，以便**在宿主机上滥用它们**并提升权限（可能修改 `/etc/shadow`）
{% endhint %}

### 从容器中逃逸

* **`--privileged`** -> 使用此标志，您[移除了容器的所有隔离](docker-privileged.md#what-affects)。查看技术以[从具有 root 权限的特权容器中逃逸](docker-breakout-privilege-escalation/#automatic-enumeration-and-escape)。
* **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> 为了[滥用能力进行提升](../linux-capabilities.md)，**授予容器该能力**并禁用其他可能阻止漏洞利用工作的保护方法。

### Curl

在这个页面上，我们讨论了使用 docker 标志提升权限的方法，您可以在以下页面中找到**使用 curl 命令滥用这些方法的方式**：

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>从零开始学习 AWS 黑客攻击！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks** 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现我们的独家[**NFTs 集合**](https://opensea.io/collection/the-peass-family)，[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)上**关注**我。
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧**。

</details>
