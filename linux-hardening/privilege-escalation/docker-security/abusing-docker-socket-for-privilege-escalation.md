# 滥用Docker Socket进行特权提升

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFT收藏品The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud仓库](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧。**

</details>

有时候你只能**访问Docker Socket**，并希望使用它来**提升特权**。某些操作可能非常可疑，你可能希望避免它们，因此在这里你可以找到一些有用的提权标志：

### 通过挂载

你可以在以root身份运行的容器中**挂载**文件系统的不同部分并**访问**它们。\
你还可以**滥用挂载来提升容器内的特权**。

* **`-v /:/host`** -> 将主机文件系统挂载到容器中，这样你就可以**读取主机文件系统**。
* 如果你想**感觉自己在主机上**，但实际上在容器中，你可以使用以下标志禁用其他防御机制：
* `--privileged`
* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `-security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> 这与前一种方法类似，但这里我们正在**挂载设备磁盘**。然后，在容器内运行`mount /dev/sda1 /mnt`，你就可以在`/mnt`中**访问**主机文件系统。
* 在主机上运行`fdisk -l`以查找要挂载的`</dev/sda1>`设备
* **`-v /tmp:/host`** -> 如果由于某种原因你只能从主机上**挂载某个目录**并且你可以在主机上访问它。挂载它并在挂载的目录中创建一个带有**suid**的**`/bin/bash`**，这样你就可以从主机上执行它并提升为root。

{% hint style="info" %}
请注意，也许你无法挂载`/tmp`文件夹，但你可以挂载一个**不同的可写文件夹**。你可以使用以下命令找到可写目录：`find / -writable -type d 2>/dev/null`

**请注意，并非Linux机器上的所有目录都支持suid位！**为了检查哪些目录支持suid位，请运行`mount | grep -v "nosuid"`。例如，通常`/dev/shm`、`/run`、`/proc`、`/sys/fs/cgroup`和`/var/lib/lxcfs`不支持suid位。

还要注意，如果你可以**挂载`/etc`**或任何其他包含配置文件的文件夹，你可以作为root从docker容器中更改它们，以便在主机上**滥用它们**并提升特权（也许修改`/etc/shadow`）
{% endhint %}

### 逃离容器

* **`--privileged`** -> 使用此标志，你可以[移除容器的所有隔离](docker-privileged.md#what-affects)。查看[以root身份逃离特权容器的技术](docker-breakout-privilege-escalation/#automatic-enumeration-and-escape)。
* **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> 为了[滥用能力来提升特权](../linux-capabilities.md)，**授予容器该能力**并禁用可能阻止利用的其他保护方法。

### Curl

在本页面中，我们讨论了使用docker标志提升特权的方法，你可以在页面中使用curl命令找到**滥用这些方法的方式**：

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFT收藏品The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或在 **Twitter** 上 **关注** 我 [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来分享你的黑客技巧**。

</details>
