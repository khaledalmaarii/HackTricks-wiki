# Docker 取证

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在 HackTricks 中看到你的**公司广告**吗？或者你想获得**PEASS 的最新版本或下载 HackTricks 的 PDF 版本**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks 仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud)提交 PR 来分享你的黑客技巧。**

</details>

## 容器修改

有人怀疑某个 Docker 容器被入侵：
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
您可以使用以下方法轻松**查找与镜像相关的对此容器所做的修改**：
```bash
docker diff wordpress
C /var
C /var/lib
C /var/lib/mysql
A /var/lib/mysql/ib_logfile0
A /var/lib/mysql/ib_logfile1
A /var/lib/mysql/ibdata1
A /var/lib/mysql/mysql
A /var/lib/mysql/mysql/time_zone_leap_second.MYI
A /var/lib/mysql/mysql/general_log.CSV
...
```
在上一个命令中，**C** 代表 **Changed（已更改）**，**A** 代表 **Added（已添加）**。\
如果你发现一些有趣的文件，比如 `/etc/shadow` 被修改了，你可以从容器中下载它，以检查是否存在恶意活动：
```bash
docker cp wordpress:/etc/shadow.
```
您还可以通过运行一个新的容器并从中提取文件来与原始文件进行比较：
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
如果你发现**有可疑文件被添加**，你可以访问容器并进行检查：
```bash
docker exec -it wordpress bash
```
## 图像修改

当你获得一个导出的Docker镜像（可能是`.tar`格式）时，你可以使用[**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases)来**提取修改的摘要**：
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
然后，您可以**解压缩**镜像并**访问blob**以搜索您在更改历史中可能找到的可疑文件：
```bash
tar -xf image.tar
```
### 基本分析

您可以从正在运行的镜像中获取**基本信息**：
```bash
docker inspect <image>
```
您还可以使用以下命令获取**更改历史摘要**：
```bash
docker history --no-trunc <image>
```
您还可以使用以下命令从镜像生成**dockerfile**：
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

为了在Docker镜像中找到添加/修改的文件，您还可以使用[dive](https://github.com/wagoodman/dive)（从[releases](https://github.com/wagoodman/dive/releases/tag/v0.10.0)下载）实用工具：
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
这样可以让您**浏览docker镜像的不同blob**并检查哪些文件被修改/添加。**红色**表示添加，**黄色**表示修改。使用**tab**键切换到其他视图，使用**空格**键折叠/展开文件夹。

使用die，您将无法访问镜像的不同阶段的内容。要做到这一点，您需要**解压每个层并访问它**。\
您可以从解压缩镜像的目录中解压缩所有层，执行以下操作：
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## 从内存中获取凭据

请注意，当您在主机上运行一个docker容器时，**您可以通过运行`ps -ef`命令来查看容器上运行的进程**。

因此（作为root用户），您可以从主机上**转储进程的内存**，并搜索**凭据**，就像[**以下示例**](../../linux-hardening/privilege-escalation/#process-memory)中所示。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 您在一家**网络安全公司**工作吗？您想在HackTricks中**为您的公司做广告**吗？或者您想要访问**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>
