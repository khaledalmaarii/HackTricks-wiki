# Docker 取证

<details>

<summary><strong>从零到英雄学习 AWS 黑客攻击</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF**，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上 **关注** 我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## 容器修改

有疑虑某个 docker 容器被泄露：
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
你可以轻松地**找到对此容器相对于镜像所做的修改**，方法是：
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
在上一个命令中 **C** 代表 **已更改**，**A** 代表 **已添加**。\
如果你发现像 `/etc/shadow` 这样的一些有趣的文件被修改了，你可以使用以下命令从容器中下载它，以检查是否有恶意活动：
```bash
docker cp wordpress:/etc/shadow.
```
你也可以通过**运行一个新容器并从中提取文件**来**与原始文件进行比较**：
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
如果您发现**有可疑文件被添加**，您可以访问容器并检查它：
```bash
docker exec -it wordpress bash
```
## 镜像修改

当你获得一个导出的docker镜像（可能是`.tar`格式）时，你可以使用[**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases)来**提取修改摘要**：
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
然后，您可以**解压缩**镜像并**访问 blobs**以搜索您可能在更改历史中发现的可疑文件：
```bash
tar -xf image.tar
```
### 基础分析

您可以通过运行以下命令从镜像获取**基础信息**：
```bash
docker inspect <image>
```
你也可以通过以下方式获取**变更历史**的摘要：
```bash
docker history --no-trunc <image>
```
你也可以使用以下命令从镜像**生成一个 dockerfile**：
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

为了在docker镜像中找到添加/修改的文件，你也可以使用[**dive**](https://github.com/wagoodman/dive)（从[**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)下载）工具：
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
```markdown
这使您能够**浏览不同的docker镜像blobs**，并检查哪些文件被修改/添加。**红色**表示添加，**黄色**表示修改。使用**tab**切换到其他视图，使用**空格**折叠/打开文件夹。

使用die，您将无法访问镜像不同阶段的内容。要做到这一点，您需要**解压每个层并访问它**。\
您可以从解压镜像的目录中解压所有层，执行：
```
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## 从内存中获取凭证

请注意，当您在宿主机内运行一个docker容器时，**您可以通过执行`ps -ef`命令从宿主机上看到容器中运行的进程**。

因此（作为root用户），您可以**从宿主机转储进程的内存**并搜索**凭证**，就像[**以下示例中所展示的**](../../linux-hardening/privilege-escalation/#process-memory)。

<details>

<summary><strong>从零开始学习AWS黑客攻击直到成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方的PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库**提交PR来分享您的黑客技巧**。

</details>
