# Docker取证

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中被广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 容器修改

有人怀疑某个Docker容器已被入侵：
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
您可以轻松地使用以下命令查找有关此容器对镜像所做修改：
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
在上一个命令中，**C** 代表 **Changed**，**A** 代表 **Added**。\
如果你发现一些有趣的文件，比如 `/etc/shadow` 被修改了，你可以从容器中下载它，以检查是否存在恶意活动：
```bash
docker cp wordpress:/etc/shadow.
```
您还可以通过运行一个新容器并从中提取文件来**与原始文件进行比较**：
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
如果发现**添加了一些可疑文件**，您可以访问容器并进行检查：
```bash
docker exec -it wordpress bash
```
## 图像修改

当您获得一个导出的 Docker 镜像（可能是 `.tar` 格式）时，您可以使用 [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) 来 **提取修改的摘要**：
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
然后，您可以**解压**图像并**访问 blobs**，以搜索您在更改历史记录中发现的可疑文件：
```bash
tar -xf image.tar
```
### 基本分析

您可以从运行的镜像中获取**基本信息**：
```bash
docker inspect <image>
```
您还可以使用以下命令获取**更改历史记录摘要**：
```bash
docker history --no-trunc <image>
```
您还可以使用以下命令从镜像生成**dockerfile**：
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

为了找到 Docker 镜像中添加/修改的文件，您还可以使用 [**dive**](https://github.com/wagoodman/dive)（从 [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0) 下载）实用程序：
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
这使您能够**浏览Docker镜像的不同blob**，并检查哪些文件已被修改/添加。**红色**表示已添加，**黄色**表示已修改。使用**tab**键切换到其他视图，使用**空格**键折叠/打开文件夹。

使用die，您将无法访问镜像不同阶段的内容。要这样做，您需要**解压缩每个层并访问它**。\
您可以从解压缩镜像的目录中解压缩图像的所有层，执行：
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## 从内存中获取凭据

请注意，当您在主机内运行一个docker容器时，**您可以从主机上运行`ps -ef`命令来查看容器中运行的进程**

因此（作为root用户）您可以从主机中**转储进程的内存**，并搜索凭据，就像[**以下示例**](../../linux-hardening/privilege-escalation/#process-memory)中一样。
