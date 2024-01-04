# macOS 网络服务与协议

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您希望在 **HackTricks** 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧**。

</details>

## 远程访问服务

这些是常见的 macOS 服务，用于远程访问它们。\
您可以在 `系统设置` --> `共享` 中启用/禁用这些服务

* **VNC**，被称为“屏幕共享”（tcp:5900）
* **SSH**，称为“远程登录”（tcp:22）
* **Apple Remote Desktop** (ARD)，或“远程管理”（tcp:3283, tcp:5900）
* **AppleEvent**，被称为“远程 Apple 事件”（tcp:3031）

通过运行以下命令检查是否启用了任何服务：
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### ARD 渗透测试

（此部分摘自[**此博客文章**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)）

它本质上是一个带有一些**额外 macOS 特定功能**的变种 [VNC](https://en.wikipedia.org/wiki/Virtual\_Network\_Computing)。\
然而，**屏幕共享选项**只是一个**基础 VNC**服务器。还有一个高级的 ARD 或远程管理选项，用于**设置控制屏幕密码**，这将使 ARD 向后**兼容 VNC 客户端**。但是，这种认证方法有一个弱点，它将这个**密码**限制在一个**8字符认证缓冲区**内，使得使用像 [Hydra](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) 或 [GoRedShell](https://github.com/ahhh/GoRedShell/) 这样的工具进行**暴力破解**变得非常容易（默认情况下也**没有速率限制**）。\
您可以使用 **nmap** 识别**易受攻击的屏幕共享**或远程管理实例，使用脚本 `vnc-info`，如果服务支持 `VNC Authentication (2)`，那么它们很可能**易受暴力破解攻击**。服务会将所有通过网络发送的密码截断为8个字符，这样如果您将 VNC 认证设置为 "password"，"passwords" 和 "password123" 都将进行认证。

<figure><img src="../../.gitbook/assets/image (9) (3).png" alt=""><figcaption></figcaption></figure>

如果您想启用它以提升权限（接受 TCC 提示），通过 GUI 访问或监视用户，可以启用它：

{% code overflow="wrap" %}
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
{% endcode %}

您可以在**观察**模式、**共享控制**和**完全控制**之间切换，从窥探用户到一键接管他们的桌面。此外，如果您获得ARD会话的访问权限，即使在会话期间更改了用户的密码，该会话也将保持开放状态，直到会话终止。

您还可以**直接通过ARD发送unix命令**，如果您是管理员用户，可以指定root用户以root身份执行操作。您甚至可以使用这种unix命令方法来安排在特定时间运行远程任务，但这是在指定时间作为网络连接发生的（与存储在目标服务器上并执行相比）。最后，远程Spotlight是我最喜欢的功能之一。这非常整洁，因为您可以快速且远程地运行低影响、索引搜索。这对于搜索敏感文件来说是非常有价值的，因为它快速，允许您同时在多台机器上运行搜索，并且不会导致CPU使用率激增。

## Bonjour协议

**Bonjour**是苹果设计的技术，使得位于同一网络上的计算机和**设备能够了解其他计算机和设备提供的服务**。它的设计理念是任何支持Bonjour的设备都可以插入TCP/IP网络，并且它会**选择一个IP地址**，使网络上的其他计算机**了解它提供的服务**。Bonjour有时也被称为Rendezvous、**零配置**或Zeroconf。\
零配置网络，如Bonjour提供：

* 必须能够**获取IP地址**（即使没有DHCP服务器）
* 必须能够进行**名称到地址的转换**（即使没有DNS服务器）
* 必须能够**发现网络上的服务**

设备将获得**169.254/16范围内的IP地址**，并检查是否有其他设备正在使用该IP地址。如果没有，它将保留该IP地址。Macs在其路由表中为此子网保留了一个条目：`netstat -rn | grep 169`

对于DNS，使用**组播DNS（mDNS）协议**。[**mDNS** **服务**监听端口**5353/UDP**](../../network-services-pentesting/5353-udp-multicast-dns-mdns.md)，使用**常规DNS查询**，并使用**组播地址224.0.0.251**，而不是仅向一个IP地址发送请求。任何监听这些请求的机器都会响应，通常是向一个组播地址，这样所有设备都可以更新它们的表。\
每个设备在访问网络时都会**选择自己的名称**，设备会选择一个以.local**结尾的名称**（可能基于主机名或完全随机的一个）。

用于**发现服务的是DNS服务发现（DNS-SD）**。

零配置网络的最终要求是通过**DNS服务发现（DNS-SD）**来满足。DNS服务发现使用来自DNS SRV记录的语法，但使用**DNS PTR记录，以便如果有多个主机提供特定服务，则可以返回多个结果**。客户端请求`<Service>.<Domain>`名称的PTR查找，并**接收**零个或多个形式为`<Instance>.<Service>.<Domain>`的PTR记录的列表。

`dns-sd`二进制文件可用于**宣传服务和执行服务查找**：
```bash
#Search ssh services
dns-sd -B _ssh._tcp

Browsing for _ssh._tcp
DATE: ---Tue 27 Jul 2021---
12:23:20.361  ...STARTING...
Timestamp     A/R    Flags  if Domain               Service Type         Instance Name
12:23:20.362  Add        3   1 local.               _ssh._tcp.           M-C02C934RMD6R
12:23:20.362  Add        3  10 local.               _ssh._tcp.           M-C02C934RMD6R
12:23:20.362  Add        2  16 local.               _ssh._tcp.           M-C02C934RMD6R
```

```bash
#Announce HTTP service
dns-sd -R "Index" _http._tcp . 80 path=/index.html

#Search HTTP services
dns-sd -B _http._tcp
```
当启动新服务时，**新服务会向子网上的所有人广播其存在**。监听者不需要提问；它只需要在监听。

您可以使用[**此工具**](https://apps.apple.com/us/app/discovery-dns-sd-browser/id1381004916?mt=12)来查看当前本地网络中的**提供的服务**。\
或者您可以使用[**python-zeroconf**](https://github.com/jstasiak/python-zeroconf)编写自己的python脚本：
```python
from zeroconf import ServiceBrowser, Zeroconf


class MyListener:

def remove_service(self, zeroconf, type, name):
print("Service %s removed" % (name,))

def add_service(self, zeroconf, type, name):
info = zeroconf.get_service_info(type, name)
print("Service %s added, service info: %s" % (name, info))


zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
try:
input("Press enter to exit...\n\n")
finally:
zeroconf.close()
```
如果您认为关闭Bonjour可能会更安全，您可以使用以下命令来禁用它：
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## 参考资料

* [**Mac 黑客手册**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

其他支持 HackTricks 的方式：

* 如果您想在 **HackTricks** 中看到您的**公司广告**或**下载 HackTricks 的 PDF 版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧**。

</details>
