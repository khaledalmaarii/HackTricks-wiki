# macOS网络服务和协议

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 远程访问服务

这些是常见的macOS远程访问服务。\
您可以在`系统设置` --> `共享`中启用/禁用这些服务。

* **VNC**，也称为“屏幕共享”（tcp:5900）
* **SSH**，称为“远程登录”（tcp:22）
* **Apple Remote Desktop**（ARD），或称为“远程管理”（tcp:3283，tcp:5900）
* **AppleEvent**，也称为“远程Apple事件”（tcp:3031）

运行以下命令检查是否启用了任何服务：
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Pentesting ARD

（此部分摘自[此博客文章](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)）

它本质上是一个带有一些**额外的 macOS 特定功能**的变种[VNC](https://en.wikipedia.org/wiki/Virtual\_Network\_Computing)。\
然而，**屏幕共享选项**只是一个**基本的 VNC 服务器**。还有一个高级的 ARD 或远程管理选项，可以**设置控制屏幕密码**，这将使 ARD 向后**兼容 VNC 客户端**。然而，这种身份验证方法存在一个弱点，即将此**密码**限制为**8个字符的认证缓冲区**，因此很容易使用像[Hydra](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html)或[GoRedShell](https://github.com/ahhh/GoRedShell/)这样的工具进行**暴力破解**（默认情况下也**没有速率限制**）。\
您可以使用脚本`vnc-info`在**nmap**中识别**易受攻击的屏幕共享**或远程管理实例，如果服务支持`VNC Authentication (2)`，则很可能**容易受到暴力破解**。该服务将所有通过网络发送的密码截断为8个字符，因此如果您将 VNC 认证设置为"password"，则"passwords"和"password123"都将进行身份验证。

<figure><img src="../../.gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

如果您想要启用它以提升特权（接受 TCC 提示），通过 GUI 访问或监视用户，可以使用以下命令启用它：

{% code overflow="wrap" %}
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
{% endcode %}

您可以在点击按钮的同时，在**观察模式**、**共享控制**和**完全控制**之间切换，从监视用户到接管其桌面。此外，如果您成功访问了一个ARD会话，即使在会话期间更改了用户的密码，该会话也将保持打开状态，直到会话终止。

您还可以通过ARD**直接发送Unix命令**，并且如果您是管理员用户，可以指定root用户来执行root权限的操作。您甚至可以使用这种Unix命令方法来安排远程任务在特定时间运行，但这将在指定的时间进行网络连接（而不是存储和在目标服务器上执行）。最后，远程Spotlight是我最喜欢的功能之一。它非常方便，因为您可以快速远程运行低影响力的索引搜索。这对于搜索敏感文件非常有用，因为它快速，可以同时在多台机器上运行搜索，并且不会使CPU占用率飙升。

## Bonjour协议

**Bonjour**是苹果设计的一种技术，使位于同一网络上的计算机和**设备能够了解其他计算机和设备提供的服务**。它的设计使得任何支持Bonjour的设备可以插入TCP/IP网络中，它将**选择一个IP地址**并使该网络上的其他计算机**了解它提供的服务**。Bonjour有时也被称为Rendezvous、**Zero Configuration**或Zeroconf。\
Zero Configuration Networking（如Bonjour）提供了以下功能：

* 必须能够**获取IP地址**（即使没有DHCP服务器）
* 必须能够进行**名称到地址的转换**（即使没有DNS服务器）
* 必须能够**发现网络上的服务**

设备将获得一个**在169.254/16范围内的IP地址**，并检查是否有其他设备正在使用该IP地址。如果没有，它将保留该IP地址。Mac会在其路由表中保留此子网的条目：`netstat -rn | grep 169`

对于DNS，使用**多播DNS（mDNS）协议**。[**mDNS服务**监听端口**5353/UDP**](../../network-services-pentesting/5353-udp-multicast-dns-mdns.md)，使用**常规DNS查询**，并使用**多播地址224.0.0.251**而不是仅向IP地址发送请求。任何监听这些请求的机器都会响应，通常是向多播地址发送响应，以便所有设备都可以更新其表格。\
每个设备在访问网络时都会**选择自己的名称**，设备将选择一个以`.local`结尾的名称（可能基于主机名或完全随机）。

**发现服务**使用了**DNS服务发现（DNS-SD）**。

Zero Configuration Networking的最后一个要求通过**DNS服务发现（DNS-SD）**得到满足。DNS服务发现使用了DNS SRV记录的语法，但使用**DNS PTR记录**，以便如果多个主机提供特定服务，则可以返回多个结果。客户端请求名称`<Service>.<Domain>`的PTR查找，并**接收**一个形式为`<Instance>.<Service>.<Domain>`的零个或多个PTR记录列表。

可以使用`dns-sd`二进制文件来**广告服务和执行服务查找**：
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
当一个新的服务启动时，**新服务会向子网上的所有人广播其存在**。监听者不需要询问，只需要保持监听状态。

你可以使用[**这个工具**](https://apps.apple.com/us/app/discovery-dns-sd-browser/id1381004916?mt=12)来查看当前本地网络中**提供的服务**。\
或者你可以使用[**python-zeroconf**](https://github.com/jstasiak/python-zeroconf)编写自己的Python脚本：
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
如果你觉得Bonjour可能更安全**禁用**，你可以使用以下方法禁用它：
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## 参考资料

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
