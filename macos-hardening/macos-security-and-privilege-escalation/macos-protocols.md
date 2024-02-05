# macOS网络服务与协议

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 远程访问服务

这些是常见的macOS远程访问服务。\
您可以在`系统偏好设置` --> `共享`中启用/禁用这些服务

* **VNC**，称为“屏幕共享”（tcp:5900）
* **SSH**，称为“远程登录”（tcp:22）
* **Apple远程桌面**（ARD），或称“远程管理”（tcp:3283，tcp:5900）
* **AppleEvent**，称为“远程Apple事件”（tcp:3031）

运行以下命令检查是否已启用任何服务：
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### 渗透测试 ARD

Apple 远程桌面（ARD）是针对 macOS 定制的 [虚拟网络计算（VNC）](https://en.wikipedia.org/wiki/Virtual_Network_Computing) 的增强版本，提供额外功能。ARD 中一个显著的漏洞是其控制屏幕密码的身份验证方法仅使用密码的前 8 个字符，容易受到[暴力破解攻击](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html)的影响，使用 Hydra 或 [GoRedShell](https://github.com/ahhh/GoRedShell/) 等工具，因为没有默认速率限制。

可以使用 **nmap** 的 `vnc-info` 脚本识别存在漏洞的实例。支持 `VNC Authentication (2)` 的服务特别容易受到暴力破解攻击的影响，因为密码被截断为 8 个字符。

要启用 ARD 以执行各种管理任务，如特权升级、GUI 访问或用户监控，请使用以下命令：
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
## Bonjour协议

Bonjour是苹果设计的技术，允许**同一网络上的设备检测彼此提供的服务**。也被称为Rendezvous、**零配置**或Zeroconf，它使设备能够加入TCP/IP网络，**自动选择IP地址**，并向其他网络设备广播其服务。

由Bonjour提供的零配置网络确保设备可以：
* **即使没有DHCP服务器，也能自动获取IP地址**。
* 在不需要DNS服务器的情况下执行**名称到地址的转换**。
* **发现**网络上可用的服务。

使用Bonjour的设备将从**169.254/16范围内分配给自己一个IP地址**，并验证其在网络上的唯一性。Mac会为这个子网维护一个路由表条目，可以通过`netstat -rn | grep 169`进行验证。

对于DNS，Bonjour利用**多播DNS（mDNS）协议**。mDNS通过**端口5353/UDP**运行，使用**标准DNS查询**，但针对**多播地址224.0.0.251**。这种方法确保网络上所有监听设备都可以接收并响应查询，从而更新其记录。

加入网络后，每个设备会自行选择一个名称，通常以**.local**结尾，可以从主机名或随机生成的名称中派生。

网络内的服务发现由**DNS服务发现（DNS-SD）**实现。利用DNS SRV记录的格式，DNS-SD使用**DNS PTR记录**来列出多个服务。寻找特定服务的客户端将请求`<Service>.<Domain>`的PTR记录，如果服务在多个主机上可用，则会收到格式为`<Instance>.<Service>.<Domain>`的PTR记录列表。

`dns-sd`实用程序可用于**发现和广告网络服务**。以下是一些示例用法：

### 搜索SSH服务

要在网络上搜索SSH服务，请使用以下命令：
```bash
dns-sd -B _ssh._tcp
```
这个命令启动了对_ssh._tcp服务的浏览，并输出时间戳、标志、接口、域、服务类型和实例名称等详细信息。

### 广告一个HTTP服务

要广告一个HTTP服务，你可以使用：
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
这个命令在端口80上注册了一个名为"Index"的HTTP服务，路径为`/index.html`。

要在网络上搜索HTTP服务：
```bash
dns-sd -B _http._tcp
```
当服务启动时，它通过多播向子网上的所有设备宣布其可用性。对这些服务感兴趣的设备无需发送请求，只需监听这些公告。

为了提供更用户友好的界面，可在Apple App Store上获取的****Discovery - DNS-SD Browser** 应用程序可以可视化本地网络上提供的服务。

或者，可以编写自定义脚本来使用`python-zeroconf`库浏览和发现服务。[**python-zeroconf**](https://github.com/jstasiak/python-zeroconf)脚本演示了为`_http._tcp.local.`服务创建服务浏览器，并打印已添加或已移除的服务：
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
### 禁用Bonjour
如果出于安全或其他原因需要禁用Bonjour，则可以使用以下命令关闭：
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## 参考资料

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
