# macOS Dosya Uzantısı ve URL şema uygulama işleyicileri

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünleri**]'ni edinin (https://peass.creator-spring.com)
* [**The PEASS Ailesi**]'ni keşfedin (https://opensea.io/collection/the-peass-family), özel [**NFT'ler**]'imiz koleksiyonunu
* **Katılın** 💬 [**Discord grubuna**] (https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**] veya **bizi takip edin** **Twitter** 🐦 [**@carlospolopm**] (https://twitter.com/hacktricks\_live)**.**
* **Hacking hilelerinizi paylaşarak PR göndererek HackTricks** (https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**] (https://github.com/carlospolop/hacktricks-cloud) github depolarına.

</details>

## LaunchServices Veritabanı

Bu, macOS'ta yüklü olan tüm uygulamaların bulunduğu bir veritabanıdır ve her yüklü uygulama hakkında bilgi almak için sorgulanabilir, örneğin desteklediği URL şemaları ve MIME türleri.

Bu veritabanını şu şekilde dökümleyebilirsiniz:

{% code overflow="wrap" %}
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
{% endcode %}

Veya [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) aracını kullanarak.

**`/usr/libexec/lsd`**, veritabanının beynidir. `.lsd.installation`, `.lsd.open`, `.lsd.openurl` gibi **birkaç XPC hizmeti** sağlar. Ancak ayrıca uygulamaların `.launchservices.changedefaulthandler` veya `.launchservices.changeurlschemehandler` gibi açığa çıkarılan XPC işlevlerini kullanabilmek için bazı **yetkilendirmelere** ihtiyaç duyar, mime türleri veya url şemaları için varsayılan uygulamaları değiştirmek ve diğer işlevler.

**`/System/Library/CoreServices/launchservicesd`**, `com.apple.coreservices.launchservicesd` hizmetini iddia eder ve çalışan uygulamalar hakkında bilgi almak için sorgulanabilir. Sistem aracı /**`usr/bin/lsappinfo`** veya [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) ile sorgulanabilir.

## Dosya Uzantısı ve URL şeması uygulama işleyicileri

Aşağıdaki satır, uzantıya bağlı olarak dosyaları açabilen uygulamaları bulmak için faydalı olabilir:

{% code overflow="wrap" %}
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
{% endcode %}

Veya [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps) gibi bir şey kullanın:
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
Ayrıca, bir uygulamanın desteklediği uzantıları kontrol edebilirsiniz:
```
cd /Applications/Safari.app/Contents
grep -A3 CFBundleTypeExtensions Info.plist  | grep string
<string>css</string>
<string>pdf</string>
<string>webarchive</string>
<string>webbookmark</string>
<string>webhistory</string>
<string>webloc</string>
<string>download</string>
<string>safariextz</string>
<string>gif</string>
<string>html</string>
<string>htm</string>
<string>js</string>
<string>jpg</string>
<string>jpeg</string>
<string>jp2</string>
<string>txt</string>
<string>text</string>
<string>png</string>
<string>tiff</string>
<string>tif</string>
<string>url</string>
<string>ico</string>
<string>xhtml</string>
<string>xht</string>
<string>xml</string>
<string>xbl</string>
<string>svg</string>
```
<details>

<summary><strong>Sıfırdan kahraman olmaya kadar AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**'da takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek HackTricks** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına.

</details>
