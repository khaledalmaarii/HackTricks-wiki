# macOS Paketleri

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşün</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>ile öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## Temel Bilgiler

macOS'ta paketler, uygulamalar, kütüphaneler ve diğer gerekli dosyalar gibi çeşitli kaynakları içeren birer konteyner olarak hizmet eder ve bu sayede tanıdık `*.app` dosyaları gibi Finder'da tek bir nesne olarak görünürler. En sık karşılaşılan paket `.app` paketidir, ancak `.framework`, `.systemextension` ve `.kext` gibi diğer türler de yaygındır.

### Bir Paketin Temel Bileşenleri

Bir paketin içinde, özellikle `<uygulama>.app/Contents/` dizini içinde, çeşitli önemli kaynaklar bulunur:

- **_CodeSignature**: Bu dizin, uygulamanın bütünlüğünü doğrulamak için önemli olan kod imzalama ayrıntılarını depolar. Kod imzalama bilgilerini aşağıdaki gibi komutlarla inceleyebilirsiniz:
%%%bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
%%%
- **MacOS**: Kullanıcı etkileşimiyle çalışan uygulamanın yürütülebilir ikili dosyasını içerir.
- **Resources**: Uygulamanın görüntüleri, belgeleri ve arayüz açıklamaları (nib/xib dosyaları) gibi kullanıcı arayüzü bileşenlerini depolar.
- **Info.plist**: Uygulamanın ana yapılandırma dosyası olarak işlev görür ve uygulamanın sistem tarafından tanınmasını ve etkileşimde bulunmasını sağlamak için önemlidir.

#### Info.plist'deki Önemli Anahtarlar

`Info.plist` dosyası, uygulama yapılandırması için temel bir taşınmasıdır ve aşağıdaki gibi anahtarları içerir:

- **CFBundleExecutable**: `Contents/MacOS` dizininde bulunan ana yürütülebilir dosyanın adını belirtir.
- **CFBundleIdentifier**: Uygulama için global bir tanımlayıcı sağlar ve macOS tarafından uygulama yönetimi için yoğun bir şekilde kullanılır.
- **LSMinimumSystemVersion**: Uygulamanın çalışması için gereken macOS'in minimum sürümünü belirtir.

### Paketleri Keşfetme

`Safari.app` gibi bir paketin içeriğini keşfetmek için aşağıdaki komut kullanılabilir:
%%%bash
ls -lR /Applications/Safari.app/Contents
%%%

Bu keşif, `_CodeSignature`, `MacOS`, `Resources` gibi dizinleri ve `Info.plist` gibi dosyaları ortaya çıkarır, her biri uygulamanın güvenliğinden kullanıcı arayüzünü ve işletimsel parametrelerini tanımlamasına kadar benzersiz bir amaçla hizmet eder.

#### Ek Paket Dizinleri

Ortak dizinlerin ötesinde, paketler ayrıca şunları içerebilir:

- **Frameworks**: Uygulama tarafından kullanılan paketlenmiş çerçeveleri içerir.
- **PlugIns**: Uygulamanın yeteneklerini artıran eklentilerin ve uzantıların bulunduğu bir dizin.
- **XPCServices**: Uygulama tarafından dış süreç iletişimi için kullanılan XPC hizmetlerini barındırır.

Bu yapı, tüm gerekli bileşenlerin paketin içinde kapsüllenmesini sağlar, böylece modüler ve güvenli bir uygulama ortamı sağlanır.

`Info.plist` anahtarları ve anlamları hakkında daha detaylı bilgi için Apple geliştirici belgeleri kapsamlı kaynaklar sağlar: [Apple Info.plist Anahtar Referansı](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşün</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>ile öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
