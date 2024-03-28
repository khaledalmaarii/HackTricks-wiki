# macOS Paketleri

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşün</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks ve HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>

## Temel Bilgiler

macOS'taki paketler, uygulamaları, kütüphaneleri ve diğer gerekli dosyaları içeren bir dizi kaynağı barındıran konteynerler olarak hizmet eder, bu da onları Finder'da tek bir nesne olarak görünmesini sağlar, örneğin tanıdık `*.app` dosyaları. En sık karşılaşılan paket `.app` paketidir, ancak `.framework`, `.systemextension` ve `.kext` gibi diğer türler de yaygındır.

### Bir Paketin Temel Bileşenleri

Bir paket içinde, özellikle `<uygulama>.app/Contents/` dizini içinde, çeşitli önemli kaynaklar bulunmaktadır:

* **\_CodeSignature**: Bu dizin, uygulamanın bütünlüğünü doğrulamak için hayati öneme sahip olan kod imzalama ayrıntılarını depolar. Kod imzalama bilgilerini şu komutlarla inceleyebilirsiniz: %%%bash openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64 %%%
* **MacOS**: Kullanıcı etkileşimiyle çalışan uygulamanın yürütülebilir ikili dosyasını içerir.
* **Resources**: Uygulamanın kullanıcı arayüzü bileşenlerini içeren bir depo, resimler, belgeler ve arayüz açıklamaları (nib/xib dosyaları) gibi.
* **Info.plist**: Uygulamanın ana yapılandırma dosyası olarak hareket eder, uygulamanın uygun şekilde tanınmasını ve etkileşimde bulunmasını sağlamak için önemlidir.

#### Info.plist'teki Önemli Anahtarlar

`Info.plist` dosyası, uygulama yapılandırması için bir köşe taşıdır ve şu gibi anahtarlar içerir:

* **CFBundleExecutable**: `Contents/MacOS` dizininde bulunan ana yürütülebilir dosyanın adını belirtir.
* **CFBundleIdentifier**: Uygulama için genel bir tanımlayıcı sağlar, macOS tarafından uygulama yönetimi için yoğun bir şekilde kullanılır.
* **LSMinimumSystemVersion**: Uygulamanın çalışması için gereken macOS'in minimum sürümünü belirtir.

### Paketleri Keşfetme

`Safari.app` gibi bir paketin içeriğini keşfetmek için şu komut kullanılabilir: `bash ls -lR /Applications/Safari.app/Contents`

Bu keşif, `_CodeSignature`, `MacOS`, `Resources` gibi dizinleri ve `Info.plist` gibi dosyaları ortaya çıkarır, her biri uygulamayı güvence altına almak ve kullanıcı arayüzünü ve işletme parametrelerini tanımlamak için benzersiz bir amaçtan hizmet eder.

#### Ek Paket Dizinleri

Ortak dizinlerin ötesinde, paketler ayrıca şunları içerebilir:

* **Frameworks**: Uygulama tarafından kullanılan paketlenmiş çerçeveleri içerir. Çerçeveler, ek kaynaklara sahip dylib'ler gibidir.
* **PlugIns**: Uygulamanın yeteneklerini artıran eklentiler ve uzantılar için bir dizin.
* **XPCServices**: Uygulamanın dış işlem iletişimi için kullandığı XPC hizmetlerini barındırır.

Bu yapı, tüm gerekli bileşenlerin paket içinde kapsanmasını sağlayarak modüler ve güvenli bir uygulama ortamını kolaylaştırır.

`Info.plist` anahtarları ve anlamları hakkında daha detaylı bilgi için Apple geliştirici belgeleri kapsamlı kaynaklar sunar: [Apple Info.plist Anahtar Referansı](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşün</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks ve HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>
