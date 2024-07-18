# macOS Paketleri

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* Hacking püf noktalarını paylaşarak **HackTricks** ve **HackTricks Cloud** github depolarına PR gönderin.

</details>
{% endhint %}

## Temel Bilgiler

macOS'taki paketler, uygulamaları, kütüphaneleri ve diğer gerekli dosyaları içeren çeşitli kaynakların bir konteyneri olarak hizmet eder ve Finder'da tek bir nesne olarak görünmelerini sağlar, örneğin tanıdık `*.app` dosyaları. En sık karşılaşılan paket genellikle `.app` paketidir, ancak `.framework`, `.systemextension` ve `.kext` gibi diğer türler de yaygındır.

### Bir Paketin Temel Bileşenleri

Bir paket içinde, özellikle `<uygulama>.app/Contents/` dizini içinde, çeşitli önemli kaynaklar bulunmaktadır:

* **\_CodeSignature**: Bu dizin, uygulamanın bütünlüğünü doğrulamak için hayati öneme sahip olan kod imzalama ayrıntılarını depolar. Kod imzalama bilgilerini şu komutlarla inceleyebilirsiniz: %%%bash openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64 %%%
* **MacOS**: Kullanıcı etkileşimi sırasında çalışan uygulamanın yürütülebilir binary'sini içerir.
* **Resources**: Uygulamanın kullanıcı arayüzü bileşenlerini, resimleri, belgeleri ve arayüz açıklamalarını (nib/xib dosyalarını) içeren bir depo.
* **Info.plist**: Uygulamanın ana yapılandırma dosyası olarak hareket eder, uygulamanın uygun şekilde tanınmasını ve etkileşimde bulunmasını sağlamak için önemlidir.

#### Info.plist'teki Önemli Anahtarlar

`Info.plist` dosyası, uygulama yapılandırması için bir köşetaşı olup şu anahtarları içerir:

* **CFBundleExecutable**: `Contents/MacOS` dizininde bulunan ana yürütülebilir dosyanın adını belirtir.
* **CFBundleIdentifier**: Uygulama için genel bir tanımlayıcı sağlar, macOS tarafından uygulama yönetimi için yoğun bir şekilde kullanılır.
* **LSMinimumSystemVersion**: Uygulamanın çalışması için gereken macOS'in minimum sürümünü belirtir.

### Paketleri Keşfetme

`Safari.app` gibi bir paketin içeriğini keşfetmek için şu komut kullanılabilir: `bash ls -lR /Applications/Safari.app/Contents`

Bu keşif, `_CodeSignature`, `MacOS`, `Resources` gibi dizinleri ve `Info.plist` gibi dosyaları ortaya çıkarır; her biri uygulamayı güvence altına almak ve kullanıcı arayüzünü ve işletme parametrelerini tanımlamak için benzersiz bir amaçla hizmet verir.

#### Ek Paket Dizinleri

Ortak dizinlerin ötesinde, paketler ayrıca şunları içerebilir:

* **Frameworks**: Uygulama tarafından kullanılan paketlenmiş çerçeveleri içerir. Çerçeveler, ek kaynaklara sahip dylib'ler gibidir.
* **PlugIns**: Uygulamanın yeteneklerini artıran eklentiler ve uzantılar için bir dizin.
* **XPCServices**: Uygulama tarafından dış işlem iletişimi için kullanılan XPC hizmetlerini barındırır.

Bu yapı, tüm gerekli bileşenlerin paket içinde kapsanmasını sağlayarak modüler ve güvenli bir uygulama ortamını kolaylaştırır.

`Info.plist` anahtarları ve anlamları hakkında daha detaylı bilgi için Apple geliştirici belgeleri kapsamlı kaynaklar sunmaktadır: [Apple Info.plist Anahtar Referansı](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* Hacking püf noktalarını paylaşarak **HackTricks** ve **HackTricks Cloud** github depolarına PR gönderin.

</details>
{% endhint %}
