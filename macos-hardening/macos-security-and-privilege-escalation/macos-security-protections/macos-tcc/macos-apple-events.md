# macOS Apple Olayları

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**'da takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## Temel Bilgiler

**Apple Olayları**, uygulamaların birbirleriyle iletişim kurmasını sağlayan Apple'ın macOS'ındaki bir özelliktir. Bunlar, işletim sistemi içindeki işlem arası iletişimi ele alan macOS işletim sisteminin bir bileşeni olan **Apple Olay Yöneticisi**'nin bir parçasıdır. Bu sistem, bir uygulamanın diğer bir uygulamaya belirli bir işlemi gerçekleştirmesini istemek için bir mesaj göndermesine olanak tanır, örneğin bir dosyayı açma, veri alımı veya komut yürütme gibi.

Mina daemonu `/System/Library/CoreServices/appleeventsd`'dir ve `com.apple.coreservices.appleevents` hizmetini kaydeder.

Olayları alabilen her uygulama, Apple Olay Mach Port'unu sağlayarak bu daemon ile kontrol eder. Ve bir uygulama bir olay göndermek istediğinde, uygulama bu bağlantı noktasını daemon'dan isteyecektir.

Kumlanmış uygulamalar, olay göndermeye yetenekli olabilmek için `allow appleevent-send` ve `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` gibi ayrıcalıklara ihtiyaç duyar. `com.apple.security.temporary-exception.apple-events` gibi yetkilendirmelerin, `com.apple.private.appleevents` gibi yetkilendirmelere ihtiyaç duyacak olan olayları kimin gönderebileceğini kısıtlayabileceğini unutmayın.

{% hint style="success" %}
Mesajın gönderildiği hakkında bilgi kaydetmek için **`AEDebugSends`** ortam değişkenini kullanmak mümkündür:
```bash
AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
```
{% endhint %}

<details>

<summary><strong>Sıfırdan kahraman olmaya kadar AWS hacklemeyi öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR gönderin.

</details>
