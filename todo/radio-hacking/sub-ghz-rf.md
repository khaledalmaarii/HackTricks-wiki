# Sub-GHz RF

<details>

<summary><strong>AWS hackleme becerilerinizi sıfırdan kahraman seviyesine yükseltin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family)
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## Garaj Kapıları

Garaj kapı açıcıları genellikle 300-190 MHz aralığında çalışır, en yaygın frekanslar ise 300 MHz, 310 MHz, 315 MHz ve 390 MHz'dir. Bu frekans aralığı, diğer frekans bantlarından daha az kalabalık olduğu ve diğer cihazlardan gelen müdahaleye daha az maruz kaldığı için garaj kapı açıcıları için yaygın olarak kullanılır.

## Araba Kapıları

Çoğu araba anahtarları genellikle **315 MHz veya 433 MHz** üzerinde çalışır. Bunlar her ikisi de radyo frekanslarıdır ve çeşitli farklı uygulamalarda kullanılır. İki frekans arasındaki temel fark, 433 MHz'in 315 MHz'den daha uzun menzile sahip olmasıdır. Bu, uzun menzil gerektiren uygulamalar için 433 MHz'in daha iyi olduğu anlamına gelir, örneğin uzaktan kumandalı giriş.

Avrupa'da genellikle 433.92MHz kullanılırken, ABD ve Japonya'da 315MHz kullanılır.

## **Brute-force Saldırısı**

<figure><img src="../../.gitbook/assets/image (4) (3) (2).png" alt=""><figcaption></figcaption></figure>

Eğer her kodu 5 kez göndermek yerine (alıcının almasını sağlamak için böyle gönderilir) sadece bir kez gönderirseniz, süre 6 dakikaya düşer:

<figure><img src="../../.gitbook/assets/image (1) (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

Ve sinyaller arasındaki 2 ms bekleme süresini kaldırırsanız, süreyi 3 dakikaya kadar düşürebilirsiniz.

Ayrıca, De Bruijn Dizisi'ni kullanarak (tüm potansiyel ikili sayıları göndermek için gereken bit sayısını azaltan bir yöntem) bu süre sadece 8 saniyeye düşer:

<figure><img src="../../.gitbook/assets/image (5) (2) (3).png" alt=""><figcaption></figcaption></figure>

Bu saldırının bir örneği [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame) adresinde uygulanmıştır.

**Önambul gerekliliği**, De Bruijn Dizisi optimizasyonunu önler ve **gezici kodlar bu saldırıyı engeller** (kodun kaba kuvvetle çözülemeyecek kadar uzun olduğunu varsayarsak).

## Sub-GHz Saldırısı

Flipper Zero ile bu sinyallere saldırmak için kontrol edin:

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## Gezici Kodlar Koruması

Otomatik garaj kapı açıcıları genellikle kablosuz bir uzaktan kumanda kullanarak garaj kapısını açıp kapatır. Uzaktan kumanda, garaj kapısını açmak veya kapatmak için bir radyo frekansı (RF) sinyali gönderir.

Birisi, RF sinyalini yakalamak ve daha sonra kullanmak için bir cihaz olan bir kod yakalayıcı kullanarak RF sinyalini engelleyebilir ve kaydedebilir. Buna bir **tekrar saldırısı** denir. Bu tür bir saldırıyı önlemek için, birçok modern garaj kapı açıcısı daha güvenli bir şifreleme yöntemi olan bir **gezici kod** sistemini kullanır.

RF sinyali genellikle her kullanımda değişen bir **gezici kod** kullanılarak iletilir. Bu, kodun yakalanması ve garaja yetkisiz erişim sağlamak için kullanılması **zorlaştırır**.

Gezici kod sisteminde, uzaktan kumanda ve garaj kapı açıcısı, her uzaktan kumanda kullanıldığında yeni bir kod üreten bir **paylaşılan algoritma**ya sahiptir. Garaj kapı açıcısı, yalnızca **doğru kod**a yanıt verecektir, bu da bir kodun yakalanarak garaja yetkisiz erişim sağlamayı çok daha zor hale getirir.

### **Eksik Bağlantı Saldırısı**

Temel olarak, düğmeyi dinlersiniz ve uzaktan kumanda cihazının (örneğin araba veya garaj) menzilinin dışında olduğu sırada sinyali **yakalarsınız**. Ardından cihaza geçersiniz ve yakalanan kodu kullanarak onu **açarsınız**.

### Tam Bağlantı Engellemesi Saldırısı

Bir saldırgan, araç veya alıcıya **yakın bir yerde sinyali engelleyebilir**, böylece **alıcı kodu 'duyamaz'** ve bunu yaptıktan sonra sadece sinyali **yakalayıp tekrar oynatabilir**.

Kurban bir noktada **arabayı kilitlemek için tuşları kullanacak**, ancak saldırı **"kapıyı kapat" kodlarını kaydedecek** kadar kaydedecektir (farklı frekanslarda her iki komutu da dinleyen araçlar olduğundan **frekans değişikliği gerekebilir**).

{% hint style="warning" %}
**Engelleme işe yarar**, ancak **arabayı kilitleyen kişi** sadece kapıların kilitlendiğinden emin olmak için kapıları **test ederse** arabanın kilidinin açık olduğunu fark eder. Ayrıca, böyle saldırılardan haberdar olan kişiler, kapıların kilit **sesini** yapmadığını veya arabanın **ışıklarının** 'kilit' düğmesine bastıklarında yanıp sönmediğini bile dinleyebilirler.
{% endhint %}

### **Kod Yakalama Saldırısı (aka 'RollJam')**

Bu daha **gizli bir Engelleme tekniğidir**. Saldırgan sinyali engeller, böylece kurban kapıyı kilitlemeye çalıştığında işe yaramaz, ancak saldırgan bu kodu **kaydeder**. Ardından, kurban aracı tekrar kilitlemeye çalışırken düğmeye basar ve araç bu ikinci kodu **kaydeder**.\
Hemen ardından, saldırgan **ilk kodu gönderebilir** ve araç **kilitlenir** (kurban ikinci basışın bunu kapattığını düşünecektir). Ardından, sald
### Alarm Sounding Jamming Saldırısı

Bir araca takılan satış sonrası bir dönen kod sistemi üzerinde test yaparken, **aynı kodu iki kez göndermek**, hemen **alarmı aktive etti** ve immobilizerı devre dışı bıraktı, benzersiz bir **hizmet reddi** fırsatı sağladı. İlginç bir şekilde, alarmı ve immobilizerı **devre dışı bırakmanın** yolu, **uzaktan kumandayı basmaktı**, bu da saldırganın sürekli olarak DoS saldırısı gerçekleştirme yeteneğini sağladı. Veya bu saldırıyı **öncekiyle birleştirerek daha fazla kod elde etmek** için kullanabilirsiniz, çünkü kurban saldırıyı en kısa sürede durdurmak isteyecektir.

## Referanslar

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>
