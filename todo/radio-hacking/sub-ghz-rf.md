# Sub-GHz RF

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**'da takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>

## Garaj Kapıları

Garaj kapı açıcıları genellikle 300-190 MHz aralığında frekansta çalışır, en yaygın frekanslar ise 300 MHz, 310 MHz, 315 MHz ve 390 MHz'dir. Bu frekans aralığı genellikle garaj kapı açıcıları için kullanılır çünkü diğer frekans bantlarından daha az kalabalıktır ve diğer cihazlardan gelen müdahaleyi daha az yaşama olasılığı vardır.

## Araç Kapıları

Çoğu araç anahtarları ya **315 MHz ya da 433 MHz** frekanslarında çalışır. Bunlar her ikisi de radyo frekanslarıdır ve çeşitli farklı uygulamalarda kullanılır. İki frekans arasındaki temel fark, 433 MHz'nin 315 MHz'den daha uzun menzile sahip olmasıdır. Bu, 433 MHz'nin uzun menzil gerektiren uygulamalar için daha iyi olduğu anlamına gelir, örneğin uzaktan anahtarsız giriş.

Avrupa'da 433.92 MHz yaygın olarak kullanılırken, ABD ve Japonya'da 315 MHz kullanılır.

## **Kaba Kuvvet Saldırısı**

<figure><img src="../../.gitbook/assets/image (1081).png" alt=""><figcaption></figcaption></figure>

Her kodu 5 kez göndermek yerine (alıcının almasını sağlamak için bu şekilde gönderilir) sadece bir kez gönderirseniz, süre 6 dakikaya düşer:

<figure><img src="../../.gitbook/assets/image (616).png" alt=""><figcaption></figcaption></figure>

ve sinyaller arasındaki **2 ms bekleme süresini kaldırarak** süreyi **3 dakikaya düşürebilirsiniz**.

Ayrıca, De Bruijn Dizisi'ni kullanarak (tüm potansiyel ikili sayıları göndermek için gereken bit sayısını azaltmanın bir yolu) bu süre sadece **8 saniyeye düşer**:

<figure><img src="../../.gitbook/assets/image (580).png" alt=""><figcaption></figcaption></figure>

Bu saldırının bir örneği [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame) adresinde uygulanmıştır.

**Önambul gereksinimi**, De Bruijn Dizisi optimizasyonunu önleyecek ve **döner kodlar bu saldırıyı engelleyecektir** (kodun kaba kuvvetle çözülemeyecek kadar uzun olduğu varsayılırsa).

## Sub-GHz Saldırısı

Bu sinyalleri Flipper Zero ile saldırmak için kontrol edin:

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## Döner Kodlar Koruma

Otomatik garaj kapı açıcıları genellikle garaj kapısını açmak veya kapatmak için kablosuz uzaktan kumandayı kullanır. Uzaktan kumanda, garaj kapı açıcısına bir radyo frekansı (RF) sinyali gönderir ve motoru açmak veya kapatmak için harekete geçirir.

Birisi RF sinyalini yakalamak ve daha sonra kullanmak için kaydetmek için bir kod yakalayıcı adı verilen bir cihaz kullanabilir. Buna **tekrar saldırısı** denir. Bu tür bir saldırıyı önlemek için, birçok modern garaj kapı açıcı daha güvenli bir şifreleme yöntemi olan **döner kod** sistemini kullanır.

**RF sinyali genellikle döner bir kod kullanılarak** iletilir, yani her kullanımda kod değişir. Bu, birinin sinyali yakalamasını ve garaja **izin verilmeyen** erişim sağlamak için kullanmasını **zorlaştırır**.

Döner kod sisteminde, uzaktan kumanda ve garaj kapı açıcısının her kullanımda yeni bir kod üreten **ortak bir algoritması** vardır. Garaj kapı açıcısı sadece **doğru kod**a yanıt verecektir, bu da birinin sadece bir kod yakalayarak garaja izinsiz erişim sağlamasını çok daha zor hale getirir.

### **Eksik Bağlantı Saldırısı**

Temelde, düğmeye basmayı dinlersiniz ve cihazın (örneğin araba veya garaj) menzil dışında olduğu sırada sinyali **yakalarsınız**. Daha sonra cihaza geçersiniz ve **yakalanan kodu kullanarak açarsınız**.

### Tam Bağlantı Sinyali Engelleme Saldırısı

Bir saldırgan, aracın yanında veya alıcının yakınında sinyali **engelleyebilir**, böylece **alıcı kodu aslında 'duyamaz'** ve bunun gerçekleştiği sırada sadece **kaydedip tekrar oynatabilir**.

Kurban bir noktada **arabayı kilitlemek için anahtarı kullanacak**, ancak saldırı **umarım kapıyı açmak için yeterince "kapıyı kapat" kodu kaydeder** (aynı kodları açmak ve kapatmak için kullanan araçlar olduğundan, farklı frekansta her iki komutu da dinleyen araçlar için frekans değişikliği gerekebilir).

{% hint style="warning" %}
**Engelleme işe yarar**, ancak **arabayı kilitleyen kişi basitçe kapıların kilitli olup olmadığını kontrol ederse arabanın kilidini açık bulabilir. Ayrıca, böyle saldırılardan haberdar olanlar kapıların kilitlendiğini kontrol etmek için kapıları test edebilir veya 'kilit' düğmesine bastıklarında arabanın kilit sesini veya arabanın ışıklarının yanıp sönmediğini dinleyebilir.
{% endhint %}

### **Kod Yakalama Saldırısı (veya ‘RollJam’)**

Bu daha **gizli Engelleme tekniğidir**. Saldırgan sinyali engeller, böylece kurban kapıyı kilitlemeye çalıştığında işe yaramaz, ancak saldırgan bu kodu **kaydeder**. Ardından, kurban **arabayı tekrar kilitlemeye çalışır**ken düğmeye basar ve araba bu **ikinci kodu kaydeder**.\
Hemen ardından **saldırgan ilk kodu gönderebilir** ve **araba kilitlenecektir** (kurban ikinci basışın kapattığını düşünecektir). Ardından, saldırgan **ikinci çalınan kodu gönderebilir** ve aracı **açabilir** (bir **"arabayı kapat" kodunun aynı zamanda açmak için de kullanılabileceği** varsayılırsa). Frekans değişikliği gerekebilir (aynı kodları açmak ve kapatmak için kullanan araçlar olduğundan, farklı frekansta her iki komutu da dinleyen araçlar için frekans değişikliği gerekebilir).

Saldırgan, **araba alıcısını engelleyebilir ve kendi alıcısını engellemez** çünkü araba alıcısı örneğin 1 MHz geniş bantta dinliyorsa, saldırgan **uzaktan kumandanın kullandığı tam frekansı engellemez** ancak **saldırıya uğramış bir spektrumda yakın bir frekansta engeller** ve **saldırganın alıcısı**, uzaktan kumandanın sinyalini **engel olmadan** dinleyebileceği daha küçük bir aralıkta dinler.

{% hint style="warning" %}
Diğer özelliklerde görülen uygulamalar, **döner kodun toplam kodun bir parçası olduğunu** göstermektedir. Yani gönderilen kod, ilk **12'si döner kod**, ikinci 8'i **komut** (örneğin kilitleme veya açma) ve son 4'ü **kontrol toplamı** olan **24 bitlik bir anahtar**dır. Bu türü uygulayan araçlar da doğal olarak savunmasızdır çünkü saldırgan, yalnızca döner kod segmentini değiştirmesi gerektiğinden her iki frekansta da **herhangi bir döner kodu kullanabilmektedir**.
{% endhint %}

{% hint style="danger" %}
Kurban, saldırganın ilk kodu gönderirken üçüncü bir kod gönderirse, ilk ve ikinci kod geçersiz hale gelir.
{% endhint %}
### Alarm Sounding Jamming Attack

Bir araca takılan satış sonrası bir rulo kod sistemi üzerinde test yapılırken, **aynı kodun iki kez gönderilmesi** hemen **alarmı etkinleştirdi** ve immobilizer sağlayarak benzersiz bir **hizmet reddi** fırsatı sundu. İronik bir şekilde, alarmı ve immobilizer'ı **devre dışı bırakmanın** yolu, saldırganın **uzaktan kumandayı basması** idi, saldırganın **sürekli olarak DoS saldırısı gerçekleştirmesine** olanak tanıdı. Veya bu saldırıyı **öncekiyle birleştirerek daha fazla kod elde etmek** için kurbanın saldırıyı en kısa sürede durdurmak isteyeceği.

## Referanslar

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
