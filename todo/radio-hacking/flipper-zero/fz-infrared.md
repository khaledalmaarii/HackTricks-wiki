# FZ - Kızılötesi

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşün</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

* **Bir siber güvenlik şirketinde mi çalışıyorsunuz? Şirketinizin HackTricks'te reklamını görmek ister misiniz? Ya da PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek ister misiniz?** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) **kontrol edin!**
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonunu
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* **Katılın** [**💬**](https://emojipedia.org/speech-balloon/) **Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks deposuna** [**PR gönderin**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud deposuna**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Giriş <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Kızılötesinin nasıl çalıştığı hakkında daha fazla bilgi için şu adrese bakın:

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## Flipper Zero'da Kızılötesi Sinyal Alıcısı <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper, IR sinyal alıcısı TSOP kullanır, bu da **IR uzaktan kumandaların sinyallerini yakalamayı** mümkün kılar. Xiaomi gibi **bazı akıllı telefonlar** da bir IR bağlantı noktasına sahip olabilir, ancak **çoğu yalnızca sinyal iletebilir** ve **alabilir**.

Flipper'ın kızılötesi **alıcısı oldukça hassastır**. TV'nin yanında dururken ve hem siz hem de Flipper biraz uzaktaysanız bile sinyali **yakalayabilirsiniz**. Kumandayı doğrudan Flipper'ın IR bağlantı noktasına yönlendirmek gereksizdir. Bu, birisi TV'nin yanında kanalları değiştirirken ve hem siz hem de Flipper biraz uzakta olduğunuzda işe yarar.

Kızılötesi sinyalin **çözümlenmesi yazılım** tarafında gerçekleştiği için, Flipper Zero potansiyel olarak **herhangi bir IR uzaktan kumanda kodunu almayı ve iletmeyi** destekler. **Tanınmayan** protokoller durumunda - **alınan gibi doğru bir şekilde kaydeder ve geri oynatır**.

## Eylemler

### Evrensel Kumandalar

Flipper Zero, herhangi bir TV, klima veya medya merkezini kontrol etmek için bir **evrensel kumanda** olarak kullanılabilir. Bu modda, Flipper, SD karttaki sözlükten tüm desteklenen üreticilerin **tüm bilinen kodlarını** **brute force** eder. Bir restoran TV'sini kapatmak için belirli bir kumandayı seçmenize gerek yok.

Evrensel Kumanda modunda güç düğmesine basmak yeterlidir ve Flipper, bildiği tüm TV'lerin "Kapat" komutlarını sırayla gönderecektir: Sony, Samsung, Panasonic... ve benzeri. TV sinyali aldığında tepki verecek ve kapanacaktır.

Bu tür brute-force zaman alır. Sözlük ne kadar büyükse, bitirmesi o kadar uzun sürer. TV'nin hangi sinyali tam olarak tanıdığını öğrenmek imkansızdır çünkü TV'den geri bildirim yoktur.

### Yeni Kumandaları Öğrenme

Flipper Zero ile bir kızılötesi sinyal **yakalanabilir**. Eğer Flipper, sinyali **veritabanında bulursa**, otomatik olarak **bu cihazın hangisi olduğunu bilecek** ve sizinle etkileşime girmenize izin verecektir.\
Bulamazsa, Flipper sinyali **kaydedebilir** ve size **yeniden oynatma** olanağı sağlar.

## Referanslar

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)
