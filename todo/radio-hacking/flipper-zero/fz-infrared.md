# FZ - Kızılötesi

<details>

<summary><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* Özel [**NFT'lerimizden oluşan PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter'da** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **ile göndererek paylaşın**.

</details>

## Giriş <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Kızılötesi'nin nasıl çalıştığı hakkında daha fazla bilgi için:

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## Flipper Zero'da Kızılötesi Sinyal Alıcısı <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper, IR uzaktan kumandaların sinyallerini **intercept etmeyi** sağlayan bir dijital IR sinyal alıcısı TSOP kullanır. Xiaomi gibi bazı **akıllı telefonlar** da bir IR bağlantı noktasına sahip olabilir, ancak **çoğu sadece sinyal gönderebilir** ve **alıcı olamaz**.

Flipper'ın kızılötesi alıcısı oldukça **duyarlıdır**. TV'nin uzaktan kumandası ve Flipper arasında **bir yerde dururken bile sinyali yakalayabilirsiniz**. Uzaktan kumandayı doğrudan Flipper'ın IR bağlantı noktasına yönlendirmek gereksizdir. Bu, biri TV'nin yanında kanalları değiştirirken, hem siz hem de Flipper biraz uzakta olduğunuzda işe yarar.

Kızılötesi sinyalin çözümlenmesi **yazılım** tarafında gerçekleştiği için, Flipper Zero potansiyel olarak herhangi bir IR uzaktan kumanda kodunu **alabilme ve iletebilme** özelliğine sahiptir. **Tanınmayan** protokollerin tanınamadığı durumlarda, alınan sinyal **kaydedilir ve tam olarak o şekilde tekrar oynatılır**.

## İşlemler

### Evrensel Uzaktan Kumandalar

Flipper Zero, herhangi bir TV, klima veya medya merkezini kontrol etmek için bir **evrensel uzaktan kumanda** olarak kullanılabilir. Bu modda, Flipper, SD karttaki sözlüğe göre **tüm desteklenen üreticilerin bilinen kodlarını** **brute-force** yapar. Bir restoran TV'sini kapatmak için belirli bir uzaktan kumandayı seçmenize gerek yoktur.

Evrensel Uzaktan Kumanda modunda güç düğmesine basmak yeterlidir ve Flipper, bildiği tüm TV'lerin "Kapat" komutlarını sırayla gönderir: Sony, Samsung, Panasonic... ve böyle devam eder. TV sinyali alır almaz tepki verecek ve kapanacaktır.

Bu tür brute-force işlemi zaman alır. Sözlük ne kadar büyükse, bitirmek için o kadar uzun sürecek. TV'nin hangi sinyali tam olarak tanıdığını öğrenmek imkansızdır çünkü TV'den geri bildirim yoktur.

### Yeni Uzaktan Kumanda Öğrenme

Flipper Zero ile bir kızılötesi sinyal **yakalanabilir**. Eğer Flipper, sinyali **veritabanında bulursa**, Flipper otomatik olarak **bu cihazın ne olduğunu bilecek** ve sizinle etkileşim kurmanıza izin verecektir.\
Bulamazsa, Flipper sinyali **kaydedebilir** ve size **tekrar oynatma** imkanı sağlar.

## Referanslar

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

<details>

<summary><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* Özel [**NFT'lerimizden oluşan PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter'da** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **ve** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **ile göndererek paylaşın**.

</details>
