# Phishing Tespit Etme

<details>

<summary><strong>Sıfırdan kahraman olmaya kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

- **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
- [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
- [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
- **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
- **Hacking püf noktalarınızı paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek.

</details>

## Giriş

Bir phishing girişimini tespit etmek için **bugün kullanılan phishing tekniklerini anlamak önemlidir**. Bu gönderinin ana sayfasında, bu bilgileri bulabilirsiniz, bu yüzden bugün hangi tekniklerin kullanıldığını bilmiyorsanız, ana sayfaya gidip en azından o bölümü okumanızı öneririm.

Bu gönderi, **saldırganların kurbanın alan adını bir şekilde taklit etmeye veya kullanmaya çalışacaklarını varsayar**. Alan adınız `ornek.com` ise ve bir nedenle `kazandınız.com` gibi tamamen farklı bir alan adı kullanılarak dolandırılıyorsanız, bu teknikler bunu ortaya çıkarmayacaktır.

## Alan adı varyasyonları

E-posta içinde **benzer bir alan adı** kullanan **phishing** girişimlerini **ortaya çıkarmak** oldukça **kolaydır**.\
Bir saldırganın kullanabileceği en olası phishing adlarının bir listesini **oluşturmak** ve bunun **kayıtlı olup olmadığını kontrol etmek** yeterlidir.

### Şüpheli alan adlarını bulma

Bu amaçla, aşağıdaki araçlardan herhangi birini kullanabilirsiniz. Bu araçlar, alan adının herhangi bir IP'sinin atanıp atanmadığını kontrol etmek için DNS isteklerini otomatik olarak gerçekleştirecektir:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### Bitflipping

**Bu teknik hakkında kısa bir açıklamayı ana sayfada bulabilirsiniz. Veya orijinal araştırmayı** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/) **adresinde okuyabilirsiniz.**

Örneğin, microsoft.com alanındaki 1 bitlik bir değişiklik onu _windnws.com._ haline getirebilir.\
**Saldırganlar, kurbanı yönlendirmek için mümkün olduğunca çok bit-flipping alanı kaydedebilirler**.

**Tüm olası bit-flipping alan adları da izlenmelidir.**

### Temel kontroller

Potansiyel şüpheli alan adlarının bir listesine sahip olduktan sonra, bunları (genellikle HTTP ve HTTPS bağlantı noktalarını) **kontrol etmelisiniz** ve **kurbanın alan adından birine benzer bir giriş formu kullanıp kullanmadıklarını görmek için**.\
Ayrıca, açık olan 3333 numaralı bağlantı noktasını kontrol ederek `gophish` örneğini çalıştırıp çalıştırmadığını görebilirsiniz.\
Ayrıca, keşfedilen her şüpheli alan adının ne kadar eski olduğunu bilmek de ilginçtir, ne kadar gençse riski o kadar yüksektir.\
HTTP ve/veya HTTPS şüpheli web sayfasının ekran görüntülerini alarak, şüpheli olduğunu görmek için ve bu durumda daha derinlemesine incelemek için **erişebilirsiniz**.

### Gelişmiş kontroller

Daha ileri gitmek istiyorsanız, ara sıra (her gün mü? sadece birkaç saniye/dakika sürer) **bu şüpheli alanları izlemenizi ve daha fazlasını aramanızı** öneririm. Ayrıca, ilgili IP'lerin açık **bağlantı noktalarını kontrol edin** ve **gophish veya benzeri araçların örneklerini arayın** (evet, saldırganlar da hatalar yapar) ve **şüpheli alanların ve alt alanların HTTP ve HTTPS web sayfalarını izleyin** ve kurbanın web sayfalarından herhangi bir giriş formunu kopyalayıp kopyalamadıklarını görmek için.\
Bunu **otomatikleştirmek** için, kurbanın alanlarının bir giriş formu listesine sahip olmanızı, şüpheli web sayfaları örümcek ağı ile taramanızı ve her şüpheli alan içinde bulunan her giriş formunu, kurbanın alanının her giriş formuyla `ssdeep` gibi bir şey kullanarak karşılaştırmanızı öneririm.\
Şüpheli alanların giriş formlarını bulduysanız, **gereksiz kimlik bilgileri göndermeyi deneyebilir ve sizi kurbanın alanına yönlendirip yönlendirmediğini kontrol edebilirsiniz**.

## Anahtar kelimeler kullanan alan adları

Ana sayfa ayrıca, **kurbanın alan adını daha büyük bir alan adının içine koyma** tekniğini içeren bir alan adı varyasyon tekniğinden bahseder.

### Sertifika Şeffaflığı

Önceki "Kaba Kuvvet" yaklaşımını almak mümkün olmasa da, aslında **sertifika şeffaflığı sayesinde bu tür phishing girişimlerini ortaya çıkarmak mümkündür**. Bir CA tarafından bir sertifika verildiğinde, detaylar kamuoyuna açıklanır. Bu, sertifika şeffaflığını okuyarak veya hatta izleyerek, **adında bir anahtar kelime kullanan alan adlarını bulmak mümkündür**. Örneğin, bir saldırgan [https://paypal-financial.com](https://paypal-financial.com) adresine bir sertifika oluşturursa, sertifikayı okuyarak "paypal" anahtar kelimesini bulmak ve şüpheli e-postanın kullanıldığını bilmek mümkündür.

[https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) gönderisi, belirli bir anahtar kelimeyi etkileyen sertifikaları aramak için Censys'i kullanabileceğinizi ve tarihe göre (yalnızca "yeni" sertifikalar) ve CA yayıncısına göre filtreleyebileceğinizi önermektedir:

![https://0xpatrik.com/content/images/2018/07/cert\_listing.png](<../../.gitbook/assets/image (1115).png>)

Ancak, aynısını ücretsiz web [**crt.sh**](https://crt.sh) kullanarak yapabilirsiniz. **Anahtar kelimeyi arayabilir** ve sonuçları **tarihe ve CA'ya göre filtreleyebilirsiniz** isterseniz.

![](<../../.gitbook/assets/image (519).png>)

Bu son seçeneği kullanarak, gerçek alanın herhangi bir kimliğinin şüpheli alanlardan herhangi biriyle eşleşip eşleşmediğini görmek için Eşleşen Kimlikler alanını kullanabilirsiniz (unutmayın ki şüpheli bir alan yanlış pozitif olabilir).

**Başka bir alternatif** harika bir proje olan [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) adlı projedir. CertStream, (yaklaşık) gerçek zamanlı olarak belirli anahtar kelimeleri tespit etmek için kullanabileceğiniz yeni oluşturulan sertifikaların gerçek zamanlı akışını sağlar. Aslında, bunu yapan [**phishing\_catcher**](https://github.com/x0rz/phishing\_catcher) adlı bir proje bulunmaktadır.
### **Yeni alan adları**

**Bir diğer alternatif**, bazı TLD'ler için **yeni kayıt edilen alan adları** listesi toplamak ([Whoxy](https://www.whoxy.com/newly-registered-domains/) böyle bir hizmet sunar) ve bu alan adlarındaki anahtar kelimeleri **kontrol etmektir**. Ancak, uzun alan adları genellikle bir veya daha fazla alt alan adı kullanır, bu nedenle anahtar kelime FLD içinde görünmeyecektir ve dolayısıyla phishing alt alanını bulamayacaksınız.
