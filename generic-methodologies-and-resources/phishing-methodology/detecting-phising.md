# Phishing Tespit Etme

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklam vermek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **pull request göndererek** paylaşın.

</details>

## Giriş

Bir phishing girişimini tespit etmek için günümüzde kullanılan phishing tekniklerini anlamak önemlidir. Bu yazının ana sayfasında bu bilgileri bulabilirsiniz, bu yüzden günümüzde hangi tekniklerin kullanıldığını bilmiyorsanız, ana sayfaya gidip en azından o bölümü okumanızı öneririm.

Bu yazı, **saldırganların kurbanın alan adını taklit etmeye veya kullanmaya çalışacaklarını** varsayan bir fikre dayanmaktadır. Örneğin, alan adınız `ornek.com` ise ve `kazandınız.com` gibi tamamen farklı bir alan adı kullanarak phishing saldırısına uğrarsanız, bu teknikler bunu ortaya çıkarmayacaktır.

## Alan adı varyasyonları

E-posta içinde benzer bir alan adı kullanan phishing girişimlerini ortaya çıkarmak oldukça **kolaydır**. Bir saldırganın kullanabileceği en olası phishing isimlerinin bir listesini oluşturmak ve bunun kayıtlı olup olmadığını veya kullanılan herhangi bir **IP** olup olmadığını **kontrol etmek** yeterlidir.

### Şüpheli alan adlarını bulma

Bu amaçla, aşağıdaki araçlardan herhangi birini kullanabilirsiniz. Bu araçlar, alan adının herhangi bir IP'ye atanıp atanılmadığını kontrol etmek için otomatik olarak DNS istekleri de gerçekleştirecektir:

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### Bitflipping

Bu teknik hakkında kısa bir açıklamayı ana sayfada bulabilirsiniz. Veya orijinal araştırmayı [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/) adresinde okuyabilirsiniz.

Örneğin, microsoft.com alan adında 1 bitlik bir değişiklik yaparak _windnws.com._ haline getirebilirsiniz. **Saldırganlar, kurbanla ilgili mümkün olduğunca çok sayıda bit-flipping alan adı kaydedebilir ve meşru kullanıcıları altyapılarına yönlendirebilirler**.

**Tüm olası bit-flipping alan adları da izlenmelidir.**

### Temel kontroller

Potansiyel şüpheli alan adlarının bir listesine sahip olduktan sonra, bunları (özellikle HTTP ve HTTPS bağlantı noktalarını) **kontrol etmelisiniz** ve kurbanın alan adına benzer bir giriş formu kullanıp kullanmadığını görmek için.\
Ayrıca, 3333 numaralı bağlantı noktasının açık olup olmadığını ve `gophish` örneğini çalıştırıp çalıştırmadığını kontrol etmek de ilginç olabilir.\
Ayrıca, keşfedilen her şüpheli alan adının **ne kadar eski olduğunu bilmek de önemlidir**, ne kadar yeni ise o kadar risklidir.\
HTTP ve/veya HTTPS şüpheli web sayfasının ekran görüntülerini alarak şüpheli olup olmadığını görebilir ve bu durumda daha ayrıntılı bir inceleme yapmak için sayfaya erişebilirsiniz.

### Gelişmiş kontroller

Daha ileri gitmek isterseniz, ara sıra (her gün mü? sadece birkaç saniye/dakika sürer) **bu şüpheli alan adlarına göz kulak olmanızı ve daha fazlasını aramanızı öneririm**. Ayrıca, ilgili IP'lerin açık **bağlantı noktalarını kontrol edin** ve **`gophish` veya benzer araçların örneklerini arayın** (evet, saldırganlar da hatalar yapar) ve şüpheli alan adlarının ve alt alan adlarının HTTP ve HTTPS web sayfalarını izleyin, kurbanın web sayfalarından herhangi bir giriş formu kopyalayıp kopyalamadıklarını görmek için.\
Bunu **otomatikleştirmek** için, kurbanın alan adlarının giriş formlarının bir listesine sahip olmanızı, şüpheli web sayfalarını tarayarak her şüpheli alan adının içinde bulunan her giriş formunu kurbanın alan adının her giriş formuyla `ssdeep` gibi bir şeyle karşılaştırmanızı öneririm.\
Şüpheli alan adlarının giriş formlarını bulduysanız, **gereksiz kimlik bilgileri göndermeyi deneyebilir** ve **sizi kurbanın alan adına yönlendirip yönlendirmediğini kontrol edebilirsiniz**.

## Anahtar kelimeleri kullanan alan adları

Ana sayfa ayrıca, kurbanın alan adını daha büyük bir alan adının içine koyma gibi bir alan adı varyasyon tekniğinden bahseder (örneğin paypal.com için paypal-financial.com).

### Sertifika Şeffaflığı

Önceki "Brute-Force" yaklaşımını kullanmak mümkün olmasa da, sertifika şeffaflığı sayesinde bu tür phishing girişimlerini ortaya çıkarmak da mümkündür. Bir CA tarafından bir sertifika yayımlandığında, ayrıntılar halka açık hale gelir. Bu, sertifika şeffaflığını okuyarak veya hatta izleyerek, bir alan adının adı içinde bir anahtar kelime kullanan alan adlarını bulmanın **mümkün olduğu anlamına gelir**. Örneğin, bir saldırgan [https://paypal-financial.com](https://paypal-financial.com) için bir sertifika oluşturursa, sertifikayı görerek "paypal" anahtar kelimesini bulmak ve şüpheli bir e-posta kullanıldığını bilmek mümkündür.

[https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) adresindeki yazı, belirli bir anahtar kelimeyi etkileyen sertifikaları aramak ve tarih (yalnızca "yeni" sertifikalar) ve CA yayıncısı "Let's Encrypt" tarafından filtrelemek için Censys'i kullanabileceğinizi önermektedir:

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../.gitbook/assets/image (390).png>)

Ancak, aynı şeyi ücretsiz web [**crt.sh**](https://crt.sh) kullanarak da yapabilirsiniz. **Anahtar kelimeyi arayabilir** ve sonuçları **tarih ve CA** ile **filtreleyebilirsiniz** isterseniz.

![](<../../.gitbook/assets/image (391).png>)

Bu son seçenek kullanılarak, gerçek alan adının herhangi bir kimliğinin şüpheli alan adlarından herhangi biriyle eşleşip eşleşmediğini görmek için Eşleşen Kimlikler alanını kullanabilirsiniz (bir şüpheli alan adı yanlış pozitif olabilir).

**Başka bir alternatif** ise
### **Yeni alan adları**

**Son bir alternatif**, bazı TLD'ler için bir **yeni kaydedilen alan adları listesi toplamak** ve bu alan adlarında **anahtar kelimeleri kontrol etmek**. Bununla birlikte, uzun alan adları genellikle bir veya daha fazla alt alan adı kullanır, bu nedenle anahtar kelime FLD içinde görünmeyecektir ve dolayısıyla phishing alt alan adını bulamayacaksınız.

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'da takip edin**.
* **Hacking hilelerinizi HackTricks ve HackTricks Cloud** github depolarına **PR göndererek paylaşın**.

</details>
