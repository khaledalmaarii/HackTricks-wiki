# Kızılötesi

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## Kızılötesi Nasıl Çalışır <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Kızılötesi ışık insanlar tarafından görülemez**. Kızılötesi dalga boyu **0.7 ila 1000 mikron** arasındadır. Ev uzaktan kumandaları, veri iletimi için bir kızılötesi sinyal kullanır ve genellikle 0.75..1.4 mikron dalga boyu aralığında çalışır. Uzaktan kumandadaki bir mikrodenetleyici, belirli bir frekansta kızılötesi bir LED'i yanıp sönerek dijital sinyali kızılötesi bir sinyale dönüştürür.

Kızılötesi sinyalleri almak için bir **fotoreceiver** kullanılır. Bu, kızılötesi ışığı voltaj darbelerine dönüştürür, ki bunlar zaten **dijital sinyallerdir**. Genellikle, alıcının içinde **yalnızca istenen dalga boyunu geçiren ve gürültüyü kesen bir karanlık ışık filtresi** bulunur.

### Çeşitli Kızılötesi Protokoller <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Kızılötesi protokoller 3 faktörde farklılık gösterir:

* bit kodlaması
* veri yapısı
* taşıyıcı frekans - genellikle 36..38 kHz aralığında

#### Bit Kodlama Yöntemleri <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Kodlama**

Bitler, darbeler arasındaki boşluğun süresini modüle ederek kodlanır. Darbenin kendisi sabit genişliğe sahiptir.

<figure><img src="../../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Kodlama**

Bitler, darbe genişliğinin modülasyonuyla kodlanır. Darbe patlamasından sonra boşluk genişliği sabittir.

<figure><img src="../../.gitbook/assets/image (29) (1).png" alt=""><figcaption></figcaption></figure>

**3. Phase Kodlama**

Bu aynı zamanda Manchester kodlaması olarak da bilinir. Mantıksal değer, darbe patlaması ile boşluk arasındaki geçişin polaritesi tarafından belirlenir. "Boşluktan darbe patlamasına" mantık "0" olarak adlandırılır, "darbe patlamasından boşluğa" mantık "1" olarak adlandırılır.

<figure><img src="../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

**4. Öncekilerin ve diğer egzotiklerin kombinasyonu**

{% hint style="info" %}
Bazı kızılötesi protokoller, birden fazla cihaz türü için **evrensel olmaya çalışır**. En ünlü olanları RC5 ve NEC'dir. Ne yazık ki, en ünlü olan **en yaygın olan anlamına gelmez**. Benim çevremde, sadece iki NEC uzaktan kumanda ve hiç RC5 uzaktan kumanda ile karşılaştım.

Üreticiler, hatta aynı cihaz serisinde (örneğin, TV kutuları) farklı şirketlerden ve bazen aynı şirketin farklı modellerinden farklı kızılötesi protokoller kullanmayı severler. Bu nedenle, farklı şirketlerden ve bazen aynı şirketin farklı modellerinden gelen uzaktan kumandalar, aynı türdeki diğer cihazlarla çalışamaz.
{% endhint %}

### Bir Kızılötesi Sinyali Keşfetmek

Uzaktan kumandanın kızılötesi sinyalinin nasıl göründüğünü en güvenilir şekilde görmek için osiloskopa başvurulur. Alınan sinyali demodüle etmez veya tersine çevirmez, sadece "olduğu gibi" görüntüler. Bu, test etmek ve hata ayıklamak için kullanışlıdır. NEC kızılötesi protokolü örneğinde beklenen sinyali göstereceğim.

<figure><img src="../../.gitbook/assets/image (18) (2).png" alt=""><figcaption></figcaption></figure>

Genellikle, kodlanmış bir paketin başında bir önsöz bulunur. Bu, alıcının kazanç ve arka plan seviyesini belirlemesine olanak tanır. Ayrıca, Sharp gibi önsöz olmadan da protokoller vardır.

Ardından veri iletilir. Yapı, önsöz ve bit kodlama yöntemi, belirli protokol tarafından belirlenir.

**NEC kızılötesi protokolü**, basılan düğmeyle birlikte gönderilen kısa bir komut ve tekrar kodu içerir. Komut ve tekrar kodu, başlangıçta aynı önsöze sahiptir.

NEC **komutu**, önsözün yanı sıra, cihazın ne yapılması gerektiğini anlamasını sağlayan bir adres baytı ve bir komut numarası baytından oluşur. Adres ve komut numarası baytları, iletimin bütünlüğünü kontrol etmek için ters değerlerle çoğaltılır. Komutun sonunda ek bir durdurma biti bulunur.

**Tekrar kodu**, önsözden sonra bir "1" içerir, bu da bir durdurma bitidir.

NEC, **mantık "0" ve "1"** için Pulse Distance Kodlama kullanır: önce bir darbe patlaması iletilir, ardından bir duraklama vardır ve bu duraklamanın uzunluğu bitin değerini belirler.

### Klima Cihazları

Diğer uzaktan kumandaların aksine, **klima cihazları sadece basılan düğmenin kodunu iletmekle kalmaz**. Aynı zamanda, bir düğme basıldığında **klima cihazıyla uzaktan kumandanın senkronize olduğunu sağlamak için tüm bilgileri ileterler**.\
Bu, bir makinenin 20ºC olarak ayarlandığı bir uzaktan kumanda ile artırıldığında, hala sıcaklığı 20ºC olan başka bir uzaktan kumanda kullanılarak sıcaklığın daha da artırılmasının 21ºC'ye "artırılmasını" önler (ve 21ºC'de olduğunu düşünerek 22ºC'ye değil).

### Saldırılar
