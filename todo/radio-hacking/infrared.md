# Kızılötesi

<details>

<summary><strong>Sıfırdan kahraman olana kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks** ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR gönderin.

</details>

## Kızılötesi Nasıl Çalışır <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Kızılötesi ışık insanlar için görünmezdir**. IR dalga boyu **0.7 ila 1000 mikron** arasındadır. Ev uzaktan kumandaları veri iletimi için bir IR sinyali kullanır ve genellikle 0.75 ila 1.4 mikron dalga boyu aralığında çalışır. Kumandadaki bir mikrodenetleyici, belirli bir frekansta kızılötesi bir LED'i yanıp söndürerek dijital sinyali IR sinyaline dönüştürür.

IR sinyallerini almak için bir **foto alıcı** kullanılır. Bu, IR ışığını voltaj darbelerine dönüştürür, bu darbeler zaten **dijital sinyallerdir**. Genellikle alıcının içinde **yalnızca istenilen dalga boyunu geçiren ve gürültüyü kesen bir karanlık ışık filtresi** bulunur.

### Çeşitli IR Protokolleri <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR protokolleri 3 faktörde farklılık gösterir:

* bit kodlama
* veri yapısı
* taşıyıcı frekans — genellikle 36 ila 38 kHz aralığında

#### Bit kodlama yöntemleri <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Darbe Mesafe Kodlama**

Bitler darbeler arasındaki boşluğun süresini modüle ederek kodlanır. Darbenin genişliği sabittir.

<figure><img src="../../.gitbook/assets/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Darbe Genişliği Kodlama**

Bitler darbe genişliğinin modülasyonu ile kodlanır. Darbe patlamasından sonra boşluk genişliği sabittir.

<figure><img src="../../.gitbook/assets/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Faz Kodlama**

Bu aynı zamanda Manchester kodlaması olarak da bilinir. Mantıksal değer, darbe patlaması ve boşluk arasındaki geçişin polaritesi tarafından belirlenir. "Boşluktan darbe patlamasına" mantık "0" anlamına gelir, "darbe patlamasından boşluğa" mantık "1" anlamına gelir.

<figure><img src="../../.gitbook/assets/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Öncekilerin ve diğer egzotiklerin kombinasyonu**

{% hint style="info" %}
Bazı IR protokolleri vardır ki **çeşitli cihaz türleri için evrensel olmaya çalışır**. En ünlü olanlar RC5 ve NEC'dir. Ne yazık ki, en ünlü olanlar **en yaygın olanlar anlamına gelmez**. Benim çevremde, sadece iki NEC uzaktan kumanda ve hiç RC5 uzaktan kumanda ile karşılaştım.

Üreticiler, hatta aynı cihaz türü içinde (örneğin, TV kutuları) farklı modellerden farklı şirketlerin kendilerine ait benzersiz IR protokollerini kullanmayı severler. Bu nedenle, farklı şirketlerden ve bazen aynı şirketin farklı modellerinden gelen uzaktan kumandalar, aynı türdeki diğer cihazlarla çalışamaz.
{% endhint %}

### Bir IR sinyalini Keşfetme

Uzaktan kumanda IR sinyalinin nasıl göründüğünü görmek için en güvenilir yol bir osiloskop kullanmaktır. Alınan sinyali demodüle etmez veya tersine çevirmez, sadece "olduğu gibi" görüntüler. Bu, test etmek ve hata ayıklamak için faydalıdır. NEC IR protokolü örneğinde beklenen sinyali göstereceğim.

<figure><img src="../../.gitbook/assets/image (235).png" alt=""><figcaption></figcaption></figure>

Genellikle kodlanmış bir paketin başlangıcında bir önyükleme bulunur. Bu, alıcının kazanç seviyesini ve arka planı belirlemesine olanak tanır. Örneğin, Sharp gibi önyükleme olmayan protokoller de vardır.

Ardından veri iletilir. Yapı, önyükleme ve bit kodlama yöntemi belirli protokol tarafından belirlenir.

**NEC IR protokolü**, basit bir komut ve düğmeye basılı tutulduğunda gönderilen bir tekrarlama kodu içerir. Hem komut hem de tekrarlama kodu aynı önyükleme ile başlar.

NEC **komutu**, önyükleme dışında bir adres baytı ve bir komut numarası baytı içerir, cihazın ne yapılması gerektiğini anlamasını sağlar. Adres ve komut numarası baytları, iletimin bütünlüğünü kontrol etmek için ters değerlerle çoğaltılır. Komutun sonunda ek bir durdurma biti bulunur.

**Tekrarlama kodu**, önyüklemeden sonra bir "1" içerir, bu bir durdurma bitidir.

**Mantık "0" ve "1"** için NEC, Darbe Mesafe Kodlama kullanır: önce bir darbe patlaması iletilir, ardından bir durak gelir, bu durak uzunluğu bitin değerini belirler.

### Klima Kumandaları

Diğer uzaktan kumandaların aksine, **klima kumandaları sadece basılan düğmenin kodunu iletmekle kalmaz**. Ayrıca, bir düğmeye basıldığında **tüm bilgileri ileterek klima makinesinin ve uzaktan kumandanın senkronize olduğundan emin olur**.\
Bu, bir makinenin 20ºC olarak ayarlandığı ve bir uzaktan kumanda ile 21ºC'ye yükseltildiğinde, daha sonra hala sıcaklığı 20ºC olan başka bir uzaktan kumanda kullanılarak sıcaklığın artırılmasının "21ºC'ye" artırılmasını sağlar (ve 21ºC'de olduğunu düşünerek 22ºC'ye artırmaz).

### Saldırılar

Kızılötesi'yi Flipper Zero ile saldırabilirsiniz:

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## Referanslar

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)
