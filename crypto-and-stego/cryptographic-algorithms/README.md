# Kriptografik/Sıkıştırma Algoritmaları

## Kriptografik/Sıkıştırma Algoritmaları

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek.

</details>

## Algoritmaları Tanımlama

Eğer bir kod **kaydırma işlemleri, XOR'lar ve çeşitli aritmetik işlemler** içeriyorsa, büyük ihtimalle bir **kriptografik algoritmanın** uygulanmasıdır. Burada, **her adımı tersine çevirmeye gerek kalmadan kullanılan algoritmayı tanımlamanın bazı yolları** gösterilecektir.

### API fonksiyonları

**CryptDeriveKey**

Bu fonksiyon kullanılıyorsa, ikinci parametrenin değerini kontrol ederek **hangi algoritmanın kullanıldığını** bulabilirsiniz:

![](<../../.gitbook/assets/image (153).png>)

Mümkün algoritmaların ve atanan değerlerin tablosu için buraya bakabilirsiniz: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Veri akışını sıkıştırır ve açar.

**CryptAcquireContext**

[Belgelerden](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): **CryptAcquireContext** fonksiyonu, belirli bir kriptografik hizmet sağlayıcısı (CSP) içinde belirli bir anahtar konteynerine bir tutamaç almak için kullanılır. **Bu döndürülen tutamaç, seçilen CSP'yi kullanan CryptoAPI** fonksiyonlarına yapılan çağrılarda kullanılır.

**CryptCreateHash**

Veri akışının karma işlemini başlatır. Bu fonksiyon kullanılıyorsa, ikinci parametrenin değerini kontrol ederek **hangi algoritmanın kullanıldığını** bulabilirsiniz:

![](<../../.gitbook/assets/image (546).png>)

\
Mümkün algoritmaların ve atanan değerlerin tablosu için buraya bakabilirsiniz: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Kod sabitleri

Bazen, bir algoritmayı tanımlamak gerçekten kolay olabilir çünkü özel ve benzersiz bir değeri kullanması gerekir.

![](<../../.gitbook/assets/image (830).png>)

Google'da ilk sabit için arama yaparsanız, aşağıdakileri elde edersiniz:

![](<../../.gitbook/assets/image (526).png>)

Bu nedenle, dekompilasyon işlevinin bir **sha256 hesaplayıcısı olduğunu** varsayabilirsiniz.\
Diğer sabitlerden herhangi birini arayabilir ve (muhtemelen) aynı sonucu elde edersiniz.

### Veri bilgisi

Kodda anlamlı bir sabit yoksa, muhtemelen **.data bölümünden bilgi yükleniyor** demektir.\
Bu veriye erişebilir, **ilk dört kelimeyi gruplayabilir** ve yukarıda yaptığımız gibi Google'da arayabilirsiniz:

![](<../../.gitbook/assets/image (528).png>)

Bu durumda, **0xA56363C6** için arama yaparsanız, bunun **AES algoritmasının tablolarıyla ilişkili olduğunu** bulabilirsiniz.

## RC4 **(Simetrik Şifreleme)**

### Özellikler

Üç ana bölümden oluşur:

* **Başlatma aşaması/**: 0x00 ila 0xFF arasındaki değerlerin bir **tablosunu oluşturur** (toplamda 256 bayt, 0x100). Bu tablo genellikle **Yerine Koyma Kutusu** (veya SBox) olarak adlandırılır.
* **Karıştırma aşaması**: Önce oluşturulan tabloyu **döngü ile** (tekrar 0x100 iterasyon, tekrar) her değeri **yarı rastgele** baytlarla değiştirerek oluşturur. Bu yarı rastgele baytları oluşturmak için RC4 **anahtarı kullanılır**. RC4 **anahtarları** genellikle **1 ila 256 bayt arasında** olabilir, ancak genellikle 5 baytın üzerinde olması önerilir. Genellikle, RC4 anahtarları 16 bayt uzunluğundadır.
* **XOR aşaması**: Son olarak, düz metin veya şifre metni, önce oluşturulan değerlerle **XOR edilir**. Şifrelemek ve şifre çözmek için aynı işlev kullanılır. Bunun için, oluşturulan 256 bayt üzerinde bir döngü **gerekli olduğu kadar** yapılır. Bu genellikle bir dekompilasyon kodunda **%256 (mod 256)** ile tanınır.

{% hint style="info" %}
**RC4'ü bir dekompilasyon/derlenmiş kodda tanımlamak için 0x100 boyutunda 2 döngüye (bir anahtar kullanarak) ve ardından giriş verilerinin 2 döngüde oluşturulan 256 değerle muhtemelen %256 (mod 256) kullanılarak XOR edildiğini kontrol edebilirsiniz.**
{% endhint %}

### **Başlatma aşaması/Yerine Koyma Kutusu:** (256 sayısı kullanılan sayacı ve 256 karakterin her yerine 0 yazıldığına dikkat edin)

![](<../../.gitbook/assets/image (581).png>)

### **Karıştırma Aşaması:**

![](<../../.gitbook/assets/image (832).png>)

### **XOR Aşaması:**

![](<../../.gitbook/assets/image (901).png>)

## **AES (Simetrik Şifreleme)**

### **Özellikler**

* **Yerine koyma kutuları ve arama tabloları** kullanımı
* **Belirli arama tablosu değerlerinin** (sabitlerin) kullanımı sayesinde AES'i **ayırt etmek mümkündür**. _**Sabit**in_ _**binary'de saklanabileceğine veya dinamik olarak oluşturulabileceğine**_ _**dikkat edin**._
* **Şifreleme anahtarı**, **16'ya bölünebilmelidir** (genellikle 32B) ve genellikle 16B'lik bir **IV** kullanılır.

### SBox sabitleri

![](<../../.gitbook/assets/image (205).png>)

## Yılan **(Simetrik Şifreleme)**

### Özellikler

* Kullanan bazı kötü amaçlı yazılımların nadir olduğu ancak örneklerin bulunduğu (Ursnif gibi)
* Bir algoritmanın Serpent olup olmadığını belirlemek oldukça basittir, uzun bir işlev olmasına dayanarak (son derece uzun işlev)

### Tanımlama

Aşağıdaki resimde **0x9E3779B9** sabitinin kullanıldığına dikkat edin (bu sabitin **TEA** -Tiny Encryption Algorithm gibi diğer kripto algoritmalarında da kullanıldığını unutmayın).\
Ayrıca **döngünün boyutunu** (**132**) ve **XOR işlemlerinin sayısını** **derleme** talimatlarında ve **örnek kodda** fark edin:

![](<../../.gitbook/assets/image (544).png>)

Daha önce belirtildiği gibi, bu kod, içinde **atlamalar olmadığı için** herhangi bir dekompilatörde **çok uzun bir işlev** olarak görülebilir. Dekompilasyon kodu aşağıdaki gibi görünebilir:

![](<../../.gitbook/assets/image (510).png>)

Bu nedenle, bu algoritmayı tanımlamak için **sihirli sayıyı** ve **başlangıç XOR'larını** kontrol ederek, **çok uzun bir işlevi** görerek ve **uzun işlevin bazı talimatlarını** (örneğin, 7 ile sola kaydırma ve 22 ile sola döndürme) **bir uygulama ile karşılaştırarak** mümkündür.
## RSA **(Asimetrik Şifreleme)**

### Özellikler

* Simetrik algoritmalardan daha karmaşıktır
* Sabitler yoktur! (özel uygulamaları belirlemek zordur)
* KANAL (bir şifre analizörü) RSA hakkında ipuçları veremez çünkü sabitlere dayanır.

### Karşılaştırmalarla Tanımlama

![](<../../.gitbook/assets/image (1110).png>)

* Sol tarafta 11. satırda `+7) >> 3` sağ tarafta 35. satırda aynıdır: `+7) / 8`
* Sol tarafta 12. satırda `modulus_len < 0x040` kontrol edilirken sağ tarafta 36. satırda `inputLen+11 > modulusLen` kontrol edilmektedir.

## MD5 & SHA (hash)

### Özellikler

* 3 fonksiyon: Init, Update, Final
* Benzer başlatma fonksiyonları

### Tanımlama

**Init**

Her ikisini de sabitlere bakarak tanımlayabilirsiniz. SHA\_init'in MD5'te olmayan 1 sabiti olduğunu unutmayın:

![](<../../.gitbook/assets/image (403).png>)

**MD5 Dönüşümü**

Daha fazla sabit kullanımına dikkat edin

![](<../../.gitbook/assets/image (253) (1) (1).png>)

## CRC (hash)

* Verideki kazara değişiklikleri bulma işlevi nedeniyle daha küçük ve daha verimlidir
* Sabitleri tanımlamak için arama tabloları kullanır

### Tanımlama

**Arama tablosu sabitlerini** kontrol edin:

![](<../../.gitbook/assets/image (505).png>)

Bir CRC hash algoritması şuna benzer:

![](<../../.gitbook/assets/image (387).png>)

## APLib (Sıkıştırma)

### Özellikler

* Tanınabilir sabitler yoktur
* Algoritmayı python'da yazmayı deneyebilir ve benzer şeyleri çevrimiçi arayabilirsiniz

### Tanımlama

Grafik oldukça büyüktür:

![](<../../.gitbook/assets/image (207) (2) (1).png>)

Tanımak için **3 karşılaştırmayı kontrol edin**:

![](<../../.gitbook/assets/image (427).png>)
