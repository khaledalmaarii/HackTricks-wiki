# Kriptografik/Sıkıştırma Algoritmaları

## Kriptografik/Sıkıştırma Algoritmaları

<details>

<summary><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong> ile sıfırdan kahramana kadar AWS hacklemeyi öğrenin<strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonuna göz atın
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* Hacking hilelerinizi [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek** paylaşın.

</details>

## Algoritmaları Tanımlama

Eğer bir kodda **shift right ve left, xor ve çeşitli aritmetik işlemler** kullanılıyorsa, büyük olasılıkla bir **kriptografik algoritmanın** uygulamasıdır. Burada, her adımı tersine çevirmeden kullanılan algoritmayı **tanımlamanın yolları** gösterilecektir.

### API fonksiyonları

**CryptDeriveKey**

Bu fonksiyon kullanılıyorsa, ikinci parametrenin değerini kontrol ederek **hangi algoritmanın kullanıldığını** bulabilirsiniz:

![](<../../.gitbook/assets/image (375) (1) (1) (1) (1).png>)

Mümkün olan algoritmaların tablosunu ve atanan değerlerini buradan kontrol edin: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Verilen bir veri tamponunu sıkıştırır ve açar.

**CryptAcquireContext**

[Belgelerden](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta) alıntı: **CryptAcquireContext** fonksiyonu, belirli bir kriptografik hizmet sağlayıcısı (CSP) içinde belirli bir anahtar konteynerine bir tanıtıcı edinmek için kullanılır. **Bu döndürülen tanıtıcı, seçilen CSP'yi kullanan CryptoAPI** fonksiyonlarına yapılan çağrılarda kullanılır.

**CryptCreateHash**

Bir veri akışının karma işlemini başlatır. Bu fonksiyon kullanılıyorsa, ikinci parametrenin değerini kontrol ederek **hangi algoritmanın kullanıldığını** bulabilirsiniz:

![](<../../.gitbook/assets/image (376).png>)

Mümkün olan algoritmaların tablosunu ve atanan değerlerini buradan kontrol edin: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Kod sabitleri

Bazı durumlarda, bir algoritmayı tanımak gerçekten kolay olabilir çünkü özel ve benzersiz bir değer kullanması gerekmektedir.

![](<../../.gitbook/assets/image (370).png>)

İlk sabit için Google'da arama yaptığınızda aşağıdaki sonucu elde edersiniz:

![](<../../.gitbook/assets/image (371).png>)

Bu nedenle, dekompilasyon işlevinin bir **sha256 hesaplayıcısı** olduğunu varsayabilirsiniz. Diğer sabitlerden herhangi birini araştırırsanız (muhtemelen) aynı sonucu elde edersiniz.

### veri bilgisi

Eğer kodda anlamlı bir sabit yoksa, muhtemelen bilgileri **.data bölümünden yüklüyor** demektir. Bu verilere erişebilir, **ilk dört kelimeyi gruplayabilir** ve yukarıdaki bölümde yaptığımız gibi Google'da arayabilirsiniz:

![](<../../.gitbook/assets/image (372).png>)

Bu durumda, **0xA56363C6** için arama yaptığınızda, bu, **AES algoritmasının tablolarıyla ilgili olduğunu** bulabilirsiniz.

## RC4 **(Simetrik Şifreleme)**

### Özellikler

3 ana bölümden oluşur:

* **Başlatma aşaması/**: 0x00 ila 0xFF (toplamda 256 bayt, 0x100) arasındaki değerlerden bir **tablo oluşturur**. Bu tablo genellikle **Yerine Geçme Kutusu** (veya SBox) olarak adlandırılır.
* **Karıştırma aşaması**: Önceden oluşturulan tabloyu (tekrar 0x100 döngüsüyle) dolaşacak ve her değeri **yarı rastgele** baytlarla değiştirecektir. Bu yarı rastgele baytları oluşturmak için RC4 **anahtarını kullanır**. RC4 anahtarları genellikle 1 ila 256 bayt uzunluğunda olabilir, ancak genellikle 5 bayttan daha uzun olması önerilir. Genellikle, RC4 anahtarları 16 bayt uzunluğundadır.
* **XOR aşaması**: Son olarak, düz metin veya şifreli metin, önceden oluşturulan değerlerle **XORlanır**. Şifreleme ve şifre çözme işlevi aynıdır. Bunun için, oluşturulan 256 bayt üzerindeki döngü, gerektiği kadar çok kez gerçekleştirilir. Bu genellikle bir dekompilasyon kodunda **%256 (mod 256)** ile tanınır.

{% hint style="info" %}
**Bir değişim/dekompilasyon kodunda RC4'ü tanımlamak için, bir anahtarın kullanıldığı 2 adet 0x100 boyutunda döngüyü ve ardından giriş verilerinin 2 döngüde önceden oluşturulan 256 değerle XOR işlemini kontrol edebilirsiniz (muhtemelen %256 (mod 256) kullanılarak).**
{% endhint %}

### **Başlatma aşaması/Yerine Geçme Kutusu:** (256 kullanılan sayıya ve 256 karakterin her bir yerine 0'ın yazıldığına dikkat edin)

![](<../../.gitbook/assets/image (377).png>)

### **Karıştırma Aşaması:**

![](<../../.gitbook/assets/image (378).png>)

### **XOR Aşaması:**

![](<../../.gitbook/assets/image (379).png>)

## **AES (Simetrik Şifreleme)**

### **Özellikler**

* **Yerine Geçme Kutuları ve arama tabloları** kullanımı
* **Belirli arama tablosu değerlerinin** (sabitlerin) kullanımı sayesinde AES'yi ayırt etmek mümkündür. _Not olarak, **sabit** ikili **olarak depolanabilir** veya _**dinamik olarak**_ _**oluşturulabilir**._
* **Şifreleme anahtarı**, 16'ya **bölünebilir** olmalıdır (genellikle 32B) ve genellikle 16B'lik bir **IV** kullanılır.

### SBox sabitleri

![](<../../.gitbook/assets/image (380).png>)

## Serpent **(Simetrik Şifrele
## RSA **(Asimetrik Şifreleme)**

### Özellikler

* Simetrik algoritmalardan daha karmaşıktır.
* Sabitler yoktur! (özel uygulamaları belirlemek zordur)
* RSA'ya dair ipuçları göstermekte başarısız olan KANAL (bir kripto analizörü) sabitlere dayanır.

### Karşılaştırmalarla Tanımlama

![](<../../.gitbook/assets/image (383).png>)

* Sol tarafta 11. satırda `+7) >> 3` sağ tarafta 35. satırda `+7) / 8` ile aynıdır.
* Sol tarafta 12. satır `modulus_len < 0x040` kontrol ederken sağ tarafta 36. satır `inputLen+11 > modulusLen` kontrol eder.

## MD5 & SHA (hash)

### Özellikler

* Init, Update, Final olmak üzere 3 fonksiyon vardır.
* Benzer başlatma fonksiyonları vardır.

### Tanımlama

**Init**

Her ikisini de sabitlere bakarak tanımlayabilirsiniz. MD5'in sahip olmadığı bir sabit olan sha\_init'e dikkat edin:

![](<../../.gitbook/assets/image (385).png>)

**MD5 Dönüşümü**

Daha fazla sabit kullanımına dikkat edin:

![](<../../.gitbook/assets/image (253) (1) (1) (1).png>)

## CRC (hash)

* Verilerdeki kazara değişiklikleri bulmak için işlevi olduğu için daha küçük ve daha verimlidir.
* Sabitleri tanımlamak için arama tabloları kullanır.

### Tanımlama

**Arama tablosu sabitlerini kontrol edin**:

![](<../../.gitbook/assets/image (387).png>)

Bir CRC karma algoritması şuna benzer:

![](<../../.gitbook/assets/image (386).png>)

## APLib (Sıkıştırma)

### Özellikler

* Tanınabilir sabitler yoktur.
* Algoritmayı Python'da yazmayı deneyebilir ve benzer şeyleri çevrimiçi arayabilirsiniz.

### Tanımlama

Grafik oldukça büyüktür:

![](<../../.gitbook/assets/image (207) (2) (1).png>)

**Tanımak için 3 karşılaştırma kontrol edin**:

![](<../../.gitbook/assets/image (384).png>)

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklam vermek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi Twitter'da takip edin 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live).
* Hacking hilelerinizi [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek paylaşın.

</details>
