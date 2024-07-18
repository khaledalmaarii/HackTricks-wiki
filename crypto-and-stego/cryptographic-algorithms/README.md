# Kriptografik/Sıkıştırma Algoritmaları

## Kriptografik/Sıkıştırma Algoritmaları

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR gönderin.

</details>
{% endhint %}

## Algoritmaları Tanımlama

Eğer bir kod **kaydırma işlemleri, XOR'lar ve çeşitli aritmetik işlemler** içeriyorsa, büyük ihtimalle bir **kriptografik algoritmanın** uygulanmasıdır. Burada, **her adımı tersine çevirmeye gerek kalmadan kullanılan algoritmayı tanımlamanın bazı yolları** gösterilecektir.

### API fonksiyonları

**CryptDeriveKey**

Bu fonksiyon kullanılıyorsa, ikinci parametrenin değerini kontrol ederek hangi **algoritmanın kullanıldığını** bulabilirsiniz:

![](<../../.gitbook/assets/image (156).png>)

Mümkün algoritmalar ve atanan değerlerin tablosu için buraya bakabilirsiniz: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Veri akışını sıkıştırır ve açar.

**CryptAcquireContext**

[Belgelerden](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): **CryptAcquireContext** fonksiyonu, belirli bir kriptografik hizmet sağlayıcısı (CSP) içinde belirli bir anahtar konteynerine bir tutamaç almak için kullanılır. **Bu döndürülen tutamaç, seçilen CSP'yi kullanan CryptoAPI** fonksiyonlarına yapılan çağrılarda kullanılır.

**CryptCreateHash**

Veri akışının karma işlemini başlatır. Bu fonksiyon kullanılıyorsa, ikinci parametrenin değerini kontrol ederek hangi **algoritmanın kullanıldığını** bulabilirsiniz:

![](<../../.gitbook/assets/image (549).png>)

\
Mümkün algoritmalar ve atanan değerlerin tablosu için buraya bakabilirsiniz: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Kod sabitleri

Bazen bir algoritmayı tanımlamak gerçekten kolay olabilir çünkü özel ve benzersiz bir değeri kullanması gerekir.

![](<../../.gitbook/assets/image (833).png>)

Eğer ilk sabit için Google'da arama yaparsanız, aşağıdakini elde edersiniz:

![](<../../.gitbook/assets/image (529).png>)

Bu nedenle, dekompilasyon edilmiş fonksiyonun bir **sha256 hesaplayıcısı** olduğunu varsayabilirsiniz. Diğer sabitlerden herhangi birini arayabilir ve (muhtemelen) aynı sonucu elde edersiniz.

### Veri bilgisi

Eğer kodda önemli bir sabit yoksa, muhtemelen **.data bölümünden bilgi yükleniyor** demektir.\
Bu verilere erişebilir, **ilk dört kelimeyi gruplayabilir** ve yukarıda yaptığımız gibi Google'da arayabilirsiniz:

![](<../../.gitbook/assets/image (531).png>)

Bu durumda, **0xA56363C6** için arama yaparsanız, bunun **AES algoritmasının tablolarıyla** ilişkili olduğunu bulabilirsiniz.

## RC4 **(Simetrik Şifreleme)**

### Özellikler

* **Başlatma aşaması/**: 0x00 ile 0xFF (toplamda 256 bayt, 0x100) arasında bir **değer tablosu oluşturur**. Bu tablo genellikle **Yerine Koyma Kutusu** (veya SBox) olarak adlandırılır.
* **Karıştırma aşaması**: Önceki oluşturulan tablo üzerinde dönecek (tekrar 0x100 iterasyon döngüsü) ve her bir değeri **yarı rastgele** baytlarla değiştirerek **değiştirecek**. Bu yarı rastgele baytları oluşturmak için RC4 **anahtarı kullanılır**. RC4 **anahtarları** genellikle **1 ile 256 bayt arasında** olabilir, ancak genellikle 5 bayttan fazla olması önerilir. Genellikle, RC4 anahtarları 16 bayt uzunluğundadır.
* **XOR aşaması**: Son olarak, düz metin veya şifreli metin, önceki oluşturulan değerlerle **XOR edilir**. Şifrelemek ve deşifre etmek için aynı işlev kullanılır. Bunun için, oluşturulan 256 bayt üzerinde bir döngü **gerektiği kadar** yapılacaktır. Bu genellikle bir dekompilasyon kodunda **%256 (mod 256)** ile tanınır.

{% hint style="info" %}
**RC4'ü bir dekompilasyon/dekompilasyon kodunda tanımlamak için 0x100 boyutunda 2 döngüye (bir anahtar kullanarak) ve ardından giriş verilerinin 2 döngüde önceden oluşturulan 256 değerle XOR'lanmasıyla muhtemelen %256 (mod 256) kullanılarak kontrol edebilirsiniz.**
{% endhint %}

### **Başlatma aşaması/Yerine Koyma Kutusu:** (256 sayısı kullanılan sayacı ve 256 karakterin her bir yerine 0 yazıldığına dikkat edin)

![](<../../.gitbook/assets/image (584).png>)

### **Karıştırma Aşaması:**

![](<../../.gitbook/assets/image (835).png>)

### **XOR Aşaması:**

![](<../../.gitbook/assets/image (904).png>)

## **AES (Simetrik Şifreleme)**

### **Özellikler**

* **Yerine koyma kutuları ve arama tabloları** kullanımı
* **Belirli arama tablosu değerlerinin** (sabitlerin) kullanımı sayesinde AES'i **ayırt etmek mümkündür**. _**Sabit**'in ikili dosyada **saklanabileceğini veya dinamik olarak oluşturulabileceğini**_ _**unutmayın**._
* **Şifreleme anahtarı** 16'ya **bölünebilir** olmalıdır (genellikle 32B) ve genellikle 16B'lik bir **IV** kullanılır.

### SBox sabitleri

![](<../../.gitbook/assets/image (208).png>)

## Yılan **(Simetrik Şifreleme)**

### Özellikler

* Kullanan bazı kötü amaçlı yazılımların nadir olduğu ancak örneklerin bulunduğu (Ursnif gibi)
* Bir algoritmanın Serpent olup olmadığını belirlemek oldukça basittir, uzunluğuna (son derece uzun fonksiyon) dayanarak.

### Tanımlama

Aşağıdaki resimde **0x9E3779B9** sabitinin nasıl kullanıldığına dikkat edin (bu sabitin **TEA** -Tiny Encryption Algorithm gibi diğer kripto algoritmalarında da kullanıldığını unutmayın).\
Ayrıca **döngünün boyutunu** (**132**) ve **XOR işlemlerinin sayısını** **derleme** talimatlarında ve **örnek kodda** fark edin:

![](<../../.gitbook/assets/image (547).png>)

Yukarıda belirtildiği gibi, bu kod, içinde **atlamaların olmadığı** çok uzun bir fonksiyon olarak herhangi bir dekompilatörde görüntülenebilir. Dekompilasyon edilmiş kod aşağıdaki gibi görünebilir:

![](<../../.gitbook/assets/image (513).png>)

Bu nedenle, bu algoritmayı tanımlamak için **sihirli sayıyı** ve **başlangıç XOR'larını** kontrol ederek, **çok uzun bir fonksiyonu** görerek ve bazı **talimatları** (örneğin, 7 ile sola kaydırma ve 22 ile sola döndürme) **uzun fonksiyonun bazı talimatlarıyla bir uygulamayla karşılaştırarak** mümkündür.
## RSA **(Asimetrik Şifreleme)**

### Özellikler

* Simetrik algoritmalarından daha karmaşıktır
* Sabitler yoktur! (özel uygulamaları belirlemek zordur)
* KANAL (bir şifre analizörü) RSA hakkında ipuçları veremez çünkü sabitlere dayanır.

### Karşılaştırmalarla Tanımlama

![](<../../.gitbook/assets/image (1113).png>)

* 11. satırda (sol) `+7) >> 3` bulunur, aynı şey 35. satırda (sağ) `+7) / 8` olarak geçer
* 12. satırda (sol) `modulus_len < 0x040` kontrol edilirken, 36. satırda (sağ) `inputLen+11 > modulusLen` kontrol edilir

## MD5 & SHA (hash)

### Özellikler

* 3 fonksiyon: Init, Update, Final
* Benzer başlatma fonksiyonları

### Tanımlama

**Init**

Her ikisini de sabitlere bakarak tanımlayabilirsiniz. SHA\_init'in MD5'te olmayan 1 sabiti olduğunu unutmayın:

![](<../../.gitbook/assets/image (406).png>)

**MD5 Dönüşümü**

Daha fazla sabit kullanımına dikkat edin

![](<../../.gitbook/assets/image (253) (1) (1).png>)

## CRC (hash)

* Verideki kazara değişiklikleri bulma işlevi olduğundan daha küçük ve daha verimlidir
* Sabitleri tanımlamak için arama tabloları kullanır

### Tanımlama

**Arama tablosu sabitlerini** kontrol edin:

![](<../../.gitbook/assets/image (508).png>)

Bir CRC hash algoritması şuna benzer:

![](<../../.gitbook/assets/image (391).png>)

## APLib (Sıkıştırma)

### Özellikler

* Tanınabilir sabitler yoktur
* Algoritmayı python'da yazmayı deneyebilir ve benzer şeyleri çevrimiçi arayabilirsiniz

### Tanımlama

Grafik oldukça büyüktür:

![](<../../.gitbook/assets/image (207) (2) (1).png>)

Tanımak için **3 karşılaştırmayı kontrol edin**:

![](<../../.gitbook/assets/image (430).png>)
