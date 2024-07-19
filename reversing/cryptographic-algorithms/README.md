# Kriptografik/Sıkıştırma Algoritmaları

## Kriptografik/Sıkıştırma Algoritmaları

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

## Algoritmaları Tanımlama

Eğer bir kod **sağa ve sola kaydırma, XOR ve çeşitli aritmetik işlemler** kullanıyorsa, bunun bir **kriptografik algoritmanın** uygulanması olması oldukça olasıdır. Burada, **her adımı tersine çevirmeye gerek kalmadan kullanılan algoritmayı tanımlamanın bazı yolları** gösterilecektir.

### API fonksiyonları

**CryptDeriveKey**

Bu fonksiyon kullanılıyorsa, ikinci parametrenin değerini kontrol ederek hangi **algoritmanın kullanıldığını** bulabilirsiniz:

![](<../../.gitbook/assets/image (375) (1) (1) (1) (1).png>)

Olası algoritmalar ve atanan değerleri için buradaki tabloya bakın: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Verilen bir veri tamponunu sıkıştırır ve açar.

**CryptAcquireContext**

[Belgelerden](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): **CryptAcquireContext** fonksiyonu, belirli bir kriptografik hizmet sağlayıcısı (CSP) içindeki belirli bir anahtar konteynerine bir tanıtıcı almak için kullanılır. **Bu döndürülen tanıtıcı, seçilen CSP'yi kullanan CryptoAPI** fonksiyonlarına yapılan çağrılarda kullanılır.

**CryptCreateHash**

Bir veri akışının hash'ini başlatır. Bu fonksiyon kullanılıyorsa, ikinci parametrenin değerini kontrol ederek hangi **algoritmanın kullanıldığını** bulabilirsiniz:

![](<../../.gitbook/assets/image (376).png>)

\
Olası algoritmalar ve atanan değerleri için buradaki tabloya bakın: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Kod sabitleri

Bazen, bir algoritmayı tanımlamak gerçekten kolaydır çünkü özel ve benzersiz bir değer kullanması gerekir.

![](<../../.gitbook/assets/image (370).png>)

Eğer ilk sabiti Google'da aratırsanız, bu sonucu alırsınız:

![](<../../.gitbook/assets/image (371).png>)

Bu nedenle, dekompile edilmiş fonksiyonun bir **sha256 hesaplayıcısı** olduğunu varsayabilirsiniz.\
Diğer sabitlerden herhangi birini arayabilirsiniz ve (muhtemelen) aynı sonucu alırsınız.

### veri bilgisi

Eğer kodda herhangi bir önemli sabit yoksa, bu **.data bölümünden bilgi yüklüyor olabilir**.\
Bu veriye erişebilir, **ilk dword'u gruplandırabilir** ve önceki bölümde yaptığımız gibi Google'da arama yapabilirsiniz:

![](<../../.gitbook/assets/image (372).png>)

Bu durumda, eğer **0xA56363C6**'yı ararsanız, bunun **AES algoritmasının tablolarıyla** ilişkili olduğunu bulabilirsiniz.

## RC4 **(Simetrik Kriptografi)**

### Özellikler

3 ana bölümden oluşur:

* **Başlatma aşaması/**: **0x00'dan 0xFF'e kadar** (toplam 256 bayt, 0x100) bir **değerler tablosu** oluşturur. Bu tablo genellikle **Yer Değiştirme Kutusu** (veya SBox) olarak adlandırılır.
* **Karıştırma aşaması**: Daha önce oluşturulan tabloyu **döngü ile geçer** (0x100 yineleme döngüsü) ve her değeri **yarı rastgele** baytlarla değiştirir. Bu yarı rastgele baytları oluşturmak için RC4 **anahtarı kullanılır**. RC4 **anahtarları** **1 ile 256 bayt arasında** olabilir, ancak genellikle 5 bayttan fazla olması önerilir. Genellikle, RC4 anahtarları 16 bayt uzunluğundadır.
* **XOR aşaması**: Son olarak, düz metin veya şifreli metin, daha önce oluşturulan değerlerle **XOR'lanır**. Şifreleme ve şifre çözme fonksiyonu aynıdır. Bunun için, oluşturulan 256 bayt üzerinden gerekli olduğu kadar döngü yapılacaktır. Bu genellikle dekompile edilmiş kodda **%256 (mod 256)** ile tanınır.

{% hint style="info" %}
**Bir dekompile edilmiş kodda RC4'ü tanımlamak için, 0x100 boyutunda 2 döngü kontrol edebilir ve ardından giriş verisinin 2 döngüde daha önce oluşturulan 256 değerle XOR'lanmasını kontrol edebilirsiniz, muhtemelen %256 (mod 256) kullanarak.**
{% endhint %}

### **Başlatma aşaması/Yer Değiştirme Kutusu:** (Sayac olarak kullanılan 256 sayısını ve 256 karakterin her yerinde nasıl 0 yazıldığını not edin)

![](<../../.gitbook/assets/image (377).png>)

### **Karıştırma Aşaması:**

![](<../../.gitbook/assets/image (378).png>)

### **XOR Aşaması:**

![](<../../.gitbook/assets/image (379).png>)

## **AES (Simetrik Kriptografi)**

### **Özellikler**

* **Yer değiştirme kutuları ve arama tabloları** kullanımı
* **Belirli arama tablo değerlerinin** (sabitlerin) kullanımı sayesinde AES'i **ayırmak mümkündür**. _Not edin ki **sabit** ikili dosyada **saklanabilir** veya _**dinamik olarak**_ _**oluşturulabilir**._
* **Şifreleme anahtarı** **16'ya** (genellikle 32B) **tam bölünebilir** olmalıdır ve genellikle 16B'lik bir **IV** kullanılır.

### SBox sabitleri

![](<../../.gitbook/assets/image (380).png>)

## Serpent **(Simetrik Kriptografi)**

### Özellikler

* Bunu kullanan bazı kötü amaçlı yazılımlar bulmak nadirdir ama örnekler vardır (Ursnif)
* Bir algoritmanın Serpent olup olmadığını belirlemek için uzunluğuna (son derece uzun fonksiyon) dayanarak basit.

### Tanımlama

Aşağıdaki görüntüde **0x9E3779B9** sabitinin nasıl kullanıldığına dikkat edin (bu sabitin ayrıca **TEA** -Küçük Şifreleme Algoritması gibi diğer kripto algoritmaları tarafından da kullanıldığını not edin).\
Ayrıca **döngünün boyutunu** (**132**) ve **dekompile** talimatlarındaki **XOR işlemleri** sayısını ve **kod** örneğindeki sayısını not edin:

![](<../../.gitbook/assets/image (381).png>)

Daha önce belirtildiği gibi, bu kod herhangi bir dekompiler içinde **çok uzun bir fonksiyon** olarak görselleştirilebilir çünkü içinde **atlamalar** yoktur. Dekompile edilmiş kod aşağıdaki gibi görünebilir:

![](<../../.gitbook/assets/image (382).png>)

Bu nedenle, bu algoritmayı tanımlamak, **büyülü sayıyı** ve **ilk XOR'ları** kontrol ederek, **çok uzun bir fonksiyon** görerek ve uzun fonksiyonun bazı **talimatlarını** bir **uygulama** ile **karşılaştırarak** mümkündür (örneğin, 7'ye sola kaydırma ve 22'ye sola döndürme).

## RSA **(Asimetrik Kriptografi)**

### Özellikler

* Simetrik algoritmalardan daha karmaşık
* Sabit yok! (özel uygulamaların belirlenmesi zordur)
* KANAL (bir kripto analizörü) RSA hakkında ipuçları gösteremiyor çünkü sabitlere dayanıyor.

### Karşılaştırmalarla Tanımlama

![](<../../.gitbook/assets/image (383).png>)

* 11. satırda (solda) `+7) >> 3` var, bu da 35. satırda (sağda) `+7) / 8` ile aynıdır.
* 12. satır (solda) `modulus_len < 0x040` kontrol ediyor ve 36. satırda (sağda) `inputLen+11 > modulusLen` kontrol ediliyor.

## MD5 & SHA (hash)

### Özellikler

* 3 fonksiyon: Başlat, Güncelle, Son
* Benzer başlatma fonksiyonları

### Tanımlama

**Başlat**

Her ikisini de sabitleri kontrol ederek tanımlayabilirsiniz. Not edin ki sha\_init'in MD5'de olmayan 1 sabiti vardır:

![](<../../.gitbook/assets/image (385).png>)

**MD5 Dönüştürme**

Daha fazla sabit kullanıldığına dikkat edin

![](<../../.gitbook/assets/image (253) (1) (1) (1).png>)

## CRC (hash)

* Daha küçük ve daha verimli çünkü işlevi verilerdeki kazara değişiklikleri bulmaktır.
* Sabitleri tanımlamak için arama tabloları kullanır.

### Tanımlama

**arama tablo sabitlerini** kontrol edin:

![](<../../.gitbook/assets/image (387).png>)

Bir CRC hash algoritması şöyle görünür:

![](<../../.gitbook/assets/image (386).png>)

## APLib (Sıkıştırma)

### Özellikler

* Tanınabilir sabit yok
* Algoritmayı python'da yazmayı deneyebilir ve çevrimiçi benzer şeyler arayabilirsiniz.

### Tanımlama

Grafik oldukça büyük:

![](<../../.gitbook/assets/image (207) (2) (1).png>)

Bunu tanımak için **3 karşılaştırmayı** kontrol edin:

![](<../../.gitbook/assets/image (384).png>)

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
