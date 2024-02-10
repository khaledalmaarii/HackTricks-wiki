# macOS Seri Numarası

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşün</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>ile öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi **HackTricks'te reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'da takip edin.**
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek paylaşın.

</details>


## Temel Bilgiler

Apple cihazları 2010'dan sonra **12 alfasayısal karakterden** oluşan seri numaralarına sahiptir. Her bir segment belirli bilgileri iletmektedir:

- **İlk 3 Karakter**: **Üretim yeri**ni gösterir.
- **4. ve 5. Karakterler**: **Üretim yılını ve haftasını** belirtir.
- **6 ila 8. Karakterler**: Her cihaz için **benzersiz bir tanımlayıcı** olarak hizmet eder.
- **Son 4 Karakter**: **Model numarasını** belirtir.

Örneğin, seri numarası **C02L13ECF8J2** bu yapıyı takip eder.

### **Üretim Yerleri (İlk 3 Karakter)**
Bazı kodlar belirli fabrikaları temsil eder:
- **FC, F, XA/XB/QP/G8**: ABD'deki çeşitli konumlar.
- **RN**: Meksika.
- **CK**: Cork, İrlanda.
- **VM**: Foxconn, Çek Cumhuriyeti.
- **SG/E**: Singapur.
- **MB**: Malezya.
- **PT/CY**: Kore.
- **EE/QT/UV**: Tayvan.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7**: Çin'deki farklı konumlar.
- **C0, C3, C7**: Çin'deki belirli şehirler.
- **RM**: Yenilenmiş cihazlar.

### **Üretim Yılı (4. Karakter)**
Bu karakter 'C' (2010'un ilk yarısını temsil eder) ile 'Z' (2019'un ikinci yarısı) arasında değişir ve farklı harfler farklı yarı yıl dönemlerini gösterir.

### **Üretim Haftası (5. Karakter)**
Rakamlar 1-9, haftaları 1-9'a karşılık gelir. C-Y harfleri (ünlü harfler ve 'S' harfi hariç) 10-27 haftalarını temsil eder. Yılın ikinci yarısı için bu sayıya 26 eklenir.

### **Benzersiz Tanımlayıcı (6 ila 8. Karakterler)**
Bu üç rakam, aynı model ve partiden olan her cihazın farklı bir seri numarasına sahip olmasını sağlar.

### **Model Numarası (Son 4 Karakter)**
Bu rakamlar cihazın belirli modelini tanımlar.

### Referans

* [https://beetstech.com/blog/decode-meaning-behind-apple-serial-number](https://beetstech.com/blog/decode-meaning-behind-apple-serial-number)

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşün</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>ile öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi **HackTricks'te reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'da takip edin.**
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek paylaşın.

</details>
