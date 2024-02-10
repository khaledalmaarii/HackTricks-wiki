# ZIP hileleri

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamını görmek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı takip edin.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

**ZIP dosyalarını** yönetmek için **komut satırı araçları**, zip dosyalarını teşhis etmek, onarmak ve kırmak için önemlidir. İşte bazı temel araçlar:

- **`unzip`**: Bir zip dosyasının neden açılamadığını ortaya çıkarır.
- **`zipdetails -v`**: Zip dosyası format alanlarının detaylı analizini sunar.
- **`zipinfo`**: Bir zip dosyasının içeriğini çıkarmadan listeler.
- **`zip -F input.zip --out output.zip`** ve **`zip -FF input.zip --out output.zip`**: Bozuk zip dosyalarını onarmaya çalışır.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Zip şifrelerini brute-force yöntemiyle kırmak için etkili olan bir araç, genellikle 7 karaktere kadar olan şifreler için kullanılır.

[Zip dosya formatı spesifikasyonu](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT), zip dosyalarının yapısı ve standartları hakkında kapsamlı bilgiler sağlar.

Önemli bir nokta, şifre korumalı zip dosyalarının içindeki dosya adlarını veya dosya boyutlarını **şifrelemediğidir**, bu güvenlik açığı RAR veya 7z dosyalarıyla paylaşılmaz. Ayrıca, eski ZipCrypto yöntemiyle şifrelenen zip dosyaları, sıkıştırılmış bir dosyanın şifrelenmemiş bir kopyası mevcutsa bir **açık metin saldırısına** karşı savunmasızdır. Bu saldırı, zip'in şifresini kırmak için bilinen içeriği kullanır ve bu zayıflık [HackThis'in makalesinde](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) ayrıntılı olarak açıklanmıştır ve [bu akademik makalede](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf) daha fazla açıklanmıştır. Bununla birlikte, **AES-256** şifreleme ile korunan zip dosyaları, bu açık metin saldırısına karşı bağışıktır ve hassas veriler için güvenli şifreleme yöntemlerinin seçiminin önemini gösterir.

## Referanslar
* [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamını görmek** veya HackTricks'i **PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'i keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı takip edin.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
