# ZIPs hileleri

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)** takip edin.**
* **Hacking hilelerinizi göndererek HackTricks ve HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>

**Komut satırı araçları** zip dosyalarını yönetmek için gereklidir, zip dosyalarını teşhis etmek, onarmak ve kırmak için kullanılır. İşte bazı temel yardımcı programlar:

- **`unzip`**: Bir zip dosyasının neden açılmayabileceğini ortaya çıkarır.
- **`zipdetails -v`**: Zip dosyası biçim alanlarının detaylı analizini sunar.
- **`zipinfo`**: İçerikleri çıkarmadan bir zip dosyasının içeriğini listeler.
- **`zip -F input.zip --out output.zip`** ve **`zip -FF input.zip --out output.zip`**: Bozuk zip dosyalarını onarmaya çalışır.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Zip şifrelerini kaba kuvvet yöntemiyle kırmak için etkili bir araç, genellikle 7 karaktere kadar olan şifreler için etkilidir.

[Zip dosya biçimi belirtimi](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT), zip dosyalarının yapısı ve standartları hakkında kapsamlı bilgiler sunar.

Önemli bir not olarak, şifre korumalı zip dosyalarının **dosya adlarını veya dosya boyutlarını şifrelemediğini** unutmamak önemlidir, bu bilgiyi şifreleyen RAR veya 7z dosyalarıyla paylaşmayan bir güvenlik açığıdır. Ayrıca, eski ZipCrypto yöntemiyle şifrelenmiş zip dosyaları, sıkıştırılmış bir dosyanın şifresiz bir kopyası mevcutsa **düz metin saldırısına** açıktır. Bu saldırı, zip dosyasının şifresini kırmak için bilinen içeriği kullanır, bu zayıflık [HackThis'in makalesinde](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) detaylı olarak açıklanmış ve [bu akademik makalede](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf) daha fazla açıklanmıştır. Bununla birlikte, **AES-256** şifreleme ile korunan zip dosyaları, bu düz metin saldırısına karşı bağışıktır, hassas veriler için güvenli şifreleme yöntemlerini seçmenin önemini gösterir.

## Referanslar
* [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
