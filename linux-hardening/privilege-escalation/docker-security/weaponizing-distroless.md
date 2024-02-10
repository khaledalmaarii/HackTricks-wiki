# Distroless'u Silahlandırma

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

## Distroless Nedir

Distroless bir konteyner türüdür ve **belirli bir uygulamayı çalıştırmak için gerekli olan bağımlılıkları içerir**, gereksiz yazılım veya araçlar olmadan. Bu konteynerler, **mümkün olduğunca hafif** ve **güvenli** olacak şekilde tasarlanmıştır ve gereksiz bileşenleri kaldırarak **saldırı yüzeyini en aza indirmeyi** amaçlar.

Distroless konteynerler genellikle **güvenlik ve güvenilirlik açısından önemli olan üretim ortamlarında** kullanılır.

Bazı **distroless konteyner** örnekleri şunlardır:

* **Google tarafından sağlanan**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
* **Chainguard tarafından sağlanan**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Distroless'u Silahlandırma

Distroless konteyneri silahlandırmanın amacı, **distroless'un** (sistemde yaygın olan ortak ikili dosyaların eksikliği gibi) **sınırlamaları** tarafından ima edilen **sınırlamalarla bile keyfi ikili dosyaları ve yükleri yürütebilmektir** ve ayrıca `/dev/shm` içindeki **salt okunur** veya **yürütülemez** gibi konteynerlerde yaygın olarak bulunan korumaları da içerir.

### Bellek Aracılığıyla

2023'ün bir noktasında gelecek...

### Varolan ikili dosyalar aracılığıyla

#### openssl

Bu [**gönderide**](https://www.form3.tech/engineering/content/exploiting-distroless-images) belirtildiği gibi, **`openssl`** ikili dosyası bu konteynerlerde sık ​​sık bulunur, muhtemelen konteyner içinde çalışacak yazılım tarafından **gereklidir**.

**`openssl`** ikili dosyasının kötüye kullanılmasıyla keyfi işler **yürütülebilir**.
