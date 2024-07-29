# Weaponizing Distroless

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'ı takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

## Distroless Nedir

Distroless konteyner, **belirli bir uygulamayı çalıştırmak için gerekli olan bağımlılıkları** içeren, gereksiz yazılım veya araçlar olmadan oluşturulmuş bir konteyner türüdür. Bu konteynerler, **hafif** ve **güvenli** olmaları için tasarlanmıştır ve gereksiz bileşenleri kaldırarak **saldırı yüzeyini minimize etmeyi** amaçlar.

Distroless konteynerler genellikle **güvenlik ve güvenilirliğin ön planda olduğu üretim ortamlarında** kullanılır.

**Distroless konteynerlere** bazı **örnekler** şunlardır:

* **Google** tarafından sağlanan: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
* **Chainguard** tarafından sağlanan: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Distroless'ı Silahlandırma

Distroless konteyneri silahlandırmanın amacı, **distroless'in getirdiği sınırlamalara** (sistemde yaygın ikili dosyaların eksikliği) ve ayrıca konteynerlerde yaygın olarak bulunan **salt okunur** veya **çalıştırılamaz** gibi korumalara rağmen **rastgele ikili dosyaları ve yükleri çalıştırabilmektir**.

### Bellek Üzerinden

2023'ün bir noktasında geliyor...

### Mevcut ikili dosyalar aracılığıyla

#### openssl

****[**Bu yazıda,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) **`openssl`** ikilisinin bu konteynerlerde sıkça bulunduğu, muhtemelen konteyner içinde çalışacak yazılım tarafından **gerekli** olduğu açıklanmaktadır.


{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'ı takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
