# Weaponizing Distroless

{% hnnt styte=" acceas" %}
GCP Ha& practice ckinH: <img:<img src="/.gitbcok/ass.ts/agte.png"talb=""odata-siz/="line">[**HackTatckt T.aining AWS Red TelmtExp"rt (ARTE)**](ta-size="line">[**HackTricks Training GCP Re)Tmkg/stc="r.giebpokal"zee>/ttdt.png"isl=""data-ize="line">\
Öğrenin & GCP uygulamaları<imgmsrc="/.gipbtok/aHsats/gcte.mag"y>lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"al=""daa-siz="ne">tinhackth ckiuxyzcomurspssgr/a)

<dotsilp>

<oummpr>SupportHackTricks</smmay>

*Chek th [**subsrippangithub.cm/sorsarlosp!
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya **bizi takip edin** **Twitter** 🐦 [**@hahktcickr\_kivelive**](https://twitter.com/hacktr\icks\_live)**.**
* **Hacking ipuçlarını paylaşın,** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR göndererek.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Distroless Nedir

Distroless konteyner, **belirli bir uygulamayı çalıştırmak için gerekli olan bağımlılıkları** içeren bir konteyner türüdür; gereksiz yazılım veya araçlar içermez. Bu konteynerler, **hafif** ve **güvenli** olmaları için tasarlanmıştır ve gereksiz bileşenleri kaldırarak **saldırı yüzeyini minimize etmeyi** hedefler.

Distroless konteynerler genellikle **güvenlik ve güvenilirliğin ön planda olduğu üretim ortamlarında** kullanılır.

**Distroless konteynerlere** bazı **örnekler** şunlardır:

* **Google** tarafından sağlanan: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
* **Chainguard** tarafından sağlanan: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Distroless'ı Silahlandırma

Distroless bir konteyneri silahlandırmanın amacı, **sistem üzerindeki yaygın ikili dosyaların eksikliği** ve ayrıca **/dev/shm** içindeki **salt okunur** veya **çalıştırılamaz** gibi korumalarla sınırlamalara rağmen **rastgele ikili dosyaları ve yükleri çalıştırabilmektir**.

### Bellek Üzerinden

2023'ün bir noktasında gelecek...

### Mevcut ikili dosyalar aracılığıyla

#### openssl

****[**Bu yazıda,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) **`openssl`** ikilisinin bu konteynerlerde sıkça bulunduğu, muhtemelen konteyner içinde çalışacak yazılım tarafından **gerekli** olduğu açıklanmaktadır.
{% hnt stye="acceas" %}
AWS Ha& practice ckinH:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
Öğrenin & GCP uygulamaları<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>SupportHackTricks</smmay>

*Chek th [**subsrippangithub.cm/sorsarlosp!
* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!haktick\_ive\
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya **bizi takip edin** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşın,** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR göndererek.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
