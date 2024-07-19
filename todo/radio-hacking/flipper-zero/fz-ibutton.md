# FZ - iButton

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** bizi takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

## Giriş

iButton hakkında daha fazla bilgi için kontrol edin:

{% content-ref url="../ibutton.md" %}
[ibutton.md](../ibutton.md)
{% endcontent-ref %}

## Tasarım

Aşağıdaki resmin **mavi** kısmı, Flipper'ın **okuyabilmesi için gerçek iButton'u** nasıl **yerleştirmeniz gerektiğini** gösterir. **Yeşil** kısım ise Flipper Zero ile okuyucuya **doğru bir şekilde iButton'u taklit etmek için** nasıl **dokunmanız gerektiğini** gösterir.

<figure><img src="../../../.gitbook/assets/image (565).png" alt=""><figcaption></figcaption></figure>

## Eylemler

### Oku

Okuma Modunda Flipper, iButton anahtarının dokunmasını bekler ve üç tür anahtarı sindirebilir: **Dallas, Cyfral ve Metakom**. Flipper, anahtarın türünü **kendisi belirleyecektir**. Anahtar protokolünün adı, ID numarasının üzerinde ekranda görüntülenecektir.

### Manuel ekle

**Dallas, Cyfral ve Metakom** türünde bir iButton'u **manuel olarak eklemek** mümkündür.

### **Taklit et**

Kaydedilmiş iButton'ları (okunan veya manuel olarak eklenen) **taklit etmek** mümkündür.

{% hint style="info" %}
Flipper Zero'nun beklenen temaslarının okuyucuya dokunmasını sağlayamazsanız, **harici GPIO'yu kullanabilirsiniz:**
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (138).png" alt=""><figcaption></figcaption></figure>

## Referanslar

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** bizi takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
