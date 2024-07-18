# macOS Chromium Enjeksiyonu

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 **Discord grubuna** [**katılın**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'da takip edin**.
* **Hacking püf noktalarını paylaşarak PR'ler göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}

## Temel Bilgiler

Google Chrome, Microsoft Edge, Brave ve diğerleri gibi Chromium tabanlı tarayıcılar. Bu tarayıcılar, Chromium açık kaynak projesi üzerine inşa edildiği için ortak bir temaya sahiptir ve dolayısıyla benzer işlevselliklere ve geliştirici seçeneklerine sahiptir.

#### `--load-extension` Bayrağı

`--load-extension` bayrağı, bir Chromium tabanlı tarayıcıyı komut satırından veya bir betikten başlatırken kullanılır. Bu bayrak, tarayıcıyı başlatırken **bir veya daha fazla uzantıyı otomatik olarak yüklemeyi** sağlar.

#### `--use-fake-ui-for-media-stream` Bayrağı

`--use-fake-ui-for-media-stream` bayrağı, Chromium tabanlı tarayıcıları başlatmak için kullanılan başka bir komut satırı seçeneğidir. Bu bayrak, kameradan ve mikrofondan medya akışlarına erişim izni isteyen normal kullanıcı uyarılarını **atlamak için tasarlanmıştır**. Bu bayrak kullanıldığında, tarayıcı, kameraya veya mikrofona erişim isteyen herhangi bir web sitesine veya uygulamaya otomatik olarak izin verir.

### Araçlar

* [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop)
* [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO)

### Örnek
```bash
# Intercept traffic
voodoo intercept -b chrome
```
## Referanslar

* [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak PR'ler göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}
