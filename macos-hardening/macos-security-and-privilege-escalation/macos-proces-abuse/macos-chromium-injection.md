# macOS Chromium Enjeksiyonu

<details>

<summary><strong>Sıfırdan kahraman olmak için AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünleri**]'ni edinin (https://peass.creator-spring.com)
* [**The PEASS Family**]'yi keşfedin (https://opensea.io/collection/the-peass-family), özel [**NFT'ler**] koleksiyonumuz (https://opensea.io/collection/the-peass-family)
* **Katılın** 💬 [**Discord grubuna**] (https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**] veya bizi **Twitter** 🐦 [**@carlospolopm**] (https://twitter.com/hacktricks\_live)**.**
* **Hacking püf noktalarınızı paylaşarak PR'lar göndererek HackTricks** (https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**] (https://github.com/carlospolop/hacktricks-cloud) github depolarına.

</details>

## Temel Bilgiler

Google Chrome, Microsoft Edge, Brave ve diğerleri gibi Chromium tabanlı tarayıcılar. Bu tarayıcılar, ortak bir temele sahip oldukları için benzer işlevselliklere ve geliştirici seçeneklerine sahip olmaları anlamına gelir.

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

<details>

<summary><strong>Sıfırdan kahraman olana kadar AWS hackleme öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**]'na göz atın (https://github.com/sponsors/carlospolop)!
* [**Resmi PEASS & HackTricks ürünlerini alın**](https://peass.creator-spring.com)
* [**The PEASS Family**]'yi keşfedin (https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı göndererek HackTricks** (https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek paylaşın.

</details>
