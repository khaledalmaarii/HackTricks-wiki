# Donanım Hacking

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

## JTAG

JTAG, bir sınır taraması gerçekleştirmeyi sağlar. Sınır taraması, her pin için gömülü sınır tarama hücreleri ve kayıtları da dahil olmak üzere belirli devreleri analiz eder.

JTAG standardı, **sınır taramaları gerçekleştirmek için belirli komutlar** tanımlar, bunlar arasında şunlar bulunur:

* **BYPASS**, belirli bir çipi diğer çiplerden geçmeden test etmenizi sağlar.
* **SAMPLE/PRELOAD**, cihaz normal çalışma modundayken giren ve çıkan verilerin bir örneğini alır.
* **EXTEST**, pin durumlarını ayarlar ve okur.

Ayrıca aşağıdaki gibi diğer komutları da destekleyebilir:

* **IDCODE**, bir cihazı tanımlamak için
* **INTEST**, cihazın iç testleri için

JTAGulator gibi bir araç kullandığınızda bu talimatlarla karşılaşabilirsiniz.

### Test Erişim Noktası

Sınır taramaları, bileşene entegre edilmiş **JTAG test destek** işlevlerine erişim sağlayan genel amaçlı bir port olan dört telli **Test Erişim Noktası (TAP)** testlerini içerir. TAP, aşağıdaki beş sinyali kullanır:

* Test saat girişi (**TCK**) TCK, TAP denetleyicisinin tek bir eylem gerçekleştireceği sıklığı tanımlayan **saat**'tir (diğer bir deyişle, durum makinesinde bir sonraki duruma geçiş).
* Test modu seçimi (**TMS**) girişi TMS, **sonlu durum makinesini** kontrol eder. Saatin her vuruşunda, cihazın JTAG TAP denetleyicisi TMS pinindeki voltajı kontrol eder. Voltaj belirli bir eşik değerinin altındaysa, sinyal düşük kabul edilir ve 0 olarak yorumlanır; voltaj belirli bir eşik değerinin üzerindeyse, sinyal yüksek kabul edilir ve 1 olarak yorumlanır.
* Test veri girişi (**TDI**) TDI, **veriyi çipe tarama hücreleri aracılığıyla gönderen** pindir. Her üretici, bu pin üzerinden iletişim protokolünü tanımlamaktan sorumludur, çünkü JTAG bunu tanımlamaz.
* Test veri çıkışı (**TDO**) TDO, **veriyi çipten dışarı gönderen** pindir.
* Test sıfırlama (**TRST**) girişi Opsiyonel TRST, sonlu durum makinesini **bilinen iyi bir duruma** sıfırlar. Alternatif olarak, TMS beş ardışık saat döngüsü boyunca 1'de tutulursa, TRST pininin yaptığı gibi bir sıfırlama tetikler, bu nedenle TRST opsiyoneldir.

Bazen bu pinlerin PCB'de işaretlendiğini bulabilirsiniz. Diğer durumlarda, **bulmanız** gerekebilir.

### JTAG pinlerini tanımlama

JTAG portlarını tespit etmenin en hızlı ama en pahalı yolu, bu amaç için özel olarak oluşturulmuş bir cihaz olan **JTAGulator**'ı kullanmaktır (ancak **UART pinout'larını da tespit edebilir**).

**24 kanala** sahiptir ve bu kanalları kartın pinlerine bağlayabilirsiniz. Ardından, **IDCODE** ve **BYPASS** sınır tarama komutlarını göndererek tüm olası kombinasyonların **BF saldırısını** gerçekleştirir. Bir yanıt alırsa, her JTAG sinyaline karşılık gelen kanalı görüntüler.

JTAG pinout'larını tanımlamanın daha ucuz ama çok daha yavaş bir yolu, bir Arduino uyumlu mikrodenetleyiciye yüklenmiş [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) kullanmaktır.

**JTAGenum** kullanarak, önce **numune alma** cihazının pinlerini tanımlamanız gerekir. Cihazın pinout diyagramına atıfta bulunmalı ve ardından bu pinleri hedef cihazınızdaki test noktalarıyla bağlamalısınız.

JTAG pinlerini tanımlamanın **üçüncü yolu**, PCB'yi bir pinout için **incelemektir**. Bazı durumlarda, PCB'ler **Tag-Connect arayüzünü** uygun bir şekilde sağlayabilir, bu da kartın bir JTAG konektörüne sahip olduğunun açık bir göstergesidir. O arayüzün nasıl göründüğünü [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/) adresinde görebilirsiniz. Ayrıca, PCB'deki yonga setlerinin **veri sayfalarını** incelemek, JTAG arayüzlerine işaret eden pinout diyagramlarını ortaya çıkarabilir.

## SDW

SWD, hata ayıklama için tasarlanmış ARM'a özgü bir protokoldür.

SWD arayüzü, **iki pin** gerektirir: JTAG’ın **TDI ve TDO pinlerine** eşdeğer olan iki yönlü **SWDIO** sinyali ve **TCK**'ya eşdeğer olan **SWCLK**. Birçok cihaz, hedefe bir SWD veya JTAG probu bağlamanızı sağlayan birleşik bir JTAG ve SWD arayüzü olan **Seri Tel veya JTAG Hata Ayıklama Portu (SWJ-DP)**'yi destekler.

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
